"""RunRepository abstractions supporting bounded in-memory and zero-dependency SQLite persistence."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import json
import logging
from pathlib import Path
import sqlite3
import threading
from typing import Any, Dict, Iterator, List, Literal, Optional, Protocol
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


RunLifecycleStatus = Literal["PENDING", "RUNNING", "COMPLETED", "CANCELED", "FAILED"]


class IdempotencyConflictError(ValueError):
    """Raised when an idempotency key is reused with a different request payload."""


class RunRecord(BaseModel):
    """Persistent or in-memory snapshot of a single incident triage execution."""

    run_id: str
    case_id: Optional[str] = None
    idempotency_key: Optional[str] = None
    request_fingerprint: Optional[str] = None
    environment: str = "default"
    profile_id: str = "checkout-demo"
    profile_version: str = "1.0.0"
    schema_version: str = "3.0"
    status: RunLifecycleStatus = "PENDING"
    created_at: str
    completed_at: Optional[str] = None
    final_state: Optional[Dict[str, Any]] = None
    brief_markdown: Optional[str] = None
    brief_json: Optional[str] = None
    events: List[Dict[str, Any]] = Field(default_factory=list)


class ApprovalRecord(BaseModel):
    """Operator acknowledgment linked to case/run/proposal identity."""

    case_id: str
    run_id: Optional[str] = None
    proposal_id: Optional[str] = None
    decision: Literal["approved", "rejected"]
    operator_id: str
    environment: str = "default"
    timestamp: str


def parse_exported_brief(raw_json: str) -> Dict[str, Any]:
    """Reads exported JSON incident briefs cleanly across v2 (unversioned) and v3 formats."""
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Malformed exported brief JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("Exported brief must be a JSON object.")
    if "schema_version" not in data:
        data = dict(data)
        data["schema_version"] = "2.0"
        data.setdefault("profile_id", "checkout-demo")
        data.setdefault("evidence", [])
        data.setdefault("claims", [])
    return data


class RunRepository(Protocol):
    """Storage interface for run lifecycle, SSE event replay, and HITL approvals."""

    def create_run(self, record: RunRecord) -> None: ...
    def get_run(self, run_id: str) -> Optional[RunRecord]: ...
    def get_by_idempotency_key(self, environment: str, key: str) -> Optional[RunRecord]: ...
    def recover_interrupted_runs(self, completed_at: str) -> int: ...
    def mark_running(self, run_id: str) -> bool: ...
    def append_event(self, run_id: str, event_payload: Dict[str, Any]) -> int: ...
    def list_events_after(self, run_id: str, last_seq: int = 0) -> List[Dict[str, Any]]: ...
    def commit_terminal(
        self,
        run_id: str,
        *,
        status: RunLifecycleStatus,
        final_state: Dict[str, Any],
        brief_markdown: str,
        brief_json: str,
        completed_at: str,
    ) -> bool: ...
    def save_approval(self, approval: ApprovalRecord) -> ApprovalRecord: ...
    def get_approval(self, key: str) -> Optional[ApprovalRecord]: ...
    def purge_expired(self, max_age_seconds: int) -> int: ...


class MemoryRunRepository:
    """Bounded thread-safe in-memory RunRepository preserving local-replay speed."""

    def __init__(self, maxsize: int = 500):
        self.maxsize = maxsize
        self._lock = threading.Lock()
        self._runs: Dict[str, RunRecord] = {}
        self._idempotency: Dict[tuple[str, str], str] = {}
        self._approvals: Dict[str, ApprovalRecord] = {}

    def create_run(self, record: RunRecord) -> None:
        with self._lock:
            if record.idempotency_key:
                key = (record.environment, record.idempotency_key)
                if key in self._idempotency:
                    existing = self._runs.get(self._idempotency[key])
                    if existing and existing.request_fingerprint != record.request_fingerprint:
                        raise IdempotencyConflictError("Idempotency-Key reused with different request payload.")
            if len(self._runs) >= self.maxsize and record.run_id not in self._runs:
                oldest = next(iter(self._runs))
                old_rec = self._runs.pop(oldest)
                if old_rec.idempotency_key:
                    self._idempotency.pop((old_rec.environment, old_rec.idempotency_key), None)
            self._runs[record.run_id] = record
            if record.idempotency_key:
                self._idempotency[(record.environment, record.idempotency_key)] = record.run_id

    def get_run(self, run_id: str) -> Optional[RunRecord]:
        with self._lock:
            rec = self._runs.get(run_id)
            return rec.model_copy(deep=True) if rec else None

    def get_by_idempotency_key(self, environment: str, key: str) -> Optional[RunRecord]:
        with self._lock:
            rid = self._idempotency.get((environment, key))
            rec = self._runs.get(rid) if rid else None
            return rec.model_copy(deep=True) if rec else None

    def recover_interrupted_runs(self, completed_at: str) -> int:
        with self._lock:
            count = 0
            for rec in self._runs.values():
                if rec.status in ("PENDING", "RUNNING"):
                    rec.status = "FAILED"
                    rec.completed_at = completed_at
                    rec.final_state = {
                        "incident_id": rec.case_id or rec.run_id,
                        "profile_id": rec.profile_id,
                        "environment": rec.environment,
                        "terminal_status": "OPERATIONAL_FAILURE",
                        "terminal_reason": "Interrupted by server restart prior to completion.",
                        "root_cause_summary": "Run interrupted by server restart.",
                    }
                    seq = len(rec.events) + 1
                    rec.events.append({"seq": seq, "data": {"type": "error", "error": "Interrupted by server restart prior to completion."}})
                    count += 1
            return count

    def mark_running(self, run_id: str) -> bool:
        with self._lock:
            rec = self._runs.get(run_id)
            if rec is None or rec.status not in ("PENDING", "RUNNING"):
                return False
            rec.status = "RUNNING"
            return True

    def append_event(self, run_id: str, event_payload: Dict[str, Any]) -> int:
        with self._lock:
            rec = self._runs.get(run_id)
            if rec is None:
                return 0
            seq = len(rec.events) + 1
            rec.events.append({"seq": seq, "data": dict(event_payload)})
            return seq

    def list_events_after(self, run_id: str, last_seq: int = 0) -> List[Dict[str, Any]]:
        with self._lock:
            rec = self._runs.get(run_id)
            if rec is None:
                return []
            return [dict(ev) for ev in rec.events if ev["seq"] > last_seq]

    def commit_terminal(
        self,
        run_id: str,
        *,
        status: RunLifecycleStatus,
        final_state: Dict[str, Any],
        brief_markdown: str,
        brief_json: str,
        completed_at: str,
    ) -> bool:
        with self._lock:
            rec = self._runs.get(run_id)
            if rec is None or rec.status in ("COMPLETED", "CANCELED", "FAILED"):
                return False
            rec.status = status
            rec.final_state = final_state
            rec.brief_markdown = brief_markdown
            rec.brief_json = brief_json
            rec.completed_at = completed_at
            return True

    def save_approval(self, approval: ApprovalRecord) -> ApprovalRecord:
        with self._lock:
            if len(self._approvals) >= self.maxsize and approval.case_id not in self._approvals:
                oldest = next(iter(self._approvals))
                del self._approvals[oldest]
            self._approvals[approval.case_id] = approval
            if approval.run_id:
                self._approvals[f"run:{approval.run_id}"] = approval
            return approval

    def get_approval(self, key: str) -> Optional[ApprovalRecord]:
        with self._lock:
            return self._approvals.get(key)

    def purge_expired(self, max_age_seconds: int) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=max_age_seconds)).isoformat()
        with self._lock:
            stale = [rid for rid, r in self._runs.items() if r.created_at < cutoff]
            for rid in stale:
                del self._runs[rid]
            return len(stale)


class SQLiteRunRepository:
    """Zero-dependency SQLite RunRepository surviving server restarts with atomic terminal commits."""

    def __init__(self, db_path: Path | str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA busy_timeout=5000")
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    case_id TEXT,
                    idempotency_key TEXT,
                    request_fingerprint TEXT,
                    environment TEXT NOT NULL,
                    profile_id TEXT NOT NULL,
                    profile_version TEXT NOT NULL,
                    schema_version TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    completed_at TEXT,
                    final_state_json TEXT,
                    brief_markdown TEXT,
                    brief_json TEXT
                );
                CREATE TABLE IF NOT EXISTS run_events (
                    run_id TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,
                    PRIMARY KEY (run_id, seq)
                );
                CREATE TABLE IF NOT EXISTS approvals (
                    approval_key TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    run_id TEXT,
                    proposal_id TEXT,
                    decision TEXT NOT NULL,
                    operator_id TEXT NOT NULL,
                    environment TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                );
                """
            )
            cols = {r["name"] for r in conn.execute("PRAGMA table_info(runs)").fetchall()}
            if "idempotency_key" not in cols:
                conn.execute("ALTER TABLE runs ADD COLUMN idempotency_key TEXT")
            if "request_fingerprint" not in cols:
                conn.execute("ALTER TABLE runs ADD COLUMN request_fingerprint TEXT")
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_runs_env_idemp ON runs(environment, idempotency_key) WHERE idempotency_key IS NOT NULL"
            )

    def create_run(self, record: RunRecord) -> None:
        with self._lock, self._connect() as conn:
            if record.idempotency_key:
                existing = conn.execute(
                    "SELECT run_id, request_fingerprint FROM runs WHERE environment = ? AND idempotency_key = ?",
                    (record.environment, record.idempotency_key),
                ).fetchone()
                if existing is not None:
                    if existing["request_fingerprint"] != record.request_fingerprint:
                        raise IdempotencyConflictError("Idempotency-Key reused with different request payload.")
                    return
            conn.execute(
                """
                INSERT INTO runs (
                    run_id, case_id, idempotency_key, request_fingerprint, environment,
                    profile_id, profile_version, schema_version, status, created_at,
                    completed_at, final_state_json, brief_markdown, brief_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.run_id,
                    record.case_id,
                    record.idempotency_key,
                    record.request_fingerprint,
                    record.environment,
                    record.profile_id,
                    record.profile_version,
                    record.schema_version,
                    record.status,
                    record.created_at,
                    record.completed_at,
                    json.dumps(record.final_state, default=str) if record.final_state is not None else None,
                    record.brief_markdown,
                    record.brief_json,
                ),
            )

    @staticmethod
    def _safe_json_loads(raw: Optional[str], context: str) -> Any:
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.warning("Corrupted JSON detected in SQLite (%s): %s", context, exc)
            return {"corrupted_payload": True, "error": str(exc)}

    def _row_to_record(self, conn: sqlite3.Connection, row: sqlite3.Row) -> RunRecord:
        ev_rows = conn.execute(
            "SELECT seq, payload_json FROM run_events WHERE run_id = ? ORDER BY seq ASC",
            (row["run_id"],),
        ).fetchall()
        events = []
        for r in ev_rows:
            parsed = self._safe_json_loads(r["payload_json"], f"run_events:{row['run_id']}:{r['seq']}")
            events.append({"seq": r["seq"], "data": parsed if isinstance(parsed, dict) else {"raw": str(parsed)}})
        final_state = self._safe_json_loads(row["final_state_json"], f"runs:{row['run_id']}")
        return RunRecord(
            run_id=row["run_id"],
            case_id=row["case_id"],
            idempotency_key=row["idempotency_key"],
            request_fingerprint=row["request_fingerprint"],
            environment=row["environment"],
            profile_id=row["profile_id"],
            profile_version=row["profile_version"],
            schema_version=row["schema_version"],
            status=row["status"],
            created_at=row["created_at"],
            completed_at=row["completed_at"],
            final_state=final_state if isinstance(final_state, dict) else None,
            brief_markdown=row["brief_markdown"],
            brief_json=row["brief_json"],
            events=events,
        )

    def get_run(self, run_id: str) -> Optional[RunRecord]:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
            if row is None:
                return None
            return self._row_to_record(conn, row)

    def get_by_idempotency_key(self, environment: str, key: str) -> Optional[RunRecord]:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM runs WHERE environment = ? AND idempotency_key = ?",
                (environment, key),
            ).fetchone()
            if row is None:
                return None
            return self._row_to_record(conn, row)

    def recover_interrupted_runs(self, completed_at: str) -> int:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT run_id, case_id, profile_id, environment FROM runs WHERE status IN ('PENDING', 'RUNNING')"
            ).fetchall()
            if not rows:
                return 0
            for r in rows:
                rid = r["run_id"]
                err_state = {
                    "incident_id": r["case_id"] or rid,
                    "profile_id": r["profile_id"],
                    "environment": r["environment"],
                    "terminal_status": "OPERATIONAL_FAILURE",
                    "terminal_reason": "Interrupted by server restart prior to completion.",
                    "root_cause_summary": "Run interrupted by server restart.",
                }
                conn.execute(
                    """
                    UPDATE runs
                    SET status = 'FAILED', completed_at = ?, final_state_json = ?
                    WHERE run_id = ? AND status IN ('PENDING', 'RUNNING')
                    """,
                    (completed_at, json.dumps(err_state), rid),
                )
                seq_row = conn.execute(
                    "SELECT COALESCE(MAX(seq), 0) AS max_seq FROM run_events WHERE run_id = ?",
                    (rid,),
                ).fetchone()
                seq = int(seq_row["max_seq"]) + 1 if seq_row else 1
                conn.execute(
                    "INSERT INTO run_events (run_id, seq, payload_json) VALUES (?, ?, ?)",
                    (rid, seq, json.dumps({"type": "error", "error": "Interrupted by server restart prior to completion."})),
                )
            return len(rows)

    def mark_running(self, run_id: str) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "UPDATE runs SET status = 'RUNNING' WHERE run_id = ? AND status IN ('PENDING', 'RUNNING')",
                (run_id,),
            )
            return cur.rowcount > 0

    def append_event(self, run_id: str, event_payload: Dict[str, Any]) -> int:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT COALESCE(MAX(seq), 0) AS max_seq FROM run_events WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            seq = int(row["max_seq"]) + 1 if row else 1
            conn.execute(
                "INSERT INTO run_events (run_id, seq, payload_json) VALUES (?, ?, ?)",
                (run_id, seq, json.dumps(event_payload, default=str)),
            )
            return seq

    def list_events_after(self, run_id: str, last_seq: int = 0) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT seq, payload_json FROM run_events WHERE run_id = ? AND seq > ? ORDER BY seq ASC",
                (run_id, last_seq),
            ).fetchall()
            out: List[Dict[str, Any]] = []
            for r in rows:
                parsed = self._safe_json_loads(r["payload_json"], f"run_events:{run_id}:{r['seq']}")
                out.append({"seq": r["seq"], "data": parsed if isinstance(parsed, dict) else {"raw": str(parsed)}})
            return out

    def commit_terminal(
        self,
        run_id: str,
        *,
        status: RunLifecycleStatus,
        final_state: Dict[str, Any],
        brief_markdown: str,
        brief_json: str,
        completed_at: str,
    ) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                """
                UPDATE runs
                SET status = ?, final_state_json = ?, brief_markdown = ?, brief_json = ?, completed_at = ?
                WHERE run_id = ? AND status IN ('PENDING', 'RUNNING')
                """,
                (
                    status,
                    json.dumps(final_state, default=str),
                    brief_markdown,
                    brief_json,
                    completed_at,
                    run_id,
                ),
            )
            return cur.rowcount > 0

    def save_approval(self, approval: ApprovalRecord) -> ApprovalRecord:
        with self._lock, self._connect() as conn:
            keys = [approval.case_id]
            if approval.run_id:
                keys.append(f"run:{approval.run_id}")
            for k in keys:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO approvals (
                        approval_key, case_id, run_id, proposal_id, decision, operator_id, environment, timestamp
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        k,
                        approval.case_id,
                        approval.run_id,
                        approval.proposal_id,
                        approval.decision,
                        approval.operator_id,
                        approval.environment,
                        approval.timestamp,
                    ),
                )
            return approval

    def get_approval(self, key: str) -> Optional[ApprovalRecord]:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM approvals WHERE approval_key = ?", (key,)).fetchone()
            if row is None:
                return None
            return ApprovalRecord(
                case_id=row["case_id"],
                run_id=row["run_id"],
                proposal_id=row["proposal_id"],
                decision=row["decision"],
                operator_id=row["operator_id"],
                environment=row["environment"],
                timestamp=row["timestamp"],
            )

    def purge_expired(self, max_age_seconds: int) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=max_age_seconds)).isoformat()
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT run_id FROM runs WHERE created_at < ?", (cutoff,)).fetchall()
            ids = [r["run_id"] for r in rows]
            if not ids:
                return 0
            placeholders = ",".join("?" for _ in ids)
            conn.execute(f"DELETE FROM run_events WHERE run_id IN ({placeholders})", ids)
            cur = conn.execute(f"DELETE FROM runs WHERE run_id IN ({placeholders})", ids)
            return cur.rowcount
