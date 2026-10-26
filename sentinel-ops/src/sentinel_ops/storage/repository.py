"""RunRepository abstractions supporting bounded in-memory and zero-dependency SQLite persistence."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import threading
from typing import Any, Dict, List, Literal, Optional, Protocol
from pydantic import BaseModel, Field


RunLifecycleStatus = Literal["PENDING", "RUNNING", "COMPLETED", "CANCELED", "FAILED"]


class RunRecord(BaseModel):
    """Persistent or in-memory snapshot of a single incident triage execution."""

    run_id: str
    case_id: Optional[str] = None
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
    data = json.loads(raw_json)
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
        self._approvals: Dict[str, ApprovalRecord] = {}

    def create_run(self, record: RunRecord) -> None:
        with self._lock:
            if len(self._runs) >= self.maxsize and record.run_id not in self._runs:
                oldest = next(iter(self._runs))
                del self._runs[oldest]
            self._runs[record.run_id] = record

    def get_run(self, run_id: str) -> Optional[RunRecord]:
        with self._lock:
            rec = self._runs.get(run_id)
            return rec.model_copy(deep=True) if rec else None

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

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=5.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    case_id TEXT,
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

    def create_run(self, record: RunRecord) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO runs (
                    run_id, case_id, environment, profile_id, profile_version,
                    schema_version, status, created_at, completed_at,
                    final_state_json, brief_markdown, brief_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.run_id,
                    record.case_id,
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

    def get_run(self, run_id: str) -> Optional[RunRecord]:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
            if row is None:
                return None
            ev_rows = conn.execute(
                "SELECT seq, payload_json FROM run_events WHERE run_id = ? ORDER BY seq ASC",
                (run_id,),
            ).fetchall()
            return RunRecord(
                run_id=row["run_id"],
                case_id=row["case_id"],
                environment=row["environment"],
                profile_id=row["profile_id"],
                profile_version=row["profile_version"],
                schema_version=row["schema_version"],
                status=row["status"],
                created_at=row["created_at"],
                completed_at=row["completed_at"],
                final_state=json.loads(row["final_state_json"]) if row["final_state_json"] else None,
                brief_markdown=row["brief_markdown"],
                brief_json=row["brief_json"],
                events=[{"seq": r["seq"], "data": json.loads(r["payload_json"])} for r in ev_rows],
            )

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
            return [{"seq": r["seq"], "data": json.loads(r["payload_json"])} for r in rows]

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
