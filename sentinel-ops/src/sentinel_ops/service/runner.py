"""Shared application InvestigationService managing run execution, SSE events, cancellation, and isolation."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import hashlib
import json
import logging
import time
from typing import Any, AsyncIterator, Dict, Optional
import uuid

from sentinel_ops.agents.graph import compile_investigation_graph
from sentinel_ops.agents.specialists import set_backend_semaphores
from sentinel_ops.agents.state import EvidenceItem
from sentinel_ops.agents.synthesizer import format_incident_brief
from sentinel_ops.core.config import settings
from sentinel_ops.memory.graph_rag import TopologyGraphRAG
from sentinel_ops.profiles.registry import get_profile
from sentinel_ops.storage.repository import IdempotencyConflictError, MemoryRunRepository, RunRecord, RunRepository
from sentinel_ops.telemetry.reader import LiveTelemetryReader, SnapshotReplayReader

logger = logging.getLogger(__name__)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _serialize_state(state: Dict[str, Any], redact_raw: bool = False) -> Dict[str, Any]:
    """Converts InvestigationState output dict into JSON-serializable state respecting payload retention policy."""
    out = dict(state)
    evs = out.get("evidence") or []
    clean_evs = []
    for e in evs:
        if isinstance(e, EvidenceItem):
            d = e.model_dump()
        elif isinstance(e, dict):
            d = dict(e)
        else:
            d = dict(getattr(e, "model_dump", lambda: {})())
        if redact_raw:
            d["raw_payload"] = "[REDACTED: replay_disabled]"
        clean_evs.append(d)
    out["evidence"] = clean_evs

    claims = out.get("structured_claims") or []
    out["structured_claims"] = [
        c.model_dump() if hasattr(c, "model_dump") else dict(c) for c in claims
    ]
    adv = out.get("adversarial_verdict")
    if adv is not None and hasattr(adv, "model_dump"):
        out["adversarial_verdict"] = adv.model_dump()
    out["observations"] = [
        o.model_dump() if hasattr(o, "model_dump") else dict(o)
        for o in (out.get("observations") or [])
    ]
    out["probe_attempts"] = [
        a.model_dump() if hasattr(a, "model_dump") else dict(a)
        for a in (out.get("probe_attempts") or [])
    ]
    out["raw_payload_retention"] = "redacted" if redact_raw else "sanitized"
    return out


class InvestigationService:
    """Single lifecycle orchestrator shared across HTTP API, CLI, and Benchmark suites."""

    def __init__(
        self,
        repository: Optional[RunRepository] = None,
        max_concurrent_backend_calls: int = 8,
    ):
        self.repo: RunRepository = repository or MemoryRunRepository(maxsize=500)
        self.repo.recover_interrupted_runs(completed_at=_utc_now_iso())
        self.backend_semaphores: Dict[str, asyncio.Semaphore] = {
            "prometheus": asyncio.Semaphore(max_concurrent_backend_calls),
            "tempo": asyncio.Semaphore(max_concurrent_backend_calls),
        }
        set_backend_semaphores(max_concurrent=max_concurrent_backend_calls)
        self._tasks: Dict[str, asyncio.Task[Any]] = {}
        self._notifiers: Dict[str, asyncio.Condition] = {}
        self._subscribers: Dict[str, int] = {}
        self._readers: list[LiveTelemetryReader] = []

    def _cleanup_run_handles(self, run_id: str) -> None:
        self._tasks.pop(run_id, None)
        if self._subscribers.get(run_id, 0) <= 0:
            self._notifiers.pop(run_id, None)
            self._subscribers.pop(run_id, None)

    def _get_notifier(self, run_id: str) -> asyncio.Condition:
        cond = self._notifiers.get(run_id)
        if cond is None:
            cond = asyncio.Condition()
            self._notifiers[run_id] = cond
        return cond

    async def _emit(self, run_id: str, payload: Dict[str, Any]) -> int:
        seq = self.repo.append_event(run_id, payload)
        cond = self._notifiers.get(run_id)
        if cond is not None:
            async with cond:
                cond.notify_all()
        return seq

    async def aclose(self) -> None:
        for task in list(self._tasks.values()):
            if not task.done():
                task.cancel()
        for reader in list(self._readers):
            try:
                await reader.aclose()
            except Exception:
                pass
        self._readers.clear()

    def build_initial_state(
        self,
        *,
        incident_id: str,
        alert_text: str,
        incident_timestamp: str,
        target_service: str,
        profile_id: str = "checkout-demo",
        environment: str = "default",
        trace_id: Optional[str] = None,
        use_llm: bool = False,
        window_before_minutes: int = 2,
        window_after_minutes: int = 3,
        simulated_telemetry: Optional[Dict[str, Any]] = None,
        historical_context: Optional[list[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        profile = get_profile(profile_id)
        if historical_context is None:
            rag = TopologyGraphRAG(profile=profile)
            matches = rag.retrieve(
                alert_text=alert_text,
                target_service=target_service,
                incident_timestamp=incident_timestamp,
                top_k=2,
            )
            historical_context = [
                {
                    "id": m["postmortem"].incident_id,
                    "incident_id": m["postmortem"].incident_id,
                    "title": m["postmortem"].title,
                    "service": m["postmortem"].root_cause_service,
                    "score": m["composite_score"],
                }
                for m in matches
            ]
        return {
            "incident_id": incident_id,
            "alert_text": alert_text,
            "incident_timestamp": incident_timestamp,
            "target_service": target_service,
            "profile_id": profile.profile_id,
            "environment": environment,
            "window_before_minutes": window_before_minutes,
            "window_after_minutes": window_after_minutes,
            "trace_id": trace_id,
            "use_llm": use_llm,
            "historical_context": historical_context,
            "simulated_telemetry": simulated_telemetry,
            "deadline_timestamp": time.monotonic() + settings.RUN_DEADLINE_SECONDS,
            "crag_iterations": 0,
        }

    async def execute_state_sync(self, initial_state: Dict[str, Any], thread_id: Optional[str] = None) -> Dict[str, Any]:
        """Executes the graph directly through the shared service engine (used by CLI & benchmarks)."""
        graph = compile_investigation_graph()
        tid = thread_id or f"{initial_state.get('incident_id', 'run')}_{uuid.uuid4().hex[:8]}"
        return await graph.ainvoke(initial_state, config={"configurable": {"thread_id": tid}})

    async def start_run(
        self,
        *,
        case_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        incident_id: str,
        alert_text: str,
        incident_timestamp: str,
        target_service: str,
        profile_id: str = "checkout-demo",
        environment: str = "default",
        trace_id: Optional[str] = None,
        use_llm: bool = False,
        window_before_minutes: int = 2,
        window_after_minutes: int = 3,
        simulated_telemetry: Optional[Dict[str, Any]] = None,
        redact_raw: Optional[bool] = None,
    ) -> str:
        """Creates a RunRecord and launches a decoupled background investigation once."""
        if settings.SENTINEL_ENV_SCOPE and environment != settings.SENTINEL_ENV_SCOPE:
            raise PermissionError(
                f"Environment '{environment}' is not permitted under scope '{settings.SENTINEL_ENV_SCOPE}'."
            )

        profile = get_profile(profile_id)
        fp_payload = {
            "case_id": case_id,
            "target_service": target_service,
            "profile_id": profile.profile_id,
            "environment": environment,
            "trace_id": trace_id,
            "alert_text": alert_text,
            "incident_timestamp": incident_timestamp,
            "window_before_minutes": window_before_minutes,
            "window_after_minutes": window_after_minutes,
            "use_llm": use_llm,
        }
        req_fp = hashlib.sha256(json.dumps(fp_payload, sort_keys=True).encode("utf-8")).hexdigest()
        if idempotency_key:
            existing = self.repo.get_by_idempotency_key(environment, idempotency_key)
            if existing is not None:
                if existing.request_fingerprint != req_fp:
                    raise IdempotencyConflictError("Idempotency-Key reused with different request payload.")
                return existing.run_id

        run_id = uuid.uuid4().hex[:12]
        eff_redact = settings.SENTINEL_REDACT_RAW_PAYLOADS if redact_raw is None else redact_raw

        self.repo.create_run(
            RunRecord(
                run_id=run_id,
                case_id=case_id,
                idempotency_key=idempotency_key,
                request_fingerprint=req_fp,
                environment=environment,
                profile_id=profile.profile_id,
                profile_version=profile.version,
                schema_version="3.0",
                status="PENDING",
                created_at=_utc_now_iso(),
            )
        )
        self._get_notifier(run_id)
        initial_state = self.build_initial_state(
            incident_id=incident_id,
            alert_text=alert_text,
            incident_timestamp=incident_timestamp,
            target_service=target_service,
            profile_id=profile.profile_id,
            environment=environment,
            trace_id=trace_id,
            use_llm=use_llm,
            window_before_minutes=window_before_minutes,
            window_after_minutes=window_after_minutes,
            simulated_telemetry=simulated_telemetry,
        )

        async def _runner() -> None:
            self.repo.mark_running(run_id)
            await self._emit(run_id, {
                "type": "init",
                "run_id": run_id,
                "incident_id": incident_id,
                "profile_id": profile.profile_id,
                "profile_version": profile.version,
                "alert": alert_text,
            })
            await self._emit(run_id, {
                "type": "graph_rag",
                "matches": initial_state["historical_context"],
            })

            graph = compile_investigation_graph()
            config = {"configurable": {"thread_id": f"run_{run_id}"}}
            try:
                final_state: Dict[str, Any] = dict(initial_state)
                async for chunk in graph.astream(initial_state, config=config, stream_mode="updates"):
                    for node_name, update in chunk.items():
                        if isinstance(update, dict):
                            # Respect reducer keys while tracking latest scalars
                            for k, v in update.items():
                                if k in ("evidence", "observations", "probe_attempts") and isinstance(v, list):
                                    final_state[k] = list(final_state.get(k) or []) + v
                                else:
                                    final_state[k] = v
                        if node_name == "supervisor":
                            await self._emit(run_id, {
                                "type": "supervisor",
                                "status": "Decomposing incident into parallel hypotheses",
                            })

                # Pull exact checkpointed terminal state so reducers match 100%
                snap = graph.get_state(config)
                if snap and getattr(snap, "values", None):
                    final_state = dict(snap.values)

                evidence_list = [
                    {"id": e.id, "source": e.backend_source, "finding": e.finding, "status": e.status}
                    for e in final_state.get("evidence", [])
                ]
                await self._emit(run_id, {"type": "evidence", "items": evidence_list})

                claims_list = [
                    {
                        "id": c.claim_id,
                        "type": c.claim_type,
                        "statement": c.statement,
                        "citations": c.cited_evidence_ids,
                    }
                    for c in final_state.get("structured_claims", [])
                ]
                await self._emit(run_id, {"type": "claims", "claims": claims_list})

                adv = final_state.get("adversarial_verdict")
                if adv:
                    await self._emit(run_id, {
                        "type": "adversarial",
                        "supported": adv.all_claims_supported,
                        "confidence": adv.confidence,
                        "critique": adv.critique_hint,
                    })

                serialized = _serialize_state(final_state, redact_raw=eff_redact)
                brief_md = format_incident_brief(serialized, fmt="markdown")
                brief_js = format_incident_brief(serialized, fmt="json")
                committed = self.repo.commit_terminal(
                    run_id,
                    status="COMPLETED",
                    final_state=serialized,
                    brief_markdown=brief_md,
                    brief_json=brief_js,
                    completed_at=_utc_now_iso(),
                )
                if committed:
                    blast = {
                        "run_id": run_id,
                        "score": final_state.get("blast_radius_score", 0.0),
                        "callers": final_state.get("affected_callers", []),
                        "remediation": final_state.get("remediation_proposal"),
                        "recommended_runbook_action": final_state.get("recommended_runbook_action"),
                        "next_discriminating_checks": final_state.get("next_discriminating_checks", []),
                        "terminal_status": final_state.get("terminal_status"),
                        "terminal_reason": final_state.get("terminal_reason"),
                        "summary": final_state.get("root_cause_summary"),
                        "brief_markdown": brief_md,
                    }
                    await self._emit(run_id, {"type": "terminal", "data": blast})
            except asyncio.CancelledError:
                canceled_state = _serialize_state({
                    **initial_state,
                    "terminal_status": "OPERATIONAL_FAILURE",
                    "terminal_reason": "Investigation canceled by operator.",
                    "root_cause_summary": "Investigation canceled prior to completion.",
                }, redact_raw=eff_redact)
                brief_md = format_incident_brief(canceled_state, fmt="markdown")
                brief_js = format_incident_brief(canceled_state, fmt="json")
                if self.repo.commit_terminal(
                    run_id,
                    status="CANCELED",
                    final_state=canceled_state,
                    brief_markdown=brief_md,
                    brief_json=brief_js,
                    completed_at=_utc_now_iso(),
                ):
                    await self._emit(run_id, {
                        "type": "terminal",
                        "data": {
                            "run_id": run_id,
                            "score": 0.0,
                            "callers": [],
                            "terminal_status": "OPERATIONAL_FAILURE",
                            "terminal_reason": "Investigation canceled by operator.",
                            "brief_markdown": brief_md,
                        },
                    })
                raise
            except Exception as err:
                logger.error("Run %s execution failed: %s", run_id, err)
                try:
                    err_state = _serialize_state({
                        **initial_state,
                        "terminal_status": "OPERATIONAL_FAILURE",
                        "terminal_reason": str(err),
                        "root_cause_summary": f"Execution error: {err}",
                    }, redact_raw=eff_redact)
                    brief_md = format_incident_brief(err_state, fmt="markdown")
                    brief_js = format_incident_brief(err_state, fmt="json")
                    if self.repo.commit_terminal(
                        run_id,
                        status="FAILED",
                        final_state=err_state,
                        brief_markdown=brief_md,
                        brief_json=brief_js,
                        completed_at=_utc_now_iso(),
                    ):
                        await self._emit(run_id, {"type": "error", "error": str(err)})
                except Exception as commit_err:
                    logger.critical("Fallback error commit failed for run %s: %s", run_id, commit_err)
                    try:
                        self.repo.commit_terminal(
                            run_id,
                            status="FAILED",
                            final_state={"terminal_status": "OPERATIONAL_FAILURE", "terminal_reason": str(err)},
                            brief_markdown=f"# Error\n{err}",
                            brief_json=json.dumps({"terminal_status": "OPERATIONAL_FAILURE", "error": str(err)}),
                            completed_at=_utc_now_iso(),
                        )
                    except Exception:
                        pass
                    cond = self._notifiers.get(run_id)
                    if cond is not None:
                        async with cond:
                            cond.notify_all()
            finally:
                self._cleanup_run_handles(run_id)

        task = asyncio.create_task(_runner(), name=f"sentinel_run_{run_id}")
        self._tasks[run_id] = task
        task.add_done_callback(lambda _t, rid=run_id: self._cleanup_run_handles(rid))
        return run_id

    async def cancel_run(self, run_id: str) -> Optional[RunRecord]:
        rec = self.repo.get_run(run_id)
        if rec is None:
            return None
        task = self._tasks.get(run_id)
        if task and not task.done():
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        rec_after = self.repo.get_run(run_id)
        if rec_after is not None and rec_after.status in ("PENDING", "RUNNING"):
            # Commit cancel atomically if task was cancelled before entering try/except or reference was lost
            canceled_state = {
                "incident_id": rec_after.case_id or run_id,
                "target_service": "unknown",
                "profile_id": rec_after.profile_id,
                "terminal_status": "OPERATIONAL_FAILURE",
                "terminal_reason": "Investigation canceled by operator.",
                "root_cause_summary": "Investigation canceled prior to completion.",
            }
            self.repo.commit_terminal(
                run_id,
                status="CANCELED",
                final_state=canceled_state,
                brief_markdown=format_incident_brief(canceled_state, fmt="markdown"),
                brief_json=format_incident_brief(canceled_state, fmt="json"),
                completed_at=_utc_now_iso(),
            )
            cond = self._notifiers.get(run_id)
            if cond is not None:
                async with cond:
                    cond.notify_all()
        return self.repo.get_run(run_id)

    async def subscribe_events(self, run_id: str, last_event_id: int = 0) -> AsyncIterator[Dict[str, Any]]:
        """Yields sequenced events after last_event_id and tails live transitions until terminal commit."""
        cursor = max(0, int(last_event_id))
        cond = self._get_notifier(run_id)
        self._subscribers[run_id] = self._subscribers.get(run_id, 0) + 1
        try:
            while True:
                pending = self.repo.list_events_after(run_id, last_seq=cursor)
                for ev in pending:
                    cursor = ev["seq"]
                    yield ev
                rec = self.repo.get_run(run_id)
                if rec is None:
                    return
                if rec.status in ("COMPLETED", "CANCELED", "FAILED"):
                    tail = self.repo.list_events_after(run_id, last_seq=cursor)
                    for ev in tail:
                        yield ev
                    return
                async with cond:
                    if self.repo.list_events_after(run_id, last_seq=cursor):
                        continue
                    rec_now = self.repo.get_run(run_id)
                    if rec_now is None or rec_now.status in ("COMPLETED", "CANCELED", "FAILED"):
                        continue
                    try:
                        await asyncio.wait_for(cond.wait(), timeout=2.0)
                    except asyncio.TimeoutError:
                        pass
        finally:
            rem = max(0, self._subscribers.get(run_id, 1) - 1)
            if rem == 0:
                self._subscribers.pop(run_id, None)
                if run_id not in self._tasks:
                    self._notifiers.pop(run_id, None)
            else:
                self._subscribers[run_id] = rem
