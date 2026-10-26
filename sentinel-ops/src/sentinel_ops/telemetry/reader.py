"""Unified TelemetryReader interface unifying live Prometheus/Tempo queries and snapshot replay."""

from __future__ import annotations

from datetime import datetime, timezone
import time
from typing import Any, Dict, List, Optional, Protocol, Tuple
import uuid

from sentinel_ops.core.config import settings
from sentinel_ops.mcp.prometheus_adapter import PrometheusAdapter
from sentinel_ops.mcp.tempo_adapter import TempoAdapter
from sentinel_ops.telemetry.models import (
    NormalizedMetricObservation,
    NormalizedTraceObservation,
    ProbeAttempt,
    TelemetrySnapshot,
)
from sentinel_ops.telemetry.normalize import (
    DEFAULT_JOIN_LABELS,
    normalize_prometheus_response,
    normalize_tempo_trace,
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _remaining_timeout(deadline_ts: Optional[float]) -> Optional[float]:
    if deadline_ts is None:
        return None
    rem = deadline_ts - time.monotonic()
    if rem <= 0.0:
        return 0.0
    return max(0.001, min(settings.PER_QUERY_TIMEOUT_SECONDS, rem))


class TelemetryReader(Protocol):
    """Single reader interface invoked by specialists for both live backends and replay snapshots."""

    async def read_metric(
        self,
        *,
        service: str,
        metric_type: str,
        window: Tuple[str, str],
        incident_timestamp: Optional[str] = None,
        deadline_ts: Optional[float] = None,
        capacity_signal: str = "db_pool_size",
        join_labels: Tuple[str, ...] = DEFAULT_JOIN_LABELS,
        logical_signal: Optional[str] = None,
        allowed_services: Optional[Tuple[str, ...]] = None,
        promql_templates: Optional[Dict[str, str]] = None,
    ) -> Tuple[List[NormalizedMetricObservation], List[ProbeAttempt]]:
        ...

    async def read_trace(
        self,
        *,
        target_service: str,
        window: Tuple[str, str],
        trace_id: Optional[str] = None,
        incident_timestamp: Optional[str] = None,
        deadline_ts: Optional[float] = None,
    ) -> Tuple[NormalizedTraceObservation, List[ProbeAttempt]]:
        ...


class LiveTelemetryReader:
    """Executes bounded live Prometheus & Tempo reads with ProbeAttempt recording and optional capture."""

    def __init__(
        self,
        prom_adapter: Optional[PrometheusAdapter] = None,
        tempo_adapter: Optional[TempoAdapter] = None,
        capture_snapshot: Optional[TelemetrySnapshot] = None,
    ):
        self.prom_adapter = prom_adapter or PrometheusAdapter()
        self.tempo_adapter = tempo_adapter or TempoAdapter()
        self.capture_snapshot = capture_snapshot

    async def aclose(self) -> None:
        await self.prom_adapter.aclose()
        await self.tempo_adapter.aclose()

    async def read_metric(
        self,
        *,
        service: str,
        metric_type: str,
        window: Tuple[str, str],
        incident_timestamp: Optional[str] = None,
        deadline_ts: Optional[float] = None,
        capacity_signal: str = "db_pool_size",
        join_labels: Tuple[str, ...] = DEFAULT_JOIN_LABELS,
        logical_signal: Optional[str] = None,
        allowed_services: Optional[Tuple[str, ...]] = None,
        promql_templates: Optional[Dict[str, str]] = None,
    ) -> Tuple[List[NormalizedMetricObservation], List[ProbeAttempt]]:
        attempts: List[ProbeAttempt] = []
        attempt_id = f"att_{uuid.uuid4().hex[:10]}"
        probe_key = f"prom:{service}:{metric_type}"

        budget = _remaining_timeout(deadline_ts)
        if budget == 0.0:
            attempts.append(ProbeAttempt(
                attempt_id=attempt_id,
                probe_key=probe_key,
                backend="prometheus",
                service=service,
                signal_name=metric_type,
                requested_window=window,
                query_string=f"{service}_{metric_type}",
                status="BUDGET_EXCEEDED",
                acquired_at=_utc_now_iso(),
                error_detail="deadline exceeded before execution",
            ))
            obs = NormalizedMetricObservation(
                observation_id=f"OBS-prom-{attempt_id}",
                attempt_id=attempt_id,
                service=service,
                signal_name=metric_type,
                requested_window=window,
                status="TOOL_FAILURE",
                finding=f"Query aborted: deadline exceeded before live execution ({service} {metric_type})",
            )
            return [obs], attempts

        t0 = time.perf_counter()
        q_kwargs: Dict[str, Any] = {"timeout_override": budget}
        if allowed_services is not None:
            q_kwargs["allowed_services"] = allowed_services
        if promql_templates is not None:
            q_kwargs["promql_templates"] = promql_templates
        res = await self.prom_adapter.query_metric(
            service=service,
            metric_type=metric_type,
            window=window,
            **q_kwargs,
        )
        dur_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        promql = res.get("promql", f"{service}_{metric_type}")
        raw_status = res.get("status", "EMPTY")
        attempts.append(ProbeAttempt(
            attempt_id=attempt_id,
            probe_key=probe_key,
            backend="prometheus",
            service=service,
            signal_name=metric_type,
            requested_window=window,
            query_string=promql,
            status=raw_status if raw_status in ("SUCCESS", "EMPTY", "TOOL_FAILURE") else "TOOL_FAILURE",  # type: ignore
            duration_ms=dur_ms,
            acquired_at=_utc_now_iso(),
            error_detail=res.get("error"),
        ))

        if self.capture_snapshot is not None and raw_status == "SUCCESS":
            svc_bucket = self.capture_snapshot.prometheus.setdefault(service, {})
            svc_bucket[metric_type] = {"status": raw_status, "result": res.get("result", [])}

        cap_res: Optional[Dict[str, Any]] = None
        is_pool_active = (logical_signal or metric_type) in ("db_pool_active", "pool_active")
        if raw_status == "SUCCESS" and is_pool_active and capacity_signal:
            cap_budget = _remaining_timeout(deadline_ts)
            if cap_budget != 0.0:
                cap_attempt_id = f"att_{uuid.uuid4().hex[:10]}"
                ct0 = time.perf_counter()
                cap_kwargs: Dict[str, Any] = {"timeout_override": cap_budget}
                if allowed_services is not None:
                    cap_kwargs["allowed_services"] = allowed_services
                if promql_templates is not None:
                    cap_kwargs["promql_templates"] = promql_templates
                cap_res = await self.prom_adapter.query_metric(
                    service=service,
                    metric_type=capacity_signal,
                    window=window,
                    **cap_kwargs,
                )
                cdur_ms = round((time.perf_counter() - ct0) * 1000.0, 2)
                cstatus = cap_res.get("status", "EMPTY")
                attempts.append(ProbeAttempt(
                    attempt_id=cap_attempt_id,
                    probe_key=f"prom:{service}:{capacity_signal}",
                    backend="prometheus",
                    service=service,
                    signal_name=capacity_signal,
                    requested_window=window,
                    query_string=cap_res.get("promql", f"{service}_{capacity_signal}"),
                    status=cstatus if cstatus in ("SUCCESS", "EMPTY", "TOOL_FAILURE") else "TOOL_FAILURE",  # type: ignore
                    duration_ms=cdur_ms,
                    acquired_at=_utc_now_iso(),
                    error_detail=cap_res.get("error"),
                ))
                if self.capture_snapshot is not None and cstatus == "SUCCESS":
                    svc_bucket = self.capture_snapshot.prometheus.setdefault(service, {})
                    svc_bucket[capacity_signal] = {"status": cstatus, "result": cap_res.get("result", [])}

        obs_list = normalize_prometheus_response(
            attempt_id=attempt_id,
            service=service,
            signal_name=metric_type,
            response=res,
            window=window,
            incident_timestamp=incident_timestamp,
            capacity_response=cap_res,
            join_labels=join_labels,
            logical_signal=logical_signal,
        )
        return obs_list, attempts

    async def read_trace(
        self,
        *,
        target_service: str,
        window: Tuple[str, str],
        trace_id: Optional[str] = None,
        incident_timestamp: Optional[str] = None,
        deadline_ts: Optional[float] = None,
    ) -> Tuple[NormalizedTraceObservation, List[ProbeAttempt]]:
        attempts: List[ProbeAttempt] = []
        attempt_id = f"att_{uuid.uuid4().hex[:10]}"

        budget = _remaining_timeout(deadline_ts)
        if budget == 0.0:
            attempts.append(ProbeAttempt(
                attempt_id=attempt_id,
                probe_key=f"tempo:{target_service}:trace",
                backend="tempo",
                service=target_service,
                signal_name="trace",
                requested_window=window,
                query_string=trace_id or f"search:{target_service}",
                status="BUDGET_EXCEEDED",
                acquired_at=_utc_now_iso(),
                error_detail="deadline exceeded before execution",
            ))
            obs = NormalizedTraceObservation(
                observation_id=f"OBS-tempo-{attempt_id}",
                attempt_id=attempt_id,
                target_service=target_service,
                trace_id=trace_id or f"trace_{target_service}",
                requested_window=window,
                status="TOOL_FAILURE",
                finding=f"Trace collection aborted: deadline exceeded before live execution ({target_service})",
            )
            return obs, attempts

        resolved_trace_id = trace_id
        if not resolved_trace_id:
            st0 = time.perf_counter()
            resolved_trace_id = await self.tempo_adapter.search_traces(
                service=target_service,
                start_iso=window[0],
                end_iso=window[1],
                timeout_override=budget,
            )
            sdur_ms = round((time.perf_counter() - st0) * 1000.0, 2)
            attempts.append(ProbeAttempt(
                attempt_id=f"att_{uuid.uuid4().hex[:10]}",
                probe_key=f"tempo:{target_service}:search",
                backend="tempo",
                service=target_service,
                signal_name="trace_search",
                requested_window=window,
                query_string=f"search:{target_service}",
                status="SUCCESS" if resolved_trace_id else "EMPTY",
                duration_ms=sdur_ms,
                acquired_at=_utc_now_iso(),
            ))

        if not resolved_trace_id:
            obs = normalize_tempo_trace(
                attempt_id=attempt_id,
                target_service=target_service,
                trace_id=None,
                trace_data=None,
                window=window,
                incident_timestamp=incident_timestamp,
            )
            return obs, attempts

        budget = _remaining_timeout(deadline_ts)
        if budget == 0.0:
            attempts.append(ProbeAttempt(
                attempt_id=attempt_id,
                probe_key=f"tempo:{target_service}:waterfall",
                backend="tempo",
                service=target_service,
                signal_name="trace",
                requested_window=window,
                query_string=resolved_trace_id,
                status="BUDGET_EXCEEDED",
                acquired_at=_utc_now_iso(),
                error_detail="deadline exceeded before trace waterfall fetch",
            ))
            obs = NormalizedTraceObservation(
                observation_id=f"OBS-tempo-{attempt_id}",
                attempt_id=attempt_id,
                target_service=target_service,
                trace_id=resolved_trace_id,
                requested_window=window,
                status="TOOL_FAILURE",
                finding=f"Trace collection aborted: deadline exceeded before trace fetch ({resolved_trace_id})",
            )
            return obs, attempts

        wt0 = time.perf_counter()
        res = await self.tempo_adapter.get_trace_waterfall(
            trace_id=resolved_trace_id,
            timeout_override=budget,
        )
        wdur_ms = round((time.perf_counter() - wt0) * 1000.0, 2)
        w_status = res.get("status", "EMPTY")
        attempts.append(ProbeAttempt(
            attempt_id=attempt_id,
            probe_key=f"tempo:{target_service}:waterfall",
            backend="tempo",
            service=target_service,
            signal_name="trace",
            requested_window=window,
            query_string=resolved_trace_id,
            status=w_status if w_status in ("SUCCESS", "EMPTY", "TOOL_FAILURE") else "TOOL_FAILURE",  # type: ignore
            duration_ms=wdur_ms,
            acquired_at=_utc_now_iso(),
            error_detail=res.get("error"),
        ))

        if self.capture_snapshot is not None and w_status == "SUCCESS":
            self.capture_snapshot.tempo[resolved_trace_id] = dict(res)

        obs = normalize_tempo_trace(
            attempt_id=attempt_id,
            target_service=target_service,
            trace_id=resolved_trace_id,
            trace_data=res,
            window=window,
            incident_timestamp=incident_timestamp,
        )
        return obs, attempts


class SnapshotReplayReader:
    """Executes offline telemetry reads through the exact same normalizer as live queries."""

    def __init__(self, snapshot: Dict[str, Any]):
        self.snapshot = snapshot or {}

    async def read_metric(
        self,
        *,
        service: str,
        metric_type: str,
        window: Tuple[str, str],
        incident_timestamp: Optional[str] = None,
        deadline_ts: Optional[float] = None,
        capacity_signal: str = "db_pool_size",
        join_labels: Tuple[str, ...] = DEFAULT_JOIN_LABELS,
        logical_signal: Optional[str] = None,
        allowed_services: Optional[Tuple[str, ...]] = None,
        promql_templates: Optional[Dict[str, str]] = None,
    ) -> Tuple[List[NormalizedMetricObservation], List[ProbeAttempt]]:
        attempt_id = f"att_{uuid.uuid4().hex[:10]}"
        probe_key = f"prom:{service}:{metric_type}"

        if deadline_ts and time.monotonic() > deadline_ts:
            attempts = [ProbeAttempt(
                attempt_id=attempt_id,
                probe_key=probe_key,
                backend="prometheus",
                service=service,
                signal_name=metric_type,
                requested_window=window,
                query_string=f"{service}_{metric_type}",
                status="BUDGET_EXCEEDED",
                acquired_at=_utc_now_iso(),
                error_detail="deadline exceeded before replay read",
            )]
            return [NormalizedMetricObservation(
                observation_id=f"OBS-prom-{attempt_id}",
                attempt_id=attempt_id,
                service=service,
                signal_name=metric_type,
                requested_window=window,
                status="TOOL_FAILURE",
                finding=f"Query aborted: deadline exceeded before execution ({service} {metric_type})",
            )], attempts

        svc_metrics = self.snapshot.get("prometheus", {}).get(service, {})
        raw_entry = svc_metrics.get(metric_type)
        if raw_entry is None:
            raw_entry = {
                "status": "EMPTY",
                "finding": f"Metric '{metric_type}' for service '{service}' not present in replay snapshot (EMPTY)",
            }

        is_pool_active = (logical_signal or metric_type) in ("db_pool_active", "pool_active")
        cap_entry = svc_metrics.get(capacity_signal) if (is_pool_active and capacity_signal) else None
        attempts = [ProbeAttempt(
            attempt_id=attempt_id,
            probe_key=probe_key,
            backend="prometheus",
            service=service,
            signal_name=metric_type,
            requested_window=window,
            query_string=f"{service}_{metric_type}",
            status=raw_entry.get("status", "EMPTY") if raw_entry.get("status", "EMPTY") in ("SUCCESS", "EMPTY", "TOOL_FAILURE") else "TOOL_FAILURE",  # type: ignore
            acquired_at=_utc_now_iso(),
            error_detail=raw_entry.get("error"),
        )]
        if cap_entry is not None:
            attempts.append(ProbeAttempt(
                attempt_id=f"att_{uuid.uuid4().hex[:10]}",
                probe_key=f"prom:{service}:{capacity_signal}",
                backend="prometheus",
                service=service,
                signal_name=capacity_signal,
                requested_window=window,
                query_string=f"{service}_{capacity_signal}",
                status=cap_entry.get("status", "EMPTY") if cap_entry.get("status", "EMPTY") in ("SUCCESS", "EMPTY", "TOOL_FAILURE") else "TOOL_FAILURE",  # type: ignore
                acquired_at=_utc_now_iso(),
            ))

        obs_list = normalize_prometheus_response(
            attempt_id=attempt_id,
            service=service,
            signal_name=metric_type,
            response=raw_entry,
            window=window,
            incident_timestamp=incident_timestamp,
            capacity_response=cap_entry,
            join_labels=join_labels,
            logical_signal=logical_signal,
        )
        return obs_list, attempts

    async def read_trace(
        self,
        *,
        target_service: str,
        window: Tuple[str, str],
        trace_id: Optional[str] = None,
        incident_timestamp: Optional[str] = None,
        deadline_ts: Optional[float] = None,
    ) -> Tuple[NormalizedTraceObservation, List[ProbeAttempt]]:
        attempt_id = f"att_{uuid.uuid4().hex[:10]}"
        if deadline_ts and time.monotonic() > deadline_ts:
            attempts = [ProbeAttempt(
                attempt_id=attempt_id,
                probe_key=f"tempo:{target_service}:trace",
                backend="tempo",
                service=target_service,
                signal_name="trace",
                requested_window=window,
                query_string=trace_id or f"trace_{target_service}",
                status="BUDGET_EXCEEDED",
                acquired_at=_utc_now_iso(),
                error_detail="deadline exceeded before replay read",
            )]
            return NormalizedTraceObservation(
                observation_id=f"OBS-tempo-{attempt_id}",
                attempt_id=attempt_id,
                target_service=target_service,
                trace_id=trace_id or f"trace_{target_service}",
                requested_window=window,
                status="TOOL_FAILURE",
                finding=f"Trace collection aborted: deadline exceeded before execution ({target_service})",
            ), attempts

        tempo_map = self.snapshot.get("tempo", {}) or {}
        selected_tid: Optional[str] = None
        selected_data: Optional[Dict[str, Any]] = None

        if trace_id:
            if trace_id in tempo_map:
                selected_tid = trace_id
                selected_data = tempo_map[trace_id]
        elif tempo_map:
            for tid in sorted(tempo_map.keys()):
                tdata = tempo_map[tid]
                if tdata.get("status", "SUCCESS") == "SUCCESS":
                    selected_tid = tid
                    selected_data = tdata
                    break
            if not selected_tid:
                selected_tid = sorted(tempo_map.keys())[0]
                selected_data = tempo_map[selected_tid]

        attempts = [ProbeAttempt(
            attempt_id=attempt_id,
            probe_key=f"tempo:{target_service}:trace",
            backend="tempo",
            service=target_service,
            signal_name="trace",
            requested_window=window,
            query_string=selected_tid or trace_id or f"trace_{target_service}",
            status=(selected_data or {}).get("status", "EMPTY") if selected_data else "EMPTY",  # type: ignore
            acquired_at=_utc_now_iso(),
            error_detail=(selected_data or {}).get("error") if selected_data else None,
        )]

        obs = normalize_tempo_trace(
            attempt_id=attempt_id,
            target_service=target_service,
            trace_id=selected_tid or trace_id,
            trace_data=selected_data,
            window=window,
            incident_timestamp=incident_timestamp,
        )
        return obs, attempts
