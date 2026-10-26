"""Specialist worker nodes routing live and replay telemetry through the unified TelemetryReader."""

import hashlib
import logging
from typing import Any, Dict, List, Optional, Tuple

from sentinel_ops.agents.state import EvidenceItem
from sentinel_ops.mcp.prometheus_adapter import PrometheusAdapter
from sentinel_ops.mcp.tempo_adapter import TempoAdapter
from sentinel_ops.telemetry.models import NormalizedTraceObservation
from sentinel_ops.telemetry.normalize import _interpret_single_series, extract_join_key
from sentinel_ops.telemetry.reader import LiveTelemetryReader, SnapshotReplayReader

logger = logging.getLogger(__name__)

_PROM_ADAPTER: Optional[PrometheusAdapter] = None
_TEMPO_ADAPTER: Optional[TempoAdapter] = None


def get_prometheus_adapter() -> PrometheusAdapter:
    global _PROM_ADAPTER
    if _PROM_ADAPTER is None:
        _PROM_ADAPTER = PrometheusAdapter()
    return _PROM_ADAPTER


def get_tempo_adapter() -> TempoAdapter:
    global _TEMPO_ADAPTER
    if _TEMPO_ADAPTER is None:
        _TEMPO_ADAPTER = TempoAdapter()
    return _TEMPO_ADAPTER


def _metric_tag(metric_type: str) -> str:
    return {
        "db_pool_acquire_timeouts_total": "db_acq",
        "upstream_connect_timeouts_total": "upst",
        "db_pool_size": "db_sz",
        "db_pool_active": "db_p",
        "latency_p95": "late",
        "error_rate": "erro",
        "cpu_saturation": "cpu_",
        "memory_usage": "memo",
        "container_restarts": "rest",
    }.get(metric_type, metric_type[:4])


def _evidence_status(obs_status: str) -> str:
    if obs_status in ("STALE_TELEMETRY", "UNSUPPORTED"):
        return "EMPTY"
    return obs_status


def interpret_metric(
    service: str,
    metric_type: str,
    values: List[Any],
    capacity: Optional[float] = None,
) -> Tuple[str, str, str]:
    """Uniform metric interpreter delegating cleanly to telemetry.normalize."""
    if not values:
        return ("EMPTY", f"No metric samples returned for {service} {metric_type}", "")
    join_status = "single_series" if capacity is not None else "missing_denominator"
    obs = _interpret_single_series(
        attempt_id="direct_interpret",
        service=service,
        signal_name=metric_type,
        labels={},
        join_key=extract_join_key({}),
        values=values,
        window=("", ""),
        capacity_val=capacity,
        join_status=join_status,
    )
    return (_evidence_status(obs.status), obs.finding, obs.raw_payload or str(values))


async def metrics_specialist_node(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Specialist agent node collecting and normalizing Prometheus metrics via TelemetryReader."""
    service = payload.get("service", "unknown")
    metric_type = payload.get("metric_type", "error_rate")
    window = payload.get("observation_window", ("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"))
    sim_telem = payload.get("simulated_telemetry")
    incident_ts = payload.get("incident_timestamp")
    deadline_ts = payload.get("deadline_timestamp")

    reader = payload.get("telemetry_reader")
    if reader is None:
        if sim_telem is not None:
            reader = SnapshotReplayReader(sim_telem)
        else:
            reader = LiveTelemetryReader(prom_adapter=get_prometheus_adapter())

    profile_id = payload.get("profile_id", "checkout-demo")
    read_kwargs: Dict[str, Any] = {}
    try:
        from sentinel_ops.profiles.registry import get_profile
        profile = get_profile(profile_id)
        sig_map = profile.resolve_signal(metric_type)
        if sig_map:
            read_kwargs["logical_signal"] = sig_map.logical_signal
            if sig_map.capacity_signal:
                read_kwargs["capacity_signal"] = sig_map.capacity_signal
        svc_spec = profile.services.get(service)
        if svc_spec and svc_spec.replica_join_labels:
            read_kwargs["join_labels"] = tuple(svc_spec.replica_join_labels)
        if profile_id != "checkout-demo":
            read_kwargs["allowed_services"] = profile.resolve_service_names()
            read_kwargs["promql_templates"] = profile.to_promql_templates()
    except Exception:
        pass

    obs_list, attempts = await reader.read_metric(
        service=service,
        metric_type=metric_type,
        window=window,
        incident_timestamp=incident_ts,
        deadline_ts=deadline_ts,
        **read_kwargs,
    )

    m_tag = _metric_tag(metric_type)
    base_ev_id = f"EV-prom-{service[:4]}-{m_tag}"
    items: List[EvidenceItem] = []
    multi = len(obs_list) > 1

    for idx, obs in enumerate(obs_list):
        ev_id = base_ev_id
        if multi:
            suffix = hashlib.sha1(obs.join_key.encode("utf-8")).hexdigest()[:4]
            ev_id = f"{base_ev_id}-{suffix}-{idx}"
        q_params: Dict[str, Any] = {
            "service": service,
            "metric_type": metric_type,
            "observation_id": obs.observation_id,
        }
        if obs.join_key != "unlabeled":
            q_params["join_key"] = obs.join_key
        if obs.entity_labels:
            q_params["entity_labels"] = dict(obs.entity_labels)

        items.append(EvidenceItem(
            id=ev_id,
            backend_source="prometheus",
            query_string=attempts[0].query_string if attempts else f"{service}_{metric_type}",
            query_params=q_params,
            observation_window=window,
            sample_or_span_ref=metric_type,
            finding=obs.finding,
            raw_payload=obs.raw_payload,
            status=_evidence_status(obs.status),  # type: ignore
        ))

    return {
        "evidence": items,
        "observations": obs_list,
        "probe_attempts": attempts,
    }


async def trace_specialist_node(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Specialist agent node collecting and normalizing Tempo traces via TelemetryReader."""
    target_service = payload.get("target_service", "checkout-service")
    window = payload.get("observation_window", ("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"))
    trace_id = payload.get("trace_id")
    sim_telem = payload.get("simulated_telemetry")
    incident_ts = payload.get("incident_timestamp")
    deadline_ts = payload.get("deadline_timestamp")

    reader = payload.get("telemetry_reader")
    if reader is None:
        if sim_telem is not None:
            reader = SnapshotReplayReader(sim_telem)
        else:
            reader = LiveTelemetryReader(tempo_adapter=get_tempo_adapter())

    obs, attempts = await reader.read_trace(
        target_service=target_service,
        window=window,
        trace_id=trace_id,
        incident_timestamp=incident_ts,
        deadline_ts=deadline_ts,
    )
    assert isinstance(obs, NormalizedTraceObservation)

    evidence_id = f"EV-tempo-{target_service[:4]}"
    q_params: Dict[str, Any] = {
        "target_service": target_service,
        "trace_id": obs.trace_id,
        "observation_id": obs.observation_id,
    }
    if obs.bottleneck_service:
        q_params["service"] = obs.bottleneck_service
    if obs.bottleneck_operation:
        q_params["operation"] = obs.bottleneck_operation

    span_ref = "span_waterfall"
    if obs.error_spans:
        span_ref = str(obs.error_spans[0].get("span_id") or "span_waterfall")

    item = EvidenceItem(
        id=evidence_id,
        backend_source="tempo",
        query_string=obs.trace_id,
        query_params=q_params,
        observation_window=window,
        sample_or_span_ref=span_ref,
        finding=obs.finding,
        raw_payload=obs.raw_payload,
        status=_evidence_status(obs.status),  # type: ignore
    )
    return {
        "evidence": [item],
        "observations": [obs],
        "probe_attempts": attempts,
    }
