import logging
from typing import Any, Dict, List
from sentinel_ops.agents.state import EvidenceItem
from sentinel_ops.mcp.prometheus_adapter import PrometheusAdapter
from sentinel_ops.mcp.tempo_adapter import TempoAdapter

logger = logging.getLogger(__name__)


async def metrics_specialist_node(payload: Dict[str, Any]) -> Dict[str, List[EvidenceItem]]:
    """Specialist agent node that collects and sanitizes Prometheus metrics."""
    service = payload.get("service", "unknown")
    metric_type = payload.get("metric_type", "error_rate")
    window = payload.get("observation_window", ("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"))

    sim_telem = payload.get("simulated_telemetry") or {}
    simulated_data = sim_telem.get("prometheus", {}).get(service, {}).get(metric_type)
    evidence_id = f"EV-prom-{service[:4]}-{metric_type[:4]}"

    if simulated_data is not None:
        status = simulated_data.get("status", "SUCCESS")
        values = simulated_data.get("values", [])
        if status == "SUCCESS":
            val = float(values[-1][1]) if values else 0.0
            if metric_type == "db_pool_active":
                finding = (
                    f"payment_db_pool_active saturated at {val} (pool size = 2)"
                    if val >= 2.0
                    else f"payment_db_pool_active normal at {val} (pool size = 100)"
                )
            elif metric_type == "latency_p95":
                if val >= 1.0:
                    finding = f"{service} latency_p95 spiked critically at {val}s (anomaly detected)"
                else:
                    finding = f"{service} latency_p95 normal at {val}s (healthy)"
            else:
                finding = f"{service} {metric_type} observed at {val}"
            raw_payload = str(values)
        elif status == "EMPTY":
            finding = f"No {metric_type} metrics returned for {service} (EMPTY)"
            raw_payload = ""
        else:
            finding = f"Telemetry exporter failure for {service}: {simulated_data.get('error', 'Unknown error')}"
            raw_payload = ""

        item = EvidenceItem(
            id=evidence_id,
            backend_source="prometheus",
            query_string=f"{service}_{metric_type}",
            query_params={"service": service, "metric_type": metric_type},
            observation_window=window,
            sample_or_span_ref=metric_type,
            finding=finding,
            raw_payload=raw_payload,
            status=status,
        )
        return {"evidence": [item]}

    # Live Prometheus querying
    adapter = PrometheusAdapter()
    res = await adapter.query_metric(service=service, metric_type=metric_type, window=window)
    status = res.get("status", "EMPTY")
    promql = res.get("promql", f"{service}_{metric_type}")

    if status == "SUCCESS":
        series = res.get("result", [])
        finding = f"Prometheus query returned {len(series)} series for {service} {metric_type}"
        raw_payload = res.get("formatted", str(series))
    elif status == "EMPTY":
        finding = f"Prometheus query returned empty result for {service} {metric_type}"
        raw_payload = ""
    else:
        finding = f"Prometheus tool failure: {res.get('error', 'Execution error')}"
        raw_payload = ""

    item = EvidenceItem(
        id=evidence_id,
        backend_source="prometheus",
        query_string=promql,
        query_params={"service": service, "metric_type": metric_type},
        observation_window=window,
        sample_or_span_ref=metric_type,
        finding=finding,
        raw_payload=raw_payload,
        status=status,
    )
    return {"evidence": [item]}


async def trace_specialist_node(payload: Dict[str, Any]) -> Dict[str, List[EvidenceItem]]:
    """Specialist agent node that collects and summarizes Tempo traces."""
    target_service = payload.get("target_service", "checkout-service")
    window = payload.get("observation_window", ("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"))
    sim_telem = payload.get("simulated_telemetry") or {}
    simulated_tempo = sim_telem.get("tempo", {})
    evidence_id = f"EV-tempo-{target_service[:4]}"

    if simulated_tempo:
        trace_id = list(simulated_tempo.keys())[0]
        trace_data = simulated_tempo[trace_id]
        status = trace_data.get("status", "SUCCESS")
        if status == "SUCCESS":
            bottleneck = trace_data.get("bottleneck_service", "unknown")
            dur = trace_data.get("bottleneck_duration_ms", 0.0)
            finding = f"Distributed trace {trace_id} waterfall: bottleneck in {bottleneck} ({dur}ms)"
            raw_payload = str(trace_data)
        elif status == "EMPTY":
            finding = f"No distributed trace spans found for {target_service} (EMPTY)"
            raw_payload = ""
        else:
            finding = f"Tempo trace collection failure: {trace_data.get('error', 'unknown error')}"
            raw_payload = ""

        item = EvidenceItem(
            id=evidence_id,
            backend_source="tempo",
            query_string=trace_id,
            query_params={"target_service": target_service, "trace_id": trace_id},
            observation_window=window,
            sample_or_span_ref="span_waterfall",
            finding=finding,
            raw_payload=raw_payload,
            status=status,
        )
        return {"evidence": [item]}

    # Live Tempo querying (query default checkout trace or return EMPTY if none configured)
    adapter = TempoAdapter()
    res = await adapter.get_trace_waterfall(trace_id="chk-root-trace")
    status = res.get("status", "EMPTY")

    if status == "SUCCESS":
        finding = f"Tempo trace analysis isolated bottleneck in {res.get('bottleneck_service')} ({res.get('bottleneck_duration_ms')}ms)"
        raw_payload = res.get("formatted", "")
    elif status == "EMPTY":
        finding = f"No traces found for {target_service} in Tempo"
        raw_payload = ""
    else:
        finding = f"Tempo tool failure: {res.get('error')}"
        raw_payload = ""

    item = EvidenceItem(
        id=evidence_id,
        backend_source="tempo",
        query_string="chk-root-trace",
        query_params={"target_service": target_service},
        observation_window=window,
        sample_or_span_ref="span_waterfall",
        finding=finding,
        raw_payload=raw_payload,
        status=status,
    )
    return {"evidence": [item]}
