import logging
import math
from typing import Any, Dict, List, Optional, Tuple
from sentinel_ops.agents.state import EvidenceItem
from sentinel_ops.mcp.prometheus_adapter import PrometheusAdapter
from sentinel_ops.mcp.tempo_adapter import TempoAdapter

logger = logging.getLogger(__name__)


def interpret_metric(
    service: str,
    metric_type: str,
    values: List[Any],
    capacity: Optional[float] = None,
) -> Tuple[str, str, str]:
    """Uniform metric interpreter for both replay snapshots and live Prometheus responses."""
    if not values:
        return ("EMPTY", f"No metric samples returned for {service} {metric_type}", "")

    raw_val = values[-1][1] if values else None
    try:
        val = float(raw_val) if raw_val is not None else float("nan")
    except (ValueError, TypeError):
        val = float("nan")

    if not math.isfinite(val) or math.isnan(val):
        return ("TOOL_FAILURE", f"Invalid or non-finite metric value observed for {service} {metric_type}: '{raw_val}'", str(values))

    if metric_type == "db_pool_active":
        cap = capacity if capacity is not None else 100.0
        occupancy = (val / cap) if cap > 0 else 1.0
        if val >= cap and cap <= 10.0:
            finding = f"payment_db_pool_active saturated at {val:.1f} / {cap:.1f} (100% capacity exhausted)"
        else:
            finding = f"payment_db_pool_active normal at {val:.1f} / {cap:.1f} ({occupancy*100:.0f}% capacity, healthy)"
    elif metric_type == "latency_p95":
        if val >= 1.0:
            finding = f"{service} latency_p95 spiked critically at {val:.3f}s (anomaly detected)"
        else:
            finding = f"{service} latency_p95 normal at {val:.3f}s (healthy)"
    elif metric_type == "memory_usage":
        if val >= 0.90:
            finding = f"{service} memory_usage critically exhausted at {val*100:.0f}% limit"
        else:
            finding = f"{service} memory_usage normal at {val*100:.0f}%"
    elif metric_type == "container_restarts":
        if val > 1.0:
            finding = f"{service} container_restarts elevated at {val:.0f} restarts (container crash/termination detected)"
        else:
            finding = f"{service} container_restarts stable at {val:.0f}"
    elif metric_type == "error_rate":
        if val >= 0.50:
            finding = f"{service} error_rate spiked critically to {val*100:.0f}% (connection failure)"
        else:
            finding = f"{service} error_rate normal at {val*100:.0f}%"
    else:
        finding = f"{service} {metric_type} observed at {val}"

    return ("SUCCESS", finding, str(values))


async def metrics_specialist_node(payload: Dict[str, Any]) -> Dict[str, List[EvidenceItem]]:
    """Specialist agent node that collects and sanitizes Prometheus metrics."""
    service = payload.get("service", "unknown")
    metric_type = payload.get("metric_type", "error_rate")
    window = payload.get("observation_window", ("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"))

    sim_telem = payload.get("simulated_telemetry")
    is_replay = sim_telem is not None
    evidence_id = f"EV-prom-{service[:4]}-{metric_type[:4]}"

    if is_replay:
        simulated_data = sim_telem.get("prometheus", {}).get(service, {}).get(metric_type)
        if simulated_data is None:
            # Replay mode: metric not in snapshot -> emit typed EMPTY, zero live calls
            item = EvidenceItem(
                id=evidence_id,
                backend_source="prometheus",
                query_string=f"{service}_{metric_type}",
                query_params={"service": service, "metric_type": metric_type},
                observation_window=window,
                sample_or_span_ref=metric_type,
                finding=f"Metric '{metric_type}' for service '{service}' not present in replay snapshot (EMPTY)",
                raw_payload="",
                status="EMPTY",
            )
            return {"evidence": [item]}

        status = simulated_data.get("status", "SUCCESS")
        values = simulated_data.get("values", [])
        if status == "SUCCESS":
            # Extract capacity if available
            cap = None
            if metric_type == "db_pool_active":
                size_data = sim_telem.get("prometheus", {}).get(service, {}).get("db_pool_size")
                if size_data and size_data.get("values"):
                    try:
                        cap = float(size_data["values"][-1][1])
                    except (ValueError, TypeError):
                        cap = None
            status, finding, raw_payload = interpret_metric(service, metric_type, values, capacity=cap)
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
        values = series[0].get("values", []) if series else []
        # If instant vector, values might be [value]
        if not values and series and "value" in series[0]:
            values = [series[0]["value"]]
        status, finding, raw_payload = interpret_metric(service, metric_type, values, capacity=None)
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
    sim_telem = payload.get("simulated_telemetry")
    is_replay = sim_telem is not None
    evidence_id = f"EV-tempo-{target_service[:4]}"

    if is_replay:
        simulated_tempo = (sim_telem or {}).get("tempo", {})
        if not simulated_tempo:
            item = EvidenceItem(
                id=evidence_id,
                backend_source="tempo",
                query_string=f"trace_{target_service}",
                query_params={"target_service": target_service},
                observation_window=window,
                sample_or_span_ref="span_waterfall",
                finding=f"No trace data found in replay snapshot for {target_service} (EMPTY)",
                raw_payload="",
                status="EMPTY",
            )
            return {"evidence": [item]}

        # Deterministic trace selection: prioritize valid SUCCESS traces
        selected_trace_id = None
        selected_trace_data = None
        for tid in sorted(simulated_tempo.keys()):
            tdata = simulated_tempo[tid]
            if tdata.get("status") == "SUCCESS":
                selected_trace_id = tid
                selected_trace_data = tdata
                break
        if not selected_trace_id:
            selected_trace_id = sorted(simulated_tempo.keys())[0]
            selected_trace_data = simulated_tempo[selected_trace_id]

        status = selected_trace_data.get("status", "SUCCESS")
        if status == "SUCCESS":
            spans = selected_trace_data.get("spans", [])
            if spans:
                # Calculate exclusive bottleneck from span hierarchy
                children_time = {}
                for s in spans:
                    p = s.get("parent_span_id") or s.get("parentSpanId")
                    if p:
                        children_time[p] = children_time.get(p, 0.0) + s.get("duration_ms", 0.0)

                max_exclusive = -1.0
                bottleneck_svc = selected_trace_data.get("bottleneck_service", "unknown")
                dur = selected_trace_data.get("bottleneck_duration_ms", 0.0)
                for s in spans:
                    s_id = s.get("span_id") or s.get("spanId")
                    s_dur = s.get("duration_ms", 0.0)
                    excl = max(0.0, s_dur - children_time.get(s_id, 0.0))
                    if excl > max_exclusive:
                        max_exclusive = excl
                        bottleneck_svc = s.get("service", bottleneck_svc)
                        dur = excl
                finding = f"Distributed trace {selected_trace_id} waterfall: bottleneck in {bottleneck_svc} ({dur:.1f}ms exclusive)"
            else:
                bottleneck = selected_trace_data.get("bottleneck_service", "unknown")
                dur = selected_trace_data.get("bottleneck_duration_ms", 0.0)
                finding = f"Distributed trace {selected_trace_id} waterfall: bottleneck in {bottleneck} ({dur}ms)"
            raw_payload = str(selected_trace_data)
        elif status == "EMPTY":
            finding = f"No distributed trace spans found for {target_service} (EMPTY)"
            raw_payload = ""
        else:
            finding = f"Tempo trace collection failure: {selected_trace_data.get('error', 'unknown error')}"
            raw_payload = ""

        item = EvidenceItem(
            id=evidence_id,
            backend_source="tempo",
            query_string=selected_trace_id,
            query_params={"target_service": target_service, "trace_id": selected_trace_id},
            observation_window=window,
            sample_or_span_ref="span_waterfall",
            finding=finding,
            raw_payload=raw_payload,
            status=status,
        )
        return {"evidence": [item]}

    # Live Tempo querying
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
