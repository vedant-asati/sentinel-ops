import logging
import math
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from sentinel_ops.agents.state import EvidenceItem
from sentinel_ops.core.config import settings
from sentinel_ops.mcp.prometheus_adapter import PrometheusAdapter
from sentinel_ops.mcp.tempo_adapter import TempoAdapter, analyze_trace_spans
from sentinel_ops.security.sanitizer import wrap_telemetry, defang_telemetry_tags
from sentinel_ops.security.redact import scrub_credentials

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


def _compute_remaining_timeout(deadline_ts: Optional[float]) -> Optional[float]:
    if deadline_ts is None:
        return None
    rem = deadline_ts - time.monotonic()
    if rem <= 0.0:
        return 0.0
    return max(0.001, min(settings.PER_QUERY_TIMEOUT_SECONDS, rem))


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
        if capacity is not None and capacity > 0:
            occupancy = val / capacity
            if occupancy >= 0.95:
                finding = f"payment_db_pool_active saturated at {val:.1f} / {capacity:.1f} ({occupancy*100:.0f}% capacity exhausted)"
            else:
                finding = f"payment_db_pool_active normal at {val:.1f} / {capacity:.1f} ({occupancy*100:.0f}% capacity, healthy)"
        else:
            finding = f"payment_db_pool_active observed at {val:.1f} (capacity unrecorded; cannot determine saturation)"
    elif metric_type == "latency_p95":
        if val >= 1.0:
            finding = f"{service} latency_p95 spiked critically at {val:.3f}s (anomaly detected)"
        else:
            finding = f"{service} latency_p95 normal at {val:.3f}s (healthy)"
    elif metric_type == "cpu_saturation":
        if val >= 0.85:
            finding = f"{service} cpu_saturation critically saturated at {val*100:.0f}%"
        else:
            finding = f"{service} cpu_saturation normal at {val*100:.0f}%"
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
    elif metric_type in ("db_pool_acquire_timeouts_total", "upstream_connect_timeouts_total"):
        for s in values:
            try:
                v = float(s[1])
                if not math.isfinite(v) or math.isnan(v):
                    return ("TOOL_FAILURE", f"Invalid or non-finite metric value observed for {service} {metric_type}: '{s[1]}'", str(values))
            except (ValueError, TypeError):
                return ("TOOL_FAILURE", f"Non-numeric metric value observed for {service} {metric_type}: '{s[1]}'", str(values))

        if len(values) >= 2:
            v_start = float(values[0][1])
            v_end = float(values[-1][1])
            if v_end > v_start:
                finding = f"{service} {metric_type} spiked with delta +{v_end - v_start:.0f} timeouts"
            elif v_end == 0 and v_start > 0:
                finding = f"{service} {metric_type} counter reset to 0 (counter-reset detected)"
            else:
                finding = f"{service} {metric_type} flat at {v_end:.0f} (no increase)"
        else:
            finding = f"{service} {metric_type} observed at {val}"
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
    if metric_type == "db_pool_acquire_timeouts_total":
        m_tag = "db_acq"
    elif metric_type == "upstream_connect_timeouts_total":
        m_tag = "upst"
    elif metric_type == "db_pool_size":
        m_tag = "db_sz"
    elif metric_type == "db_pool_active":
        m_tag = "db_p"
    elif metric_type == "latency_p95":
        m_tag = "late"
    elif metric_type == "error_rate":
        m_tag = "erro"
    elif metric_type == "cpu_saturation":
        m_tag = "cpu_"
    elif metric_type == "cpu_saturation":
        if val >= 0.85:
            finding = f"{service} cpu_saturation critically saturated at {val*100:.0f}%"
        else:
            finding = f"{service} cpu_saturation normal at {val*100:.0f}%"
    elif metric_type == "memory_usage":
        m_tag = "memo"
    elif metric_type == "container_restarts":
        m_tag = "rest"
    else:
        m_tag = metric_type[:4]
    evidence_id = f"EV-prom-{service[:4]}-{m_tag}"

    deadline_ts = payload.get("deadline_timestamp")
    if deadline_ts and time.monotonic() > deadline_ts:
        item = EvidenceItem(
            id=evidence_id,
            backend_source="prometheus",
            query_string=f"{service}_{metric_type}",
            query_params={"service": service, "metric_type": metric_type},
            observation_window=window,
            sample_or_span_ref=metric_type,
            finding=f"Query aborted: deadline exceeded before execution ({service} {metric_type})",
            raw_payload="",
            status="TOOL_FAILURE",
        )
        return {"evidence": [item]}

    incident_ts_str = payload.get("incident_timestamp")
    start_ts: Optional[float] = None
    end_ts: Optional[float] = None
    if window and len(window) == 2 and payload.get("observation_window") is not None:
        try:
            start_ts = datetime.fromisoformat(window[0].replace("Z", "+00:00")).timestamp()
            end_ts = datetime.fromisoformat(window[1].replace("Z", "+00:00")).timestamp()
        except Exception:
            start_ts, end_ts = None, None
    elif incident_ts_str:
        try:
            t_inc = datetime.fromisoformat(incident_ts_str.replace("Z", "+00:00")).timestamp()
            start_ts = t_inc - 120.0
            end_ts = t_inc + 180.0
        except Exception:
            start_ts, end_ts = None, None

    def _filter_to_window(raw_samples: List[Any]) -> Optional[List[Any]]:
        if not raw_samples or start_ts is None or end_ts is None:
            return raw_samples
        matched = [s for s in raw_samples if start_ts <= float(s[0]) <= end_ts]
        return matched if matched else None

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
        raw_values = simulated_data.get("values", [])
        if status == "SUCCESS":
            # Strictly anchor metric samples inside the declared incident observation window
            if start_ts is not None and end_ts is not None and raw_values:
                window_samples = _filter_to_window(raw_values)
                if not window_samples:
                    item = EvidenceItem(
                        id=evidence_id,
                        backend_source="prometheus",
                        query_string=f"{service}_{metric_type}",
                        query_params={"service": service, "metric_type": metric_type},
                        observation_window=window,
                        sample_or_span_ref=metric_type,
                        finding=f"Metric '{metric_type}' for service '{service}' contains only stale/out-of-window samples (STALE_TELEMETRY)",
                        raw_payload="",
                        status="EMPTY",
                    )
                    return {"evidence": [item]}
                values = window_samples
            else:
                values = raw_values

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
            if status == "SUCCESS" and raw_payload:
                raw_payload = wrap_telemetry(name=f"prom_{service}_{metric_type}", raw_content=raw_payload)
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

    # Live Prometheus querying via pooled adapter constrained by run deadline
    adapter = get_prometheus_adapter()
    timeout_budget = _compute_remaining_timeout(deadline_ts)
    if timeout_budget == 0.0:
        return {"evidence": [EvidenceItem(
            id=evidence_id,
            backend_source="prometheus",
            query_string=f"{service}_{metric_type}",
            query_params={"service": service, "metric_type": metric_type},
            observation_window=window,
            sample_or_span_ref=metric_type,
            finding=f"Query aborted: deadline exceeded before live execution ({service} {metric_type})",
            raw_payload="",
            status="TOOL_FAILURE",
        )]}

    res = await adapter.query_metric(
        service=service, metric_type=metric_type, window=window, timeout_override=timeout_budget
    )
    status = res.get("status", "EMPTY")
    promql = res.get("promql", f"{service}_{metric_type}")

    if status == "SUCCESS":
        series = res.get("result", [])
        values = series[0].get("values", []) if series else []
        # If instant vector, values might be [value]
        if not values and series and "value" in series[0]:
            values = [series[0]["value"]]

        if start_ts is not None and end_ts is not None and values:
            windowed_live = _filter_to_window(values)
            if not windowed_live:
                return {"evidence": [EvidenceItem(
                    id=evidence_id,
                    backend_source="prometheus",
                    query_string=promql,
                    query_params={"service": service, "metric_type": metric_type},
                    observation_window=window,
                    sample_or_span_ref=metric_type,
                    finding=f"Live metric '{metric_type}' for '{service}' contains only samples outside incident window (STALE_TELEMETRY)",
                    raw_payload="",
                    status="EMPTY",
                )]}
            values = windowed_live

        cap = None
        if metric_type == "db_pool_active":
            cap_timeout = _compute_remaining_timeout(deadline_ts)
            if cap_timeout != 0.0:
                cap_res = await adapter.query_metric(
                    service=service, metric_type="db_pool_size", window=window, timeout_override=cap_timeout
                )
                if cap_res.get("status") == "SUCCESS" and cap_res.get("result"):
                    sz_series = cap_res["result"]
                    sz_vals = sz_series[0].get("values") or [sz_series[0].get("value")]
                    if sz_vals:
                        try:
                            cap = float(sz_vals[-1][1])
                        except (ValueError, TypeError):
                            cap = None

        status, finding, raw_payload = interpret_metric(service, metric_type, values, capacity=cap)
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

    incident_ts_str = payload.get("incident_timestamp")
    start_ts: Optional[float] = None
    end_ts: Optional[float] = None
    if window and len(window) == 2 and payload.get("observation_window") is not None:
        try:
            start_ts = datetime.fromisoformat(window[0].replace("Z", "+00:00")).timestamp()
            end_ts = datetime.fromisoformat(window[1].replace("Z", "+00:00")).timestamp()
        except Exception:
            start_ts, end_ts = None, None
    elif incident_ts_str:
        try:
            t_inc = datetime.fromisoformat(incident_ts_str.replace("Z", "+00:00")).timestamp()
            start_ts = t_inc - 120.0
            end_ts = t_inc + 180.0
        except Exception:
            start_ts, end_ts = None, None

    def _filter_to_window(raw_samples: List[Any]) -> Optional[List[Any]]:
        if not raw_samples or start_ts is None or end_ts is None:
            return raw_samples
        matched = [s for s in raw_samples if start_ts <= float(s[0]) <= end_ts]
        return matched if matched else None

    deadline_ts = payload.get("deadline_timestamp")
    if deadline_ts and time.monotonic() > deadline_ts:
        item = EvidenceItem(
            id=evidence_id,
            backend_source="tempo",
            query_string=f"trace_{target_service}",
            query_params={"target_service": target_service},
            observation_window=window,
            sample_or_span_ref="span_waterfall",
            finding=f"Trace collection aborted: deadline exceeded before execution ({target_service})",
            raw_payload="",
            status="TOOL_FAILURE",
        )
        return {"evidence": [item]}

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

        # Never substitute another trace when a specific target_trace_id was explicitly requested
        target_trace_id = payload.get("trace_id")
        selected_trace_id = None
        selected_trace_data = None
        if target_trace_id:
            if target_trace_id not in simulated_tempo:
                return {"evidence": [EvidenceItem(
                    id=evidence_id,
                    backend_source="tempo",
                    query_string=str(target_trace_id),
                    query_params={"target_service": target_service, "trace_id": target_trace_id},
                    observation_window=window,
                    sample_or_span_ref="span_waterfall",
                    finding=f"Requested trace '{target_trace_id}' not found in replay snapshot (EMPTY)",
                    raw_payload="",
                    status="EMPTY",
                )]}
            selected_trace_id = target_trace_id
            selected_trace_data = simulated_tempo[target_trace_id]
        else:
            # Deterministic trace selection when alert has no explicit trace_id
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
        if status != "SUCCESS":
            return {"evidence": [EvidenceItem(
                id=evidence_id,
                backend_source="tempo",
                query_string=str(selected_trace_id),
                query_params={"target_service": target_service, "trace_id": selected_trace_id},
                observation_window=window,
                sample_or_span_ref="span_waterfall",
                finding=f"Trace {selected_trace_id} returned status: {status}",
                raw_payload="",
                status=status,
            )]}

        # Strict incident observation window check on trace timestamp
        trace_ts = selected_trace_data.get("timestamp")
        if start_ts is not None and end_ts is not None and trace_ts is not None:
            if not (start_ts <= float(trace_ts) <= end_ts):
                return {"evidence": [EvidenceItem(
                    id=evidence_id,
                    backend_source="tempo",
                    query_string=str(selected_trace_id),
                    query_params={"target_service": target_service, "trace_id": selected_trace_id},
                    observation_window=window,
                    sample_or_span_ref="span_waterfall",
                    finding=f"Trace {selected_trace_id} timestamp {trace_ts} outside incident window (STALE_TRACE)",
                    raw_payload="",
                    status="EMPTY",
                )]}

        spans = selected_trace_data.get("spans", [])
        timeout_span = next((s for s in spans if s.get("error") == "TimeoutError"), None)
        if timeout_span:
            dep_svc = timeout_span.get("service")
            op_name = timeout_span.get("name")
            dur = timeout_span.get("duration_ms", 0.0)
            finding = f"Distributed trace {selected_trace_id} waterfall: TimeoutError in {dep_svc} on {op_name} ({dur:.0f}ms)"
            raw_payload = wrap_telemetry(name=f"tempo_{target_service}_{selected_trace_id}", raw_content=str(selected_trace_data))
            return {"evidence": [EvidenceItem(
                id=evidence_id,
                backend_source="tempo",
                query_string=str(selected_trace_id),
                query_params={"target_service": target_service, "trace_id": selected_trace_id, "service": dep_svc, "operation": op_name},
                observation_window=window,
                sample_or_span_ref=str(timeout_span.get("span_id", "span_waterfall")),
                finding=finding,
                raw_payload=raw_payload,
                status="SUCCESS",
            )]}

        status = selected_trace_data.get("status", "SUCCESS")
        if status == "SUCCESS":
            spans = selected_trace_data.get("spans", [])
            if spans:
                analysis = analyze_trace_spans(spans, selected_trace_id)
                bottleneck_svc = analysis["bottleneck_service"] or selected_trace_data.get("bottleneck_service", "unknown")
                dur = analysis["bottleneck_duration_ms"]
                finding = f"Distributed trace {selected_trace_id} waterfall: bottleneck in {bottleneck_svc} ({dur:.1f}ms exclusive)"
            else:
                bottleneck = selected_trace_data.get("bottleneck_service", "unknown")
                dur = selected_trace_data.get("bottleneck_duration_ms", 0.0)
                finding = f"Distributed trace {selected_trace_id} waterfall: bottleneck in {bottleneck} ({dur}ms)"
            finding = scrub_credentials(defang_telemetry_tags(finding))
            raw_payload = wrap_telemetry(name=f"tempo_{target_service}_{selected_trace_id}", raw_content=str(selected_trace_data))
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

    # Live Tempo querying via pooled adapter constrained by run deadline
    adapter = get_tempo_adapter()
    timeout_budget = _compute_remaining_timeout(deadline_ts)
    if timeout_budget == 0.0:
        return {"evidence": [EvidenceItem(
            id=evidence_id,
            backend_source="tempo",
            query_string=f"trace_{target_service}",
            query_params={"target_service": target_service},
            observation_window=window,
            sample_or_span_ref="span_waterfall",
            finding=f"Trace collection aborted: deadline exceeded before live execution ({target_service})",
            raw_payload="",
            status="TOOL_FAILURE",
        )]}

    resolved_trace_id = payload.get("trace_id")
    if not resolved_trace_id:
        resolved_trace_id = await adapter.search_traces(
            service=target_service,
            start_iso=window[0],
            end_iso=window[1],
            timeout_override=timeout_budget,
        )

    if not resolved_trace_id:
        return {"evidence": [EvidenceItem(
            id=evidence_id,
            backend_source="tempo",
            query_string=f"search:{target_service}",
            query_params={"target_service": target_service},
            observation_window=window,
            sample_or_span_ref="span_waterfall",
            finding=f"No traces found for {target_service} in Tempo incident window",
            raw_payload="",
            status="EMPTY",
        )]}

    timeout_budget = _compute_remaining_timeout(deadline_ts)
    res = await adapter.get_trace_waterfall(trace_id=resolved_trace_id, timeout_override=timeout_budget)
    status = res.get("status", "EMPTY")
    spans = res.get("spans", [])
    timeout_span = next((s for s in spans if s.get("error") == "TimeoutError"), None)

    if status == "SUCCESS" and timeout_span:
        dep_svc = timeout_span.get("service")
        op_name = timeout_span.get("name")
        dur = timeout_span.get("duration_ms", 0.0)
        finding = f"Distributed trace {resolved_trace_id} waterfall: TimeoutError in {dep_svc} on {op_name} ({dur:.0f}ms)"
        raw_payload = res.get("formatted", "")
        query_params = {"target_service": target_service, "trace_id": resolved_trace_id, "service": dep_svc, "operation": op_name}
    elif status == "SUCCESS":
        finding = f"Tempo trace analysis isolated bottleneck in {res.get('bottleneck_service')} ({res.get('bottleneck_duration_ms')}ms exclusive)"
        raw_payload = res.get("formatted", "")
        query_params = {"target_service": target_service, "trace_id": resolved_trace_id}
    elif status == "EMPTY":
        finding = f"No traces found for {target_service} in Tempo"
        raw_payload = ""
        query_params = {"target_service": target_service, "trace_id": resolved_trace_id}
    else:
        finding = f"Tempo tool failure: {res.get('error')}"
        raw_payload = ""
        query_params = {"target_service": target_service, "trace_id": resolved_trace_id}

    item = EvidenceItem(
        id=evidence_id,
        backend_source="tempo",
        query_string=resolved_trace_id,
        query_params=query_params,
        observation_window=window,
        sample_or_span_ref="span_waterfall",
        finding=finding,
        raw_payload=raw_payload,
        status=status,
    )
    return {"evidence": [item]}
