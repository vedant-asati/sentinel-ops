"""Unified normalization & label-keyed multi-replica join logic for live and replay telemetry."""

from __future__ import annotations

from datetime import datetime
import hashlib
import math
from typing import Any, Dict, List, Optional, Tuple

from sentinel_ops.mcp.tempo_adapter import analyze_trace_spans
from sentinel_ops.security.redact import scrub_credentials
from sentinel_ops.security.sanitizer import defang_telemetry_tags, wrap_telemetry
from sentinel_ops.telemetry.models import NormalizedMetricObservation, NormalizedTraceObservation


DEFAULT_JOIN_LABELS: Tuple[str, ...] = ("pod", "instance", "container", "service", "app")

SIGNAL_UNITS: Dict[str, Tuple[str, str]] = {
    "error_rate": ("ratio", "gauge"),
    "latency_p95": ("seconds", "histogram_quantile"),
    "db_pool_active": ("ratio", "ratio"),
    "db_pool_size": ("connections", "gauge"),
    "db_pool_acquire_timeouts_total": ("timeouts", "counter_delta"),
    "upstream_connect_timeouts_total": ("timeouts", "counter_delta"),
    "cpu_saturation": ("ratio", "gauge"),
    "memory_usage": ("ratio", "gauge"),
    "container_restarts": ("restarts", "gauge"),
}


def extract_join_key(
    labels: Optional[Dict[str, Any]],
    join_labels: Tuple[str, ...] = DEFAULT_JOIN_LABELS,
) -> str:
    """Computes a canonical replica identity key from Prometheus label dictionaries."""
    if not labels or not isinstance(labels, dict):
        return "unlabeled"
    cleaned = {
        str(k): str(v)
        for k, v in labels.items()
        if str(k) != "__name__" and v is not None and str(v) != ""
    }
    if not cleaned:
        return "unlabeled"
    selected = [(k, cleaned[k]) for k in join_labels if k in cleaned]
    if not selected:
        selected = sorted(cleaned.items())
    else:
        selected = sorted(selected)
    return "|".join(f"{k}={v}" for k, v in selected)


def _make_observation_id(prefix: str, service: str, signal: str, join_key: str, window: Tuple[str, str]) -> str:
    digest = hashlib.sha1(f"{prefix}:{service}:{signal}:{join_key}:{window[0]}:{window[1]}".encode("utf-8")).hexdigest()[:12]
    return f"OBS-{prefix}-{digest}"


def parse_window_bounds(
    window: Optional[Tuple[str, str]],
    incident_timestamp: Optional[str] = None,
) -> Tuple[Optional[float], Optional[float]]:
    """Resolves inclusive UTC epoch bounds [start_ts, end_ts] from window or T_incident [-120s, +180s]."""
    if window and isinstance(window, (tuple, list)) and len(window) == 2:
        try:
            s_ts = datetime.fromisoformat(str(window[0]).replace("Z", "+00:00")).timestamp()
            e_ts = datetime.fromisoformat(str(window[1]).replace("Z", "+00:00")).timestamp()
            return s_ts, e_ts
        except Exception:
            pass
    if incident_timestamp:
        try:
            t_inc = datetime.fromisoformat(str(incident_timestamp).replace("Z", "+00:00")).timestamp()
            return t_inc - 120.0, t_inc + 180.0
        except Exception:
            pass
    return None, None


def filter_samples_to_window(
    raw_samples: List[Any],
    start_ts: Optional[float],
    end_ts: Optional[float],
) -> Tuple[List[Any], bool]:
    """Filters Prometheus sample pairs strictly to [start_ts, end_ts]; returns (samples, stale_only)."""
    if not raw_samples or start_ts is None or end_ts is None:
        return raw_samples, False
    matched = []
    for s in raw_samples:
        try:
            ts = float(s[0])
        except (ValueError, TypeError, IndexError):
            continue
        if start_ts <= ts <= end_ts:
            matched.append(s)
    if not matched:
        return [], True
    return matched, False


def _validate_finite_samples(values: List[Any], service: str, signal_name: str) -> Tuple[Optional[List[Tuple[float, float]]], Optional[str]]:
    """Parses all sample values, rejecting NaN/Inf/non-numeric strings."""
    parsed: List[Tuple[float, float]] = []
    for s in values:
        try:
            ts = float(s[0])
            raw_v = s[1]
            v = float(raw_v) if raw_v is not None else float("nan")
        except (ValueError, TypeError, IndexError):
            return None, f"Invalid or non-finite metric value observed for {service} {signal_name}: '{s}'"
        if not math.isfinite(v) or math.isnan(v):
            return None, f"Invalid or non-finite metric value observed for {service} {signal_name}: '{s[1]}'"
        parsed.append((ts, v))
    return parsed, None


def _analyze_counter_series(parsed: List[Tuple[float, float]]) -> Tuple[Optional[float], float, bool]:
    """Computes monotonic cumulative delta while detecting per-replica counter resets."""
    if not parsed:
        return None, 0.0, False
    if len(parsed) == 1:
        return None, parsed[0][1], False
    reset_detected = False
    delta = 0.0
    prev = parsed[0][1]
    for _, curr in parsed[1:]:
        if curr < prev:
            reset_detected = True
        else:
            delta += (curr - prev)
        prev = curr
    # Report raw difference if reset occurred at final point cleanly flagged as reset
    if parsed[-1][1] == 0 and parsed[0][1] > 0:
        reset_detected = True
    return delta, parsed[-1][1], reset_detected


def _interpret_single_series(
    *,
    attempt_id: str,
    service: str,
    signal_name: str,
    labels: Dict[str, str],
    join_key: str,
    values: List[Any],
    window: Tuple[str, str],
    capacity_val: Optional[float],
    join_status: str,
    logical_signal: Optional[str] = None,
) -> NormalizedMetricObservation:
    """Normalizes one Prometheus series (optionally capacity-joined) into a typed observation."""
    canon = logical_signal or signal_name
    unit, kind = SIGNAL_UNITS.get(canon, SIGNAL_UNITS.get(signal_name, ("", "gauge")))
    obs_id = _make_observation_id("prom", service, signal_name, join_key, window)
    parsed, err = _validate_finite_samples(values, service, signal_name)
    label_tag = f" [{join_key}]" if join_key != "unlabeled" else ""

    if err is not None or not parsed:
        return NormalizedMetricObservation(
            observation_id=obs_id,
            attempt_id=attempt_id,
            service=service,
            signal_name=signal_name,
            entity_labels=labels,
            join_key=join_key,
            unit=unit,
            value_kind=kind,  # type: ignore
            join_status=join_status,  # type: ignore
            requested_window=window,
            status="TOOL_FAILURE",
            finding=err or f"No valid samples for {service} {signal_name}",
            raw_payload=str(values),
        )

    timestamps = tuple(ts for ts, _ in parsed)
    val = parsed[-1][1]
    delta: Optional[float] = None
    numerator: Optional[float] = None
    denominator: Optional[float] = None
    reset_detected = False

    if canon in ("db_pool_active", "pool_active"):
        numerator = val
        denominator = capacity_val
        if join_status in ("unjoinable", "missing_denominator"):
            finding = (
                f"{signal_name} observed at {val:.1f}{label_tag} "
                f"({join_status}: capacity denominator unjoinable or missing; cannot determine saturation)"
            )
            computed_val = None
        elif capacity_val is not None and capacity_val > 0:
            occ = val / capacity_val
            computed_val = occ
            if occ >= 0.95:
                finding = (
                    f"{'payment_' if signal_name == 'db_pool_active' else ''}{signal_name} saturated at {val:.1f} / {capacity_val:.1f} "
                    f"({occ * 100:.0f}% capacity exhausted){label_tag}"
                )
            else:
                finding = (
                    f"{'payment_' if signal_name == 'db_pool_active' else ''}{signal_name} normal at {val:.1f} / {capacity_val:.1f} "
                    f"({occ * 100:.0f}% capacity, healthy){label_tag}"
                )
        else:
            computed_val = None
            finding = f"{signal_name} observed at {val:.1f}{label_tag} (capacity unrecorded; cannot determine saturation)"
        return NormalizedMetricObservation(
            observation_id=obs_id,
            attempt_id=attempt_id,
            service=service,
            signal_name=signal_name,
            entity_labels=labels,
            join_key=join_key,
            unit=unit,
            value_kind="ratio",
            value=computed_val,
            numerator=numerator,
            denominator=denominator,
            join_status=join_status,  # type: ignore
            sample_timestamps=timestamps,
            requested_window=window,
            status="SUCCESS",
            finding=finding,
            raw_payload=wrap_telemetry(f"prom_{service}_{signal_name}", str(values)),
        )

    if canon in (
        "db_pool_acquire_timeouts_total",
        "pool_acquire_timeouts",
        "upstream_connect_timeouts_total",
        "upstream_connect_timeouts",
    ):
        delta, end_val, reset_detected = _analyze_counter_series(parsed)
        if len(parsed) >= 2:
            if reset_detected and (delta or 0.0) <= 0.0:
                finding = f"{service} {signal_name}{label_tag} counter reset to {end_val:.0f} (counter-reset detected)"
            elif reset_detected and (delta or 0.0) > 0.0:
                finding = f"{service} {signal_name}{label_tag} spiked with delta +{delta:.0f} timeouts (counter-reset also detected)"
            elif (delta or 0.0) > 0.0:
                finding = f"{service} {signal_name}{label_tag} spiked with delta +{delta:.0f} timeouts"
            else:
                finding = f"{service} {signal_name}{label_tag} flat at {end_val:.0f} (no increase)"
        else:
            finding = f"{service} {signal_name}{label_tag} observed at {val}"
        return NormalizedMetricObservation(
            observation_id=obs_id,
            attempt_id=attempt_id,
            service=service,
            signal_name=signal_name,
            entity_labels=labels,
            join_key=join_key,
            unit=unit,
            value_kind="counter_delta",
            value=end_val,
            delta=delta,
            counter_reset_detected=reset_detected,
            join_status="single_series",
            sample_timestamps=timestamps,
            requested_window=window,
            status="SUCCESS",
            finding=finding,
            raw_payload=wrap_telemetry(f"prom_{service}_{signal_name}", str(values)),
        )

    if signal_name == "latency_p95":
        finding = (
            f"{service} latency_p95 spiked critically at {val:.3f}s{label_tag} (anomaly detected)"
            if val >= 1.0
            else f"{service} latency_p95 normal at {val:.3f}s{label_tag} (healthy)"
        )
    elif canon in ("cpu_saturation", "cpu_utilization"):
        finding = (
            f"{service} {signal_name} critically saturated at {val * 100:.0f}%{label_tag}"
            if val >= 0.85
            else f"{service} {signal_name} normal at {val * 100:.0f}%{label_tag}"
        )
    elif canon in ("memory_usage", "memory_utilization"):
        finding = (
            f"{service} {signal_name} critically exhausted at {val * 100:.0f}% limit{label_tag}"
            if val >= 0.90
            else f"{service} {signal_name} normal at {val * 100:.0f}%{label_tag}"
        )
    elif signal_name == "container_restarts":
        finding = (
            f"{service} container_restarts elevated at {val:.0f} restarts{label_tag} (container crash/termination detected)"
            if val > 1.0
            else f"{service} container_restarts stable at {val:.0f}{label_tag}"
        )
    elif signal_name == "error_rate":
        finding = (
            f"{service} error_rate spiked critically to {val * 100:.0f}%{label_tag} (connection failure)"
            if val >= 0.50
            else f"{service} error_rate normal at {val * 100:.0f}%{label_tag}"
        )
    else:
        finding = f"{service} {signal_name}{label_tag} observed at {val}"

    return NormalizedMetricObservation(
        observation_id=obs_id,
        attempt_id=attempt_id,
        service=service,
        signal_name=signal_name,
        entity_labels=labels,
        join_key=join_key,
        unit=unit,
        value_kind=kind,  # type: ignore
        value=val,
        join_status="single_series",
        sample_timestamps=timestamps,
        requested_window=window,
        status="SUCCESS",
        finding=finding,
        raw_payload=wrap_telemetry(f"prom_{service}_{signal_name}", str(values)),
    )


def normalize_prometheus_response(
    *,
    attempt_id: str,
    service: str,
    signal_name: str,
    response: Dict[str, Any],
    window: Tuple[str, str],
    incident_timestamp: Optional[str] = None,
    capacity_response: Optional[Dict[str, Any]] = None,
    join_labels: Tuple[str, ...] = DEFAULT_JOIN_LABELS,
    logical_signal: Optional[str] = None,
) -> List[NormalizedMetricObservation]:
    """Normalizes Prometheus live or replay payload across all returned replica series."""
    start_ts, end_ts = parse_window_bounds(window, incident_timestamp)
    raw_status = response.get("status", "EMPTY")

    if raw_status == "EMPTY":
        return [NormalizedMetricObservation(
            observation_id=_make_observation_id("prom", service, signal_name, "empty", window),
            attempt_id=attempt_id,
            service=service,
            signal_name=signal_name,
            requested_window=window,
            status="EMPTY",
            finding=response.get("finding") or f"Prometheus query returned empty result for {service} {signal_name}",
        )]

    if raw_status != "SUCCESS":
        return [NormalizedMetricObservation(
            observation_id=_make_observation_id("prom", service, signal_name, "err", window),
            attempt_id=attempt_id,
            service=service,
            signal_name=signal_name,
            requested_window=window,
            status="TOOL_FAILURE",
            finding=f"Prometheus tool failure for {service} {signal_name}: {response.get('error', 'Execution error')}",
        )]

    # Support both live result=[{"metric": ..., "values": ...}] and compact replay values=[...]
    raw_series_list = response.get("result")
    if raw_series_list is None:
        raw_vals = response.get("values") or []
        raw_series_list = [{"metric": response.get("metric") or {}, "values": raw_vals}]

    if not raw_series_list:
        return [NormalizedMetricObservation(
            observation_id=_make_observation_id("prom", service, signal_name, "empty", window),
            attempt_id=attempt_id,
            service=service,
            signal_name=signal_name,
            requested_window=window,
            status="EMPTY",
            finding=f"Prometheus query returned empty series list for {service} {signal_name}",
        )]

    # Build strict replica-keyed capacity lookup when needed
    canon = logical_signal or signal_name
    cap_by_key: Dict[str, float] = {}
    cap_has_entries = False
    if canon in ("db_pool_active", "pool_active") and capacity_response and capacity_response.get("status") == "SUCCESS":
        cap_series_list = capacity_response.get("result")
        if cap_series_list is None and capacity_response.get("values") is not None:
            cap_series_list = [{"metric": capacity_response.get("metric") or {}, "values": capacity_response.get("values") or []}]
        for cs in (cap_series_list or []):
            c_labels = {str(k): str(v) for k, v in (cs.get("metric") or {}).items()}
            c_key = extract_join_key(c_labels, join_labels)
            c_vals = cs.get("values") or ([cs["value"]] if "value" in cs else [])
            c_win, c_stale = filter_samples_to_window(c_vals, start_ts, end_ts)
            if not c_stale and c_win:
                try:
                    c_float = float(c_win[-1][1])
                    if math.isfinite(c_float):
                        cap_by_key[c_key] = c_float
                        cap_has_entries = True
                except (ValueError, TypeError):
                    pass

    observations: List[NormalizedMetricObservation] = []
    for entry in raw_series_list:
        labels = {str(k): str(v) for k, v in (entry.get("metric") or {}).items()}
        jkey = extract_join_key(labels, join_labels)
        vals = entry.get("values") or ([entry["value"]] if "value" in entry else [])
        win_vals, stale_only = filter_samples_to_window(vals, start_ts, end_ts)

        if stale_only:
            observations.append(NormalizedMetricObservation(
                observation_id=_make_observation_id("prom", service, signal_name, jkey, window),
                attempt_id=attempt_id,
                service=service,
                signal_name=signal_name,
                entity_labels=labels,
                join_key=jkey,
                requested_window=window,
                status="STALE_TELEMETRY",
                finding=f"Metric '{signal_name}' for '{service}' [{jkey}] contains only samples outside incident window (STALE_TELEMETRY)",
            ))
            continue

        cap_val: Optional[float] = None
        join_status = "single_series"
        if canon in ("db_pool_active", "pool_active"):
            if not cap_has_entries:
                join_status = "missing_denominator"
            elif jkey in cap_by_key:
                cap_val = cap_by_key[jkey]
                join_status = "single_series" if jkey == "unlabeled" and len(raw_series_list) == 1 and len(cap_by_key) == 1 else "label_joined"
            elif len(raw_series_list) == 1 and len(cap_by_key) == 1 and "unlabeled" in cap_by_key and jkey == "unlabeled":
                cap_val = cap_by_key["unlabeled"]
                join_status = "single_series"
            else:
                # Strict label join mismatch across pods/instances -> unjoinable!
                join_status = "unjoinable"

        observations.append(_interpret_single_series(
            attempt_id=attempt_id,
            service=service,
            signal_name=signal_name,
            labels=labels,
            join_key=jkey,
            values=win_vals,
            window=window,
            capacity_val=cap_val,
            join_status=join_status,
            logical_signal=logical_signal,
        ))

    return observations


def normalize_tempo_trace(
    *,
    attempt_id: str,
    target_service: str,
    trace_id: Optional[str],
    trace_data: Optional[Dict[str, Any]],
    window: Tuple[str, str],
    incident_timestamp: Optional[str] = None,
) -> NormalizedTraceObservation:
    """Normalizes Tempo trace waterfall payloads into a typed TraceObservation with window enforcement."""
    eff_trace_id = trace_id or f"search:{target_service}"
    obs_id = _make_observation_id("tempo", target_service, "trace", eff_trace_id, window)

    if not trace_data or trace_data.get("status") == "EMPTY":
        return NormalizedTraceObservation(
            observation_id=obs_id,
            attempt_id=attempt_id,
            target_service=target_service,
            trace_id=eff_trace_id,
            requested_window=window,
            status="EMPTY",
            finding=f"No traces found for {target_service} in Tempo (EMPTY)",
        )

    if trace_data.get("status", "SUCCESS") != "SUCCESS":
        return NormalizedTraceObservation(
            observation_id=obs_id,
            attempt_id=attempt_id,
            target_service=target_service,
            trace_id=eff_trace_id,
            requested_window=window,
            status="TOOL_FAILURE",
            finding=f"Tempo tool failure: {trace_data.get('error', 'unknown error')}",
        )

    start_ts, end_ts = parse_window_bounds(window, incident_timestamp)
    trace_ts_raw = trace_data.get("timestamp")
    trace_ts: Optional[float] = None
    spans = list(trace_data.get("spans") or [])
    if trace_ts_raw is not None:
        try:
            trace_ts = float(trace_ts_raw)
        except (ValueError, TypeError):
            trace_ts = None
    elif spans:
        # Derive trace start epoch from span nanoseconds if available
        nanos = [int(s["start_nano"]) for s in spans if s.get("start_nano")]
        if nanos and max(nanos) > 1_000_000_000_000_000_000:
            trace_ts = min(nanos) / 1_000_000_000.0

    if start_ts is not None and end_ts is not None and trace_ts is not None:
        if not (start_ts <= trace_ts <= end_ts):
            return NormalizedTraceObservation(
                observation_id=obs_id,
                attempt_id=attempt_id,
                target_service=target_service,
                trace_id=eff_trace_id,
                trace_timestamp=trace_ts,
                requested_window=window,
                status="STALE_TELEMETRY",
                finding=f"Trace {eff_trace_id} timestamp ({trace_ts:.0f}) falls outside incident window [{start_ts:.0f}, {end_ts:.0f}] (STALE_TELEMETRY)",
            )

    analysis = analyze_trace_spans(spans, eff_trace_id) if spans else {
        "status": trace_data.get("status", "SUCCESS"),
        "spans": [],
        "bottleneck_service": trace_data.get("bottleneck_service"),
        "bottleneck_duration_ms": float(trace_data.get("bottleneck_duration_ms") or 0.0),
    }

    analyzed_spans = list(analysis.get("spans") or spans)
    bottleneck_svc = analysis.get("bottleneck_service") or trace_data.get("bottleneck_service")
    bottleneck_dur = float(analysis.get("bottleneck_duration_ms") or trace_data.get("bottleneck_duration_ms") or 0.0)
    bottleneck_op: Optional[str] = None
    if analyzed_spans and bottleneck_svc:
        bspan = next((s for s in analyzed_spans if s.get("service") == bottleneck_svc), analyzed_spans[0])
        bottleneck_op = bspan.get("name")

    error_spans = [s for s in analyzed_spans if s.get("error")]
    timeout_span = next((s for s in analyzed_spans if s.get("error") == "TimeoutError"), None)

    if timeout_span:
        dep_svc = timeout_span.get("service")
        op_name = timeout_span.get("name")
        dur = float(timeout_span.get("duration_ms", 0.0))
        finding = f"Distributed trace {eff_trace_id} waterfall: TimeoutError in {dep_svc} on {op_name} ({dur:.0f}ms)"
        bottleneck_svc = dep_svc or bottleneck_svc
        bottleneck_op = op_name or bottleneck_op
        bottleneck_dur = dur or bottleneck_dur
    elif analyzed_spans:
        finding = f"Distributed trace {eff_trace_id} waterfall: bottleneck in {bottleneck_svc or 'unknown'} ({bottleneck_dur:.1f}ms exclusive)"
    else:
        finding = f"Distributed trace {eff_trace_id} waterfall: bottleneck in {bottleneck_svc or 'unknown'} ({bottleneck_dur}ms)"

    finding = scrub_credentials(defang_telemetry_tags(finding))
    raw_payload = trace_data.get("formatted") or wrap_telemetry(f"tempo_{target_service}_{eff_trace_id}", str(trace_data))

    return NormalizedTraceObservation(
        observation_id=obs_id,
        attempt_id=attempt_id,
        target_service=target_service,
        trace_id=eff_trace_id,
        trace_timestamp=trace_ts,
        bottleneck_service=bottleneck_svc,
        bottleneck_operation=bottleneck_op,
        bottleneck_duration_ms=bottleneck_dur,
        error_spans=error_spans,
        spans=analyzed_spans,
        requested_window=window,
        status="SUCCESS",
        finding=finding,
        raw_payload=raw_payload,
    )
