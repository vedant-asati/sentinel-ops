"""Unified normalization & label-keyed multi-replica join logic for live and replay telemetry."""

from __future__ import annotations

from datetime import datetime
import hashlib
import math
from typing import Any, Dict, List, Optional, Tuple

from sentinel_ops.mcp.tempo_adapter import analyze_trace_spans
from sentinel_ops.profiles.schema import is_cumulative_counter_metric
from sentinel_ops.security.redact import scrub_credentials
from sentinel_ops.security.sanitizer import defang_telemetry_tags, wrap_telemetry
from sentinel_ops.telemetry.models import CoverageStatus, NormalizedMetricObservation, NormalizedTraceObservation


DEFAULT_JOIN_LABELS: Tuple[str, ...] = ("pod", "instance", "container")

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


def extract_replica_key(
    labels: Optional[Dict[str, Any]],
    replica_labels: Tuple[str, ...] = DEFAULT_JOIN_LABELS,
) -> str:
    """Extracts strict replica identity solely from true replica labels (excluding fleet tags)."""
    if not labels or not isinstance(labels, dict):
        return ""
    allowed = tuple(k for k in replica_labels if k not in ("service", "app")) or DEFAULT_JOIN_LABELS
    selected = sorted(
        (str(k), str(labels[k]))
        for k in allowed
        if k in labels and labels[k] is not None and str(labels[k]) != ""
    )
    return "|".join(f"{k}={v}" for k, v in selected)


def extract_join_key(
    labels: Optional[Dict[str, Any]],
    join_labels: Tuple[str, ...] = DEFAULT_JOIN_LABELS,
) -> str:
    """Computes a canonical series identity key from Prometheus label dictionaries.

    True replica labels (pod/instance/container) take strict precedence and are never
    collapsed onto service/app tags.
    """
    if not labels or not isinstance(labels, dict):
        return "unlabeled"
    cleaned = {
        str(k): str(v)
        for k, v in labels.items()
        if str(k) != "__name__" and v is not None and str(v) != ""
    }
    if not cleaned:
        return "unlabeled"
    rep_key = extract_replica_key(cleaned, join_labels)
    if rep_key:
        return rep_key
    selected = sorted(cleaned.items())
    return "|".join(f"{k}={v}" for k, v in selected)


def _compute_metric_revision(values: List[Any], status: str, coverage: str = "UNKNOWN") -> str:
    canon = "|".join(f"{s[0]}:{s[1]}" if isinstance(s, (list, tuple)) and len(s) >= 2 else str(s) for s in values)
    payload = f"{status}:{coverage}:{canon}"
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()[:12]


def _compute_trace_revision(trace_data: Optional[Dict[str, Any]], status: str) -> str:
    if not trace_data:
        return hashlib.sha1(f"{status}:empty".encode("utf-8")).hexdigest()[:12]
    spans = trace_data.get("spans") or []
    span_sig = "|".join(
        f"{s.get('span_id')}:{s.get('service')}:{s.get('name')}:{s.get('duration_ms')}:{s.get('error')}"
        for s in spans
    )
    payload = (
        f"{status}:{trace_data.get('timestamp')}:{trace_data.get('bottleneck_service')}:"
        f"{trace_data.get('bottleneck_duration_ms')}:{span_sig}"
    )
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()[:12]


def _make_observation_id(
    prefix: str,
    service: str,
    signal: str,
    join_key: str,
    window: Tuple[str, str],
    sample_revision: str = "",
) -> str:
    digest = hashlib.sha256(
        f"{prefix}:{service}:{signal}:{join_key}:{window[0]}:{window[1]}:{sample_revision}".encode("utf-8")
    ).hexdigest()[:24]
    return f"OBS-{prefix}-{digest}"


def observations_conflict(revs: List[NormalizedMetricObservation]) -> bool:
    """Returns True if multiple sample revisions on the same series genuinely contradict each other,
    while allowing normal monotonic Prometheus scrape advancement across CRAG retries.
    """
    if len(revs) <= 1:
        return False
    # Different sample revisions with distinct terminal findings or conflicting deltas/saturation contradict
    statuses = {r.status for r in revs if r.status != "EMPTY"}
    if len(statuses) > 1:
        return True
    # Compare deltas cleanly for counter signals
    deltas = [r.delta for r in revs if r.delta is not None]
    if deltas:
        has_pos = any(d > 0.0 for d in deltas)
        has_nonpos = any(d <= 0.0 for d in deltas)
        if has_pos and has_nonpos:
            return True
    if any(r.counter_reset_detected for r in revs) and any(not r.counter_reset_detected for r in revs):
        return True
    # Compare value revisions at equal sample counts or when values flip materially (>1e-6)
    by_len: Dict[int, List[Optional[float]]] = {}
    for r in revs:
        by_len.setdefault(len(r.sample_timestamps), []).append(r.value)
    for vals in by_len.values():
        non_null = [v for v in vals if v is not None]
        if non_null and (max(non_null) - min(non_null)) > 1e-6:
            return True
    # Also check if overlapping prefixes of timestamps disagree via numeric values flipping across window growth
    vals_all = [r.value for r in revs if r.value is not None]
    ts_lists = [set(r.sample_timestamps) for r in revs if r.sample_timestamps]
    if ts_lists and all(len(s) == len(ts_lists[0]) for s in ts_lists) and len({r.sample_revision for r in revs}) > 1:
        if vals_all and (max(vals_all) - min(vals_all)) > 1e-6:
            return True
    return False


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
    """Parses all sample values, rejecting NaN/Inf/non-numeric strings and sorting chronologically."""
    parsed: List[Tuple[float, float]] = []
    for s in values:
        try:
            ts = float(s[0])
            raw_v = s[1]
            v = float(raw_v) if raw_v is not None else float("nan")
        except (ValueError, TypeError, IndexError):
            return None, f"Invalid or non-finite metric value observed for {service} {signal_name}: '{s}'"
        if not math.isfinite(ts) or not math.isfinite(v) or math.isnan(v):
            return None, f"Invalid or non-finite metric value observed for {service} {signal_name}: '{s[1]}'"
        parsed.append((ts, v))
    parsed.sort(key=lambda pt: pt[0])
    return parsed, None


def _analyze_counter_series(parsed: List[Tuple[float, float]]) -> Tuple[Optional[float], float, bool]:
    """Computes monotonic cumulative delta over the latest post-reset segment after chronological sort."""
    if not parsed:
        return None, 0.0, False
    ordered = sorted(parsed, key=lambda pt: pt[0])
    if len(ordered) == 1:
        return None, ordered[0][1], False

    last_reset_idx = -1
    for idx in range(1, len(ordered)):
        if ordered[idx][1] < ordered[idx - 1][1]:
            last_reset_idx = idx

    if last_reset_idx == -1:
        delta = sum(ordered[i][1] - ordered[i - 1][1] for i in range(1, len(ordered)))
        return delta, ordered[-1][1], False

    post_reset = ordered[last_reset_idx:]
    post_delta = post_reset[-1][1] - post_reset[0][1] if len(post_reset) >= 2 else 0.0
    if len(post_reset) >= 2 and post_delta > 0.0:
        return post_delta, ordered[-1][1], False
    return 0.0, ordered[-1][1], True


def _interpret_single_series(
    *,
    attempt_id: str,
    service: str,
    signal_name: str,
    labels: Dict[str, str],
    join_key: str,
    replica_key: str = "",
    values: List[Any],
    window: Tuple[str, str],
    capacity_val: Optional[float] = None,
    cap_series: Optional[Dict[float, float]] = None,
    join_status: str = "single_series",
    logical_signal: Optional[str] = None,
    promql: str = "",
    truncated: bool = False,
    total_series_count: Optional[int] = None,
    retained_series_count: Optional[int] = None,
    coverage_status: CoverageStatus = "COMPLETE",
) -> NormalizedMetricObservation:
    """Normalizes one Prometheus series (optionally capacity-joined) into a typed observation."""
    canon = logical_signal or signal_name
    unit, kind = SIGNAL_UNITS.get(canon, SIGNAL_UNITS.get(signal_name, ("", "gauge")))
    parsed, err = _validate_finite_samples(values, service, signal_name)
    label_tag = f" [{join_key}]" if join_key != "unlabeled" else ""
    rev = _compute_metric_revision(values, "TOOL_FAILURE" if (err is not None or not parsed) else "SUCCESS", coverage_status)
    obs_id = _make_observation_id("prom", service, signal_name, join_key, window, rev)

    if err is not None or not parsed:
        return NormalizedMetricObservation(
            observation_id=obs_id,
            attempt_id=attempt_id,
            attempt_ids=(attempt_id,),
            sample_revision=rev,
            service=service,
            signal_name=signal_name,
            entity_labels=labels,
            join_key=join_key,
            replica_key=replica_key,
            unit=unit,
            value_kind=kind,  # type: ignore
            join_status=join_status,  # type: ignore
            truncated=truncated,
            total_series_count=total_series_count,
            retained_series_count=retained_series_count,
            coverage_status=coverage_status,
            requested_window=window,
            status="TOOL_FAILURE",
            finding=err or f"No valid samples for {service} {signal_name}",
            raw_payload=str(values),
        )

    # Validate semantic metric meaning BEFORE numeric thresholds for ratio/utilization gauges
    is_ratio_signal = unit == "ratio" or canon in (
        "cpu_utilization",
        "cpu_saturation",
        "memory_utilization",
        "memory_usage",
        "error_rate",
    )
    if is_ratio_signal and is_cumulative_counter_metric(promql, signal_name, labels):
        inv_rev = _compute_metric_revision(values, "INVALID_MEASUREMENT", coverage_status)
        inv_id = _make_observation_id("prom", service, signal_name, join_key, window, inv_rev)
        return NormalizedMetricObservation(
            observation_id=inv_id,
            attempt_id=attempt_id,
            attempt_ids=(attempt_id,),
            sample_revision=inv_rev,
            service=service,
            signal_name=signal_name,
            entity_labels=labels,
            join_key=join_key,
            replica_key=replica_key,
            unit=unit,
            value_kind=kind,  # type: ignore
            join_status=join_status,  # type: ignore
            truncated=truncated,
            total_series_count=total_series_count,
            retained_series_count=retained_series_count,
            coverage_status=coverage_status,
            sample_timestamps=tuple(ts for ts, _ in parsed),
            requested_window=window,
            status="INVALID_MEASUREMENT",
            finding=(
                f"Invalid measurement for {service} {signal_name}{label_tag}: cumulative counter cannot represent "
                f"ratio utilization without rate() normalization and declared capacity"
            ),
            raw_payload=wrap_telemetry(f"prom_{service}_{signal_name}", str(values)),
        )

    timestamps = tuple(ts for ts, _ in parsed)
    val = parsed[-1][1]
    if is_ratio_signal and canon not in ("db_pool_active", "pool_active") and (val < 0.0 or val > 1.0):
        inv_rev = _compute_metric_revision(values, "INVALID_MEASUREMENT", coverage_status)
        inv_id = _make_observation_id("prom", service, signal_name, join_key, window, inv_rev)
        return NormalizedMetricObservation(
            observation_id=inv_id,
            attempt_id=attempt_id,
            attempt_ids=(attempt_id,),
            sample_revision=inv_rev,
            service=service,
            signal_name=signal_name,
            entity_labels=labels,
            join_key=join_key,
            replica_key=replica_key,
            unit=unit,
            value_kind=kind,  # type: ignore
            join_status=join_status,  # type: ignore
            truncated=truncated,
            total_series_count=total_series_count,
            retained_series_count=retained_series_count,
            coverage_status=coverage_status,
            sample_timestamps=timestamps,
            requested_window=window,
            status="INVALID_MEASUREMENT",
            finding=(
                f"Invalid measurement for {service} {signal_name}{label_tag}: observed value {val} "
                f"exceeds valid unit='{unit or 'ratio'}' range [0.0, 1.0]"
            ),
            raw_payload=wrap_telemetry(f"prom_{service}_{signal_name}", str(values)),
        )

    delta: Optional[float] = None
    numerator: Optional[float] = None
    denominator: Optional[float] = None
    reset_detected = False

    if canon in ("db_pool_active", "pool_active"):
        eff_cap_val = capacity_val
        eff_num_val = val
        # Enforce exact evaluation timestamp alignment when capacity series samples are available
        if cap_series is not None and join_status not in ("unjoinable", "missing_denominator"):
            num_by_ts = {ts: v for ts, v in parsed}
            common_ts = sorted(set(num_by_ts) & set(cap_series))
            if not common_ts:
                join_status = "unjoinable"
                eff_cap_val = None
            else:
                eval_ts = common_ts[-1]
                eff_num_val = num_by_ts[eval_ts]
                eff_cap_val = cap_series[eval_ts]

        numerator = eff_num_val
        denominator = eff_cap_val
        if join_status in ("unjoinable", "missing_denominator"):
            finding = (
                f"{signal_name} observed at {eff_num_val:.1f}{label_tag} "
                f"({join_status}: capacity denominator unjoinable, timestamp-misaligned, or missing; cannot determine saturation)"
            )
            computed_val = None
        elif eff_cap_val is not None and eff_cap_val > 0:
            occ = eff_num_val / eff_cap_val
            computed_val = occ
            if occ >= 0.95:
                finding = (
                    f"{'payment_' if signal_name == 'db_pool_active' else ''}{signal_name} saturated at {eff_num_val:.1f} / {eff_cap_val:.1f} "
                    f"({occ * 100:.0f}% capacity exhausted){label_tag}"
                )
            else:
                finding = (
                    f"{'payment_' if signal_name == 'db_pool_active' else ''}{signal_name} normal at {eff_num_val:.1f} / {eff_cap_val:.1f} "
                    f"({occ * 100:.0f}% capacity, healthy){label_tag}"
                )
        else:
            computed_val = None
            finding = f"{signal_name} observed at {eff_num_val:.1f}{label_tag} (capacity unrecorded; cannot determine saturation)"
        rev = _compute_metric_revision(values, f"SUCCESS:{join_status}:{eff_cap_val}", coverage_status)
        obs_id = _make_observation_id("prom", service, signal_name, join_key, window, rev)
        return NormalizedMetricObservation(
            observation_id=obs_id,
            attempt_id=attempt_id,
            attempt_ids=(attempt_id,),
            sample_revision=rev,
            service=service,
            signal_name=signal_name,
            entity_labels=labels,
            join_key=join_key,
            replica_key=replica_key,
            unit=unit,
            value_kind="ratio",
            value=computed_val,
            numerator=numerator,
            denominator=denominator,
            join_status=join_status,  # type: ignore
            truncated=truncated,
            total_series_count=total_series_count,
            retained_series_count=retained_series_count,
            coverage_status=coverage_status,
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
            attempt_ids=(attempt_id,),
            sample_revision=rev,
            service=service,
            signal_name=signal_name,
            entity_labels=labels,
            join_key=join_key,
            replica_key=replica_key,
            unit=unit,
            value_kind="counter_delta",
            value=end_val,
            delta=delta,
            counter_reset_detected=reset_detected,
            join_status="single_series",
            truncated=truncated,
            total_series_count=total_series_count,
            retained_series_count=retained_series_count,
            coverage_status=coverage_status,
            sample_timestamps=timestamps,
            requested_window=window,
            status="SUCCESS",
            finding=finding,
            raw_payload=wrap_telemetry(f"prom_{service}_{signal_name}", str(values)),
        )

    if signal_name == "container_restarts":
        delta, end_val, reset_detected = _analyze_counter_series(parsed)
        in_win_delta = delta if delta is not None else 0.0
        finding = (
            f"{service} container_restarts increased by +{in_win_delta:.0f} restarts (to {end_val:.0f}){label_tag}"
            if len(parsed) >= 2 and in_win_delta > 0.0
            else f"{service} container_restarts flat at {end_val:.0f}{label_tag}"
        )
        return NormalizedMetricObservation(
            observation_id=obs_id,
            attempt_id=attempt_id,
            attempt_ids=(attempt_id,),
            sample_revision=rev,
            service=service,
            signal_name=signal_name,
            entity_labels=labels,
            join_key=join_key,
            replica_key=replica_key,
            unit=unit,
            value_kind="counter_delta",
            value=end_val,
            delta=delta,
            counter_reset_detected=reset_detected,
            join_status="single_series",
            truncated=truncated,
            total_series_count=total_series_count,
            retained_series_count=retained_series_count,
            coverage_status=coverage_status,
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
    elif signal_name == "error_rate":
        finding = (
            f"{service} error_rate spiked critically to {val * 100:.0f}%{label_tag}"
            if val >= 0.50
            else f"{service} error_rate normal at {val * 100:.0f}%{label_tag}"
        )
    else:
        finding = f"{service} {signal_name}{label_tag} observed at {val}"

    return NormalizedMetricObservation(
        observation_id=obs_id,
        attempt_id=attempt_id,
        attempt_ids=(attempt_id,),
        sample_revision=rev,
        service=service,
        signal_name=signal_name,
        entity_labels=labels,
        join_key=join_key,
        replica_key=replica_key,
        unit=unit,
        value_kind=kind,  # type: ignore
        value=val,
        join_status="single_series",
        truncated=truncated,
        total_series_count=total_series_count,
        retained_series_count=retained_series_count,
        coverage_status=coverage_status,
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
    promql: str = "",
    max_series: int = 5,
) -> List[NormalizedMetricObservation]:
    """Normalizes Prometheus live or replay payload across all returned replica series."""
    start_ts, end_ts = parse_window_bounds(window, incident_timestamp)
    raw_status = response.get("status", "EMPTY")
    eff_promql = promql or str(response.get("promql") or "")

    if start_ts is not None and end_ts is not None and start_ts > end_ts:
        rev = _compute_metric_revision([], "TOOL_FAILURE", "UNKNOWN")
        return [NormalizedMetricObservation(
            observation_id=_make_observation_id("prom", service, signal_name, "invwin", window, rev),
            attempt_id=attempt_id,
            attempt_ids=(attempt_id,),
            sample_revision=rev,
            service=service,
            signal_name=signal_name,
            coverage_status="UNKNOWN",
            requested_window=window,
            status="TOOL_FAILURE",
            finding=f"Invalid inverted query window for {service} {signal_name}: start '{window[0]}' exceeds end '{window[1]}'",
        )]

    if raw_status == "EMPTY":
        rev = _compute_metric_revision([], "EMPTY", "EMPTY")
        return [NormalizedMetricObservation(
            observation_id=_make_observation_id("prom", service, signal_name, "empty", window, rev),
            attempt_id=attempt_id,
            attempt_ids=(attempt_id,),
            sample_revision=rev,
            service=service,
            signal_name=signal_name,
            coverage_status="EMPTY",
            requested_window=window,
            status="EMPTY",
            finding=response.get("finding") or f"Prometheus query returned empty result for {service} {signal_name}",
        )]

    if raw_status != "SUCCESS":
        rev = _compute_metric_revision([], "TOOL_FAILURE", "UNKNOWN")
        return [NormalizedMetricObservation(
            observation_id=_make_observation_id("prom", service, signal_name, "err", window, rev),
            attempt_id=attempt_id,
            attempt_ids=(attempt_id,),
            sample_revision=rev,
            service=service,
            signal_name=signal_name,
            coverage_status="UNKNOWN",
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
        rev = _compute_metric_revision([], "EMPTY", "EMPTY")
        return [NormalizedMetricObservation(
            observation_id=_make_observation_id("prom", service, signal_name, "empty", window, rev),
            attempt_id=attempt_id,
            attempt_ids=(attempt_id,),
            sample_revision=rev,
            service=service,
            signal_name=signal_name,
            coverage_status="EMPTY",
            requested_window=window,
            status="EMPTY",
            finding=f"Prometheus query returned empty series list for {service} {signal_name}",
        )]

    # Track true total vs retained series across both live adapter metadata and replay lists
    adapter_total = response.get("total_series_count")
    total_series_count = int(adapter_total) if adapter_total is not None else len(raw_series_list)
    if len(raw_series_list) > max_series:
        raw_series_list = raw_series_list[:max_series]
    retained_series_count = len(raw_series_list)
    truncated = bool(response.get("truncated")) or (total_series_count > retained_series_count)
    coverage_status: CoverageStatus = "PARTIAL" if truncated else "COMPLETE"

    # Build strict replica-keyed capacity lookup preserving exact timestamps per replica
    canon = logical_signal or signal_name
    cap_by_key: Dict[str, Dict[float, float]] = {}
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
                ts_map: Dict[float, float] = {}
                for pt in c_win:
                    try:
                        ts_f = float(pt[0])
                        c_f = float(pt[1])
                        if math.isfinite(c_f):
                            ts_map[ts_f] = c_f
                    except (ValueError, TypeError, IndexError):
                        pass
                if ts_map:
                    cap_by_key[c_key] = ts_map
                    cap_has_entries = True

    observations: List[NormalizedMetricObservation] = []
    for entry in raw_series_list:
        labels = {str(k): str(v) for k, v in (entry.get("metric") or {}).items()}
        jkey = extract_join_key(labels, join_labels)
        rkey = extract_replica_key(labels, join_labels)
        vals = entry.get("values") or ([entry["value"]] if "value" in entry else [])
        win_vals, stale_only = filter_samples_to_window(vals, start_ts, end_ts)

        if stale_only:
            rev = _compute_metric_revision(vals, "STALE_TELEMETRY", coverage_status)
            observations.append(NormalizedMetricObservation(
                observation_id=_make_observation_id("prom", service, signal_name, jkey, window, rev),
                attempt_id=attempt_id,
                attempt_ids=(attempt_id,),
                sample_revision=rev,
                service=service,
                signal_name=signal_name,
                entity_labels=labels,
                join_key=jkey,
                replica_key=rkey,
                truncated=truncated,
                total_series_count=total_series_count,
                retained_series_count=retained_series_count,
                coverage_status=coverage_status,
                requested_window=window,
                status="STALE_TELEMETRY",
                finding=f"Metric '{signal_name}' for '{service}' [{jkey}] contains only samples outside incident window (STALE_TELEMETRY)",
            ))
            continue

        cap_ts_map: Optional[Dict[float, float]] = None
        cap_latest: Optional[float] = None
        join_status = "single_series"
        if canon in ("db_pool_active", "pool_active"):
            if not cap_has_entries:
                join_status = "missing_denominator"
            elif jkey in cap_by_key:
                cap_ts_map = cap_by_key[jkey]
                cap_latest = cap_ts_map[max(cap_ts_map)]
                join_status = "single_series" if jkey == "unlabeled" and len(raw_series_list) == 1 and len(cap_by_key) == 1 and not rkey else "label_joined"
            else:
                # Strict label join mismatch across pods/instances -> unjoinable!
                join_status = "unjoinable"

        observations.append(_interpret_single_series(
            attempt_id=attempt_id,
            service=service,
            signal_name=signal_name,
            labels=labels,
            join_key=jkey,
            replica_key=rkey,
            values=win_vals,
            window=window,
            capacity_val=cap_latest,
            cap_series=cap_ts_map,
            join_status=join_status,
            logical_signal=logical_signal,
            promql=eff_promql,
            truncated=truncated,
            total_series_count=total_series_count,
            retained_series_count=retained_series_count,
            coverage_status=coverage_status,
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
    raw_status = (trace_data or {}).get("status", "EMPTY") if trace_data else "EMPTY"
    rev = _compute_trace_revision(trace_data, raw_status)
    obs_id = _make_observation_id("tempo", target_service, "trace", eff_trace_id, window, rev)

    if not trace_data or raw_status == "EMPTY":
        return NormalizedTraceObservation(
            observation_id=obs_id,
            attempt_id=attempt_id,
            attempt_ids=(attempt_id,),
            sample_revision=rev,
            target_service=target_service,
            trace_id=eff_trace_id,
            requested_window=window,
            status="EMPTY",
            finding=f"No traces found for {target_service} in Tempo (EMPTY)",
        )

    if raw_status != "SUCCESS":
        return NormalizedTraceObservation(
            observation_id=obs_id,
            attempt_id=attempt_id,
            attempt_ids=(attempt_id,),
            sample_revision=rev,
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
        # Derive trace start epoch safely from span nanoseconds if available
        nanos = []
        for s in spans:
            if s.get("start_nano") is not None:
                try:
                    nanos.append(int(s["start_nano"]))
                except (ValueError, TypeError):
                    continue
        if nanos and max(nanos) > 1_000_000_000_000_000_000:
            trace_ts = min(nanos) / 1_000_000_000.0

    if start_ts is not None and end_ts is not None and trace_ts is not None:
        if not (start_ts <= trace_ts <= end_ts):
            return NormalizedTraceObservation(
                observation_id=obs_id,
                attempt_id=attempt_id,
                attempt_ids=(attempt_id,),
                sample_revision=rev,
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
    timeout_span = next((s for s in analyzed_spans if s.get("error") in ("TimeoutError", "DEADLINE_EXCEEDED")), None)

    if timeout_span:
        dep_svc = timeout_span.get("service")
        op_name = timeout_span.get("name")
        dur = float(timeout_span.get("duration_ms", 0.0))
        err_label = timeout_span.get("error") or "TimeoutError"
        finding = f"Distributed trace {eff_trace_id} waterfall: {err_label} in {dep_svc} on {op_name} ({dur:.0f}ms)"
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
        attempt_ids=(attempt_id,),
        sample_revision=rev,
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
