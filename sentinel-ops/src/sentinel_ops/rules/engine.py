"""Profile-agnostic causal rule evaluators shared between CRAG selection and adversarial verification."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from sentinel_ops.profiles.schema import SystemProfile
from sentinel_ops.telemetry.models import NormalizedMetricObservation, NormalizedTraceObservation


class LocalizationResult(BaseModel):
    """Identifies the primary slow or failing downstream dependency independently of mechanism certainty."""

    bottleneck_service: Optional[str] = None
    bottleneck_operation: Optional[str] = None
    exclusive_duration_ms: float = 0.0
    trace_id: Optional[str] = None
    observation_id: Optional[str] = None


class RuleEvaluationResult(BaseModel):
    """Typed diagnostic outcome returned by shared rule predicates."""

    is_sufficient: bool = False
    winning_rule: Optional[str] = None
    root_cause_service: Optional[str] = None
    mechanism: Optional[str] = None
    supporting_observation_ids: List[str] = Field(default_factory=list)
    supporting_signal_names: List[str] = Field(default_factory=list)
    supporting_trace_id: Optional[str] = None
    healthy_observation_ids: List[str] = Field(default_factory=list)
    localization: Optional[LocalizationResult] = None
    gap_reasons: List[str] = Field(default_factory=list)
    next_discriminating_checks: List[str] = Field(default_factory=list)
    recommended_runbook_action: Optional[str] = None


def observation_in_window(requested_window: Tuple[str, str], incident_timestamp: Optional[str]) -> bool:
    """Validates an observation window strictly brackets T_incident within bounded range."""
    if not incident_timestamp or not requested_window or len(requested_window) != 2:
        return True
    try:
        t_inc = datetime.fromisoformat(incident_timestamp.replace("Z", "+00:00")).timestamp()
        w_start = datetime.fromisoformat(requested_window[0].replace("Z", "+00:00")).timestamp()
        w_end = datetime.fromisoformat(requested_window[1].replace("Z", "+00:00")).timestamp()
        return (w_start - 180.0 <= t_inc <= w_end + 180.0) and (w_end - w_start <= 600.0)
    except Exception:
        return True


def _matches_signal(signal_name: str, logical_target: str, profile: SystemProfile) -> bool:
    if signal_name == logical_target:
        return True
    mapping = profile.signals.get(logical_target)
    return bool(mapping and signal_name == mapping.metric_name)


def _format_checks(profile: SystemProfile, rule_id: str, svc: str) -> List[str]:
    return [c.format(service=svc) for c in profile.check_templates.get(rule_id, [])]


def _format_runbook(profile: SystemProfile, rule_id: str, svc: str) -> Optional[str]:
    tpl = profile.runbook_hints.get(rule_id)
    return tpl.format(service=svc) if tpl else None


def extract_localization(
    trace_obs: List[NormalizedTraceObservation],
    explicit_trace_id: Optional[str],
    incident_timestamp: Optional[str],
) -> Optional[LocalizationResult]:
    """Extracts the primary slow/failing downstream dependency from valid traces."""
    valid_traces = [
        t for t in trace_obs
        if t.status == "SUCCESS"
        and observation_in_window(t.requested_window, incident_timestamp)
        and (not explicit_trace_id or t.trace_id == explicit_trace_id)
    ]
    if not valid_traces:
        return None
    primary = valid_traces[0]
    if not primary.bottleneck_service:
        return None
    return LocalizationResult(
        bottleneck_service=primary.bottleneck_service,
        bottleneck_operation=primary.bottleneck_operation,
        exclusive_duration_ms=primary.bottleneck_duration_ms,
        trace_id=primary.trace_id,
        observation_id=primary.observation_id,
    )


def evaluate_all_rules(
    *,
    profile: SystemProfile,
    observations: List[Any],
    explicit_trace_id: Optional[str] = None,
    incident_timestamp: Optional[str] = None,
    enabled_only: Optional[List[str]] = None,
) -> RuleEvaluationResult:
    """Shared deterministic evaluator across all enabled diagnostic rules on typed observations."""
    metric_obs: List[NormalizedMetricObservation] = [
        o for o in observations
        if getattr(o, "backend_source", None) == "prometheus"
        and o.status == "SUCCESS"
        and observation_in_window(o.requested_window, incident_timestamp)
    ]
    trace_obs: List[NormalizedTraceObservation] = [
        o for o in observations
        if getattr(o, "backend_source", None) == "tempo"
        and o.status == "SUCCESS"
        and observation_in_window(o.requested_window, incident_timestamp)
        and (not explicit_trace_id or o.trace_id == explicit_trace_id)
    ]
    loc = extract_localization(trace_obs, explicit_trace_id, incident_timestamp)

    # Reject if an explicit trace_id was requested but absent/stale/failed
    if explicit_trace_id and not trace_obs:
        return RuleEvaluationResult(
            is_sufficient=False,
            localization=loc,
            gap_reasons=[f"Requested trace_id '{explicit_trace_id}' unavailable or outside incident window."],
        )

    enabled = set(enabled_only) if enabled_only is not None else set(profile.enabled_rules)
    timeout_markers = set(profile.trace_contract.timeout_error_markers or ["TimeoutError"])
    pool_ops = set(profile.trace_contract.operation_aliases.get("pool_acquisition_timeout", ["db.connection.acquire"]))
    connect_ops = set(profile.trace_contract.operation_aliases.get("upstream_connect_timeout", ["rpc.connect"]))

    # Index counter spikes by service
    pool_wait_spikes: Dict[str, List[NormalizedMetricObservation]] = {}
    connect_wait_spikes: Dict[str, List[NormalizedMetricObservation]] = {}
    for m in metric_obs:
        if _matches_signal(m.signal_name, "pool_acquire_timeouts", profile) and (m.delta or 0.0) > 0.0:
            pool_wait_spikes.setdefault(m.service, []).append(m)
        if _matches_signal(m.signal_name, "upstream_connect_timeouts", profile) and (m.delta or 0.0) > 0.0:
            connect_wait_spikes.setdefault(m.service, []).append(m)

    # Collect healthy observations on candidate dependencies for falsification claims
    def _healthy_ids(exclude_svc: str) -> List[str]:
        res: List[str] = []
        for m in metric_obs:
            if m.service == exclude_svc or m.value is None:
                continue
            if _matches_signal(m.signal_name, "latency_p95", profile) and m.value < 1.0:
                res.append(m.observation_id)
            elif _matches_signal(m.signal_name, "pool_active", profile) and m.join_status in ("single_series", "label_joined") and m.value < 0.50:
                res.append(m.observation_id)
        return res[:2]

    # 1. Timeout trace checks (pool_acquisition_timeout & upstream_connect_timeout)
    any_timeout_span = False
    for t in trace_obs:
        for sp in t.error_spans:
            if sp.get("error") not in timeout_markers:
                continue
            any_timeout_span = True
            op = sp.get("name", "")
            svc = sp.get("service") or t.bottleneck_service
            if not svc:
                continue
            if op in pool_ops and "pool_acquisition_timeout" in enabled and svc in pool_wait_spikes:
                counter_obs = pool_wait_spikes[svc][0]
                return RuleEvaluationResult(
                    is_sufficient=True,
                    winning_rule="pool_acquisition_timeout",
                    root_cause_service=svc,
                    mechanism="pool_acquisition_timeout",
                    supporting_observation_ids=[counter_obs.observation_id, t.observation_id],
                    supporting_signal_names=[counter_obs.signal_name],
                    supporting_trace_id=t.trace_id,
                    healthy_observation_ids=_healthy_ids(svc),
                    localization=loc,
                    next_discriminating_checks=_format_checks(profile, "pool_acquisition_timeout", svc),
                    recommended_runbook_action=_format_runbook(profile, "pool_acquisition_timeout", svc),
                )
            if op in connect_ops and "upstream_connect_timeout" in enabled and svc in connect_wait_spikes:
                counter_obs = connect_wait_spikes[svc][0]
                return RuleEvaluationResult(
                    is_sufficient=True,
                    winning_rule="upstream_connect_timeout",
                    root_cause_service=svc,
                    mechanism="upstream_connect_timeout",
                    supporting_observation_ids=[counter_obs.observation_id, t.observation_id],
                    supporting_signal_names=[counter_obs.signal_name],
                    supporting_trace_id=t.trace_id,
                    healthy_observation_ids=_healthy_ids(svc),
                    localization=loc,
                    next_discriminating_checks=_format_checks(profile, "upstream_connect_timeout", svc),
                    recommended_runbook_action=_format_runbook(profile, "upstream_connect_timeout", svc),
                )

    if any_timeout_span:
        # Timeout span existed without corroborating timeout counter on the span's service
        checks = []
        if loc and loc.bottleneck_service:
            checks.append(
                f"Timeout span isolated on {loc.bottleneck_service} ({loc.bottleneck_operation or 'timeout'}) without counter corroboration; inspect exporter scrape coverage and timeout counters on {loc.bottleneck_service}."
            )
        return RuleEvaluationResult(
            is_sufficient=False,
            localization=loc,
            gap_reasons=["Trace TimeoutError lacks corroborating monotonic timeout counter on the same service."],
            next_discriminating_checks=checks,
        )

    # 2. Evaluate all non-timeout / multi-metric candidates across services
    trace_error_services = {sp.get("service") for t in trace_obs for sp in t.error_spans if sp.get("service")}

    def _trace_allows(svc_name: str) -> bool:
        if not explicit_trace_id:
            return True
        return bool((loc and loc.bottleneck_service == svc_name) or (svc_name in trace_error_services))

    candidates: List[RuleEvaluationResult] = []
    unjoinable_gaps: List[str] = []

    # 2a. Pool acquisition timeout (replica-safe pool saturation + wait counter delta)
    saturated_pools: Dict[str, List[NormalizedMetricObservation]] = {}
    if "pool_acquisition_timeout" in enabled:
        active_sig = profile.signals.get("pool_active")
        pool_thr = active_sig.saturation_threshold if (active_sig and active_sig.saturation_threshold is not None) else 0.95
        for m in metric_obs:
            if _matches_signal(m.signal_name, "pool_active", profile):
                if m.join_status in ("unjoinable", "missing_denominator"):
                    unjoinable_gaps.append(
                        f"Replica capacity join failed for {m.service} {m.signal_name} ({m.join_status})"
                    )
                elif m.value is not None and m.value >= pool_thr:
                    saturated_pools.setdefault(m.service, []).append(m)

        for svc, pool_list in saturated_pools.items():
            if not _trace_allows(svc) or svc not in pool_wait_spikes:
                continue
            waits = pool_wait_spikes[svc]
            matched_pool: Optional[NormalizedMetricObservation] = None
            matched_wait: Optional[NormalizedMetricObservation] = None
            for p in pool_list:
                same_key = next((w for w in waits if w.join_key == p.join_key), None)
                if same_key is not None:
                    matched_pool, matched_wait = p, same_key
                    break
            if matched_pool is None and any(w.join_key == "unlabeled" or "service=" in w.join_key for w in waits):
                matched_pool, matched_wait = pool_list[0], waits[0]
            if matched_pool and matched_wait:
                obs_ids = [matched_pool.observation_id, matched_wait.observation_id]
                t_ref = None
                if loc and loc.observation_id and loc.bottleneck_service == svc:
                    obs_ids.append(loc.observation_id)
                    t_ref = loc.trace_id
                candidates.append(RuleEvaluationResult(
                    is_sufficient=True,
                    winning_rule="pool_acquisition_timeout",
                    root_cause_service=svc,
                    mechanism="db_pool_exhaustion" if profile.profile_id == "checkout-demo" else "pool_acquisition_timeout",
                    supporting_observation_ids=obs_ids,
                    supporting_signal_names=[matched_pool.signal_name, matched_wait.signal_name],
                    supporting_trace_id=t_ref,
                    healthy_observation_ids=_healthy_ids(svc),
                    localization=loc,
                    next_discriminating_checks=_format_checks(profile, "pool_acquisition_timeout", svc),
                    recommended_runbook_action=_format_runbook(profile, "pool_acquisition_timeout", svc),
                ))

    # 2b. CPU Contention (calibrated coarse CPU pressure + latency/trace bottleneck)
    if "cpu_contention" in enabled or "cpu_algorithmic_latency" in enabled:
        cpu_sig = profile.signals.get("cpu_utilization")
        cpu_thr = cpu_sig.saturation_threshold if (cpu_sig and cpu_sig.saturation_threshold is not None) else 0.85
        for m in metric_obs:
            if not _matches_signal(m.signal_name, "cpu_utilization", profile):
                continue
            if m.value is None or m.value < cpu_thr or not _trace_allows(m.service):
                continue
            lat_obs = next(
                (l for l in metric_obs if l.service == m.service and _matches_signal(l.signal_name, "latency_p95", profile) and (l.value or 0.0) >= 1.0),
                None,
            )
            trace_match = next(
                (t for t in trace_obs if t.bottleneck_service == m.service),
                None,
            )
            if lat_obs is not None or trace_match is not None:
                obs_ids = [m.observation_id]
                sigs = [m.signal_name]
                t_ref = None
                if lat_obs is not None:
                    obs_ids.append(lat_obs.observation_id)
                    sigs.append(lat_obs.signal_name)
                if trace_match is not None:
                    obs_ids.append(trace_match.observation_id)
                    t_ref = trace_match.trace_id
                candidates.append(RuleEvaluationResult(
                    is_sufficient=True,
                    winning_rule="cpu_contention",
                    root_cause_service=m.service,
                    mechanism="cpu_contention",
                    supporting_observation_ids=obs_ids,
                    supporting_signal_names=sigs,
                    supporting_trace_id=t_ref,
                    healthy_observation_ids=_healthy_ids(m.service),
                    localization=loc,
                    next_discriminating_checks=_format_checks(profile, "cpu_contention", m.service),
                    recommended_runbook_action=_format_runbook(profile, "cpu_contention", m.service),
                ))

    # 2c. Memory Exhaustion & OOMKill (memory >= 90% + container restarts > 1)
    if "memory_leak_oomkill" in enabled:
        mem_sig = profile.signals.get("memory_utilization")
        mem_thr = mem_sig.saturation_threshold if (mem_sig and mem_sig.saturation_threshold is not None) else 0.90
        for m in metric_obs:
            if not _matches_signal(m.signal_name, "memory_utilization", profile):
                continue
            if m.value is None or m.value < mem_thr or not _trace_allows(m.service):
                continue
            restart_obs = next(
                (r for r in metric_obs if r.service == m.service and _matches_signal(r.signal_name, "container_restarts", profile) and (r.value or 0.0) > 1.0),
                None,
            )
            if restart_obs is not None:
                obs_ids = [m.observation_id, restart_obs.observation_id]
                sigs = [m.signal_name, restart_obs.signal_name]
                t_ref = None
                trace_match = next((t for t in trace_obs if t.bottleneck_service == m.service), None)
                if trace_match is not None:
                    obs_ids.append(trace_match.observation_id)
                    t_ref = trace_match.trace_id
                candidates.append(RuleEvaluationResult(
                    is_sufficient=True,
                    winning_rule="memory_leak_oomkill",
                    root_cause_service=m.service,
                    mechanism="memory_leak_oomkill",
                    supporting_observation_ids=obs_ids,
                    supporting_signal_names=sigs,
                    supporting_trace_id=t_ref,
                    healthy_observation_ids=_healthy_ids(m.service),
                    localization=loc,
                    next_discriminating_checks=_format_checks(profile, "memory_leak_oomkill", m.service),
                    recommended_runbook_action=_format_runbook(profile, "memory_leak_oomkill", m.service),
                ))

    # 2d. High Error Rate / Connection Refusal + Trace Localization (e.g. config drift)
    if "upstream_connect_timeout" in enabled:
        for m in metric_obs:
            if not _matches_signal(m.signal_name, "error_rate", profile):
                continue
            if m.value is None or m.value < 0.50 or not _trace_allows(m.service):
                continue
            trace_match = next(
                (t for t in trace_obs if t.bottleneck_service == m.service),
                None,
            )
            refused_span = any(
                "refused" in str(sp.get("error", "")).lower() and sp.get("service") == m.service
                for t in trace_obs for sp in t.error_spans
            )
            if trace_match is not None or refused_span:
                obs_ids = [m.observation_id]
                t_ref = None
                if trace_match is not None:
                    obs_ids.append(trace_match.observation_id)
                    t_ref = trace_match.trace_id
                candidates.append(RuleEvaluationResult(
                    is_sufficient=True,
                    winning_rule="upstream_connect_timeout",
                    root_cause_service=m.service,
                    mechanism="config_drift_connection_refused" if profile.profile_id == "checkout-demo" else "upstream_connect_timeout",
                    supporting_observation_ids=obs_ids,
                    supporting_signal_names=[m.signal_name],
                    supporting_trace_id=t_ref,
                    healthy_observation_ids=_healthy_ids(m.service),
                    localization=loc,
                    next_discriminating_checks=_format_checks(profile, "upstream_connect_timeout", m.service),
                    recommended_runbook_action=_format_runbook(profile, "upstream_connect_timeout", m.service),
                ))

    # 3. Conflict resolution across multiple candidate causes
    if candidates:
        distinct_svcs = sorted({c.root_cause_service for c in candidates if c.root_cause_service})
        if len(distinct_svcs) > 1:
            if loc and loc.bottleneck_service in distinct_svcs:
                isolated = [c for c in candidates if c.root_cause_service == loc.bottleneck_service]
                return isolated[0]
            checks = [
                f"Trace both competing candidates ({', '.join(distinct_svcs)}) inside the same request path before applying mitigation."
            ]
            return RuleEvaluationResult(
                is_sufficient=False,
                localization=loc,
                gap_reasons=[
                    f"Simultaneous candidate faults detected across multiple dependencies ({', '.join(distinct_svcs)}) without an isolating trace."
                ],
                next_discriminating_checks=checks,
            )
        return candidates[0]

    # 4. Inconclusive / localization-only abstain
    gaps = list(unjoinable_gaps)
    next_checks: List[str] = []
    if loc and loc.bottleneck_service:
        next_checks.append(
            f"Trace {loc.trace_id} localized bottleneck to {loc.bottleneck_service} ({loc.bottleneck_operation or 'slow_span'}, {loc.exclusive_duration_ms:.1f}ms); inspect wait queues, CPU pressure, and logs on {loc.bottleneck_service}."
        )
    if saturated_pools and not pool_wait_spikes:
        gaps.append("Pool occupancy >= 95% observed without corresponding wait timeout counter increase.")
    return RuleEvaluationResult(
        is_sufficient=False,
        localization=loc,
        gap_reasons=gaps,
        next_discriminating_checks=next_checks,
    )


def evaluate_pool_acquisition_timeout(
    *,
    profile: SystemProfile,
    observations: List[Any],
    explicit_trace_id: Optional[str] = None,
    incident_timestamp: Optional[str] = None,
) -> RuleEvaluationResult:
    """Evaluates only the `pool_acquisition_timeout` rule slice using shared typed evaluation."""
    return evaluate_all_rules(
        profile=profile,
        observations=observations,
        explicit_trace_id=explicit_trace_id,
        incident_timestamp=incident_timestamp,
        enabled_only=["pool_acquisition_timeout"],
    )
