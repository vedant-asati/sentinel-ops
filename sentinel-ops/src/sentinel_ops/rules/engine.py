"""Profile-agnostic causal rule evaluators shared between CRAG selection and adversarial verification."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional, Set, Tuple
from pydantic import BaseModel, Field

from sentinel_ops.core.config import settings
from sentinel_ops.profiles.schema import SystemProfile, normalize_duration_to_seconds
from sentinel_ops.telemetry.models import CoverageStatus, NormalizedMetricObservation, NormalizedTraceObservation
from sentinel_ops.telemetry.normalize import observations_conflict


class LocalizationResult(BaseModel):
    """Identifies the primary slow or failing downstream dependency independently of mechanism certainty."""

    bottleneck_service: Optional[str] = None
    bottleneck_operation: Optional[str] = None
    bottleneck_span_id: Optional[str] = None
    exclusive_duration_ms: float = 0.0
    trace_id: Optional[str] = None
    observation_id: Optional[str] = None


class RuleEvaluationResult(BaseModel):
    """Typed diagnostic outcome returned by shared rule predicates."""

    is_sufficient: bool = False
    winning_rule: Optional[str] = None
    root_cause_service: Optional[str] = None
    mechanism: Optional[str] = None
    claim_scope: Optional[Literal["affected_request", "replica_correlated", "service_fleet"]] = None
    claim_subject: Optional[str] = None
    supporting_observation_ids: List[str] = Field(default_factory=list)
    supporting_signal_names: List[str] = Field(default_factory=list)
    supporting_trace_id: Optional[str] = None
    supporting_span_id: Optional[str] = None
    healthy_observation_ids: List[str] = Field(default_factory=list)
    localization: Optional[LocalizationResult] = None
    coverage_status: CoverageStatus = "UNKNOWN"
    truncated_series: List[str] = Field(default_factory=list)
    invalid_measurements: List[str] = Field(default_factory=list)
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
    bspan_id: Optional[str] = None
    if primary.error_spans:
        match_err = next((s for s in primary.error_spans if s.get("service") == primary.bottleneck_service), primary.error_spans[0])
        bspan_id = match_err.get("span_id")
    elif primary.spans:
        match_sp = next((s for s in primary.spans if s.get("service") == primary.bottleneck_service), None)
        if match_sp:
            bspan_id = match_sp.get("span_id")
    return LocalizationResult(
        bottleneck_service=primary.bottleneck_service,
        bottleneck_operation=primary.bottleneck_operation,
        bottleneck_span_id=str(bspan_id) if bspan_id else None,
        exclusive_duration_ms=primary.bottleneck_duration_ms,
        trace_id=primary.trace_id,
        observation_id=primary.observation_id,
    )


def _fleet_scope_tags(join_key: str) -> Tuple[str, ...]:
    if not join_key or join_key == "unlabeled":
        return ()
    benign = {"job", "app", "service", "env"}
    return tuple(
        part for part in join_key.split("|")
        if part and part.split("=", 1)[0] not in benign
    )


def _pairs_same_replica_or_fleet(a: NormalizedMetricObservation, b: NormalizedMetricObservation) -> Tuple[bool, Literal["replica_correlated", "service_fleet"]]:
    """Enforces strict replica alignment: never collapses different replicas or services onto each other."""
    if a.service != b.service:
        return False, "replica_correlated"
    ra = getattr(a, "replica_key", "") or ""
    rb = getattr(b, "replica_key", "") or ""
    if ra or rb:
        return (ra != "" and ra == rb), "replica_correlated"
    for rk in ("pod=", "instance=", "container="):
        if rk in (a.join_key or "") or rk in (b.join_key or ""):
            return (a.join_key == b.join_key), "replica_correlated"
    return (_fleet_scope_tags(a.join_key) == _fleet_scope_tags(b.join_key)), "service_fleet"


def evaluate_all_rules(
    *,
    profile: SystemProfile,
    observations: List[Any],
    explicit_trace_id: Optional[str] = None,
    incident_timestamp: Optional[str] = None,
    enabled_only: Optional[List[str]] = None,
) -> RuleEvaluationResult:
    """Shared deterministic evaluator enforcing scope isolation, replica joins, and pilot boundaries."""
    all_prom = [o for o in observations if getattr(o, "backend_source", None) == "prometheus"]
    invalid_measurements = [
        o.finding for o in all_prom if getattr(o, "status", None) == "INVALID_MEASUREMENT"
    ]
    trunc_notes = sorted({
        f"{o.service}/{o.signal_name} ({o.retained_series_count}/{o.total_series_count} series)"
        for o in all_prom if getattr(o, "truncated", False)
    })
    if trunc_notes:
        cov_status: CoverageStatus = "PARTIAL"
    elif any(o.status == "SUCCESS" for o in all_prom):
        cov_status = "COMPLETE"
    elif any(o.status == "EMPTY" for o in all_prom):
        cov_status = "EMPTY"
    else:
        cov_status = "UNKNOWN"

    metric_obs: List[NormalizedMetricObservation] = [
        o for o in all_prom
        if o.status == "SUCCESS"
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
            coverage_status=cov_status,
            truncated_series=trunc_notes,
            invalid_measurements=invalid_measurements,
            gap_reasons=[f"Requested trace_id '{explicit_trace_id}' unavailable or outside incident window."],
            next_discriminating_checks=[
                f"Verify Tempo trace ingestion and retention for target trace '{explicit_trace_id}' inside incident window."
            ],
        )

    # Detect conflicting revisions on the exact same series (service, signal_name, join_key)
    series_revs: Dict[Tuple[str, str, str], List[NormalizedMetricObservation]] = {}
    for m in metric_obs:
        series_revs.setdefault((m.service, m.signal_name, m.join_key), []).append(m)
    conflicting_series: Set[Tuple[str, str, str]] = set()
    conflict_gaps: List[str] = []
    for skey, revs in series_revs.items():
        if len(revs) > 1 and observations_conflict(revs):
            conflicting_series.add(skey)
            conflict_gaps.append(
                f"Conflicting backend revisions observed for {skey[0]} {skey[1]} [{skey[2]}]; keeping both revisions without certifying."
            )

    if enabled_only is not None:
        enabled = set(enabled_only)
    elif settings.EXPERIMENTAL_RULES_ENABLED:
        enabled = set(profile.enabled_rules)
    else:
        # Pilot boundary: allow causal certification ONLY for verified timeout family
        enabled = set(profile.enabled_rules) & {"pool_acquisition_timeout", "upstream_connect_timeout"}

    timeout_markers = set(profile.trace_contract.timeout_error_markers or ["TimeoutError"])
    pool_ops = set(profile.trace_contract.operation_aliases.get("pool_acquisition_timeout", ["db.connection.acquire"]))
    connect_ops = set(profile.trace_contract.operation_aliases.get("upstream_connect_timeout", ["rpc.connect"]))

    # Index counter spikes by service (never trusting single-sample or counter-reset series)
    pool_wait_spikes: Dict[str, List[NormalizedMetricObservation]] = {}
    connect_wait_spikes: Dict[str, List[NormalizedMetricObservation]] = {}
    for m in metric_obs:
        skey = (m.service, m.signal_name, m.join_key)
        if skey in conflicting_series or m.counter_reset_detected:
            continue
        if _matches_signal(m.signal_name, "pool_acquire_timeouts", profile) and (m.delta or 0.0) > 0.0:
            pool_wait_spikes.setdefault(m.service, []).append(m)
        if _matches_signal(m.signal_name, "upstream_connect_timeouts", profile) and (m.delta or 0.0) > 0.0:
            connect_wait_spikes.setdefault(m.service, []).append(m)

    # Index pool saturation & join failures by service
    saturated_pools: Dict[str, List[NormalizedMetricObservation]] = {}
    all_pools: Dict[str, List[NormalizedMetricObservation]] = {}
    unjoinable_gaps: List[str] = []
    active_sig = profile.signals.get("pool_active")
    pool_thr = active_sig.saturation_threshold if (active_sig and active_sig.saturation_threshold is not None) else 0.95
    for m in metric_obs:
        if _matches_signal(m.signal_name, "pool_active", profile):
            all_pools.setdefault(m.service, []).append(m)
            if m.join_status in ("unjoinable", "missing_denominator"):
                unjoinable_gaps.append(
                    f"Replica capacity join failed for {m.service} {m.signal_name} ({m.join_status})"
                )
            elif m.value is not None and m.value >= pool_thr and (m.service, m.signal_name, m.join_key) not in conflicting_series:
                saturated_pools.setdefault(m.service, []).append(m)

    def _pool_replica_compatible(svc: str, counter_obs: NormalizedMetricObservation) -> bool:
        """If both replica-labeled pool occupancy and replica-labeled wait counters exist, require same replica."""
        pools = all_pools.get(svc, [])
        if not pools or not counter_obs.replica_key:
            return True
        rep_pools = [p for p in pools if p.replica_key]
        if not rep_pools:
            return True
        sat_reps = [p for p in rep_pools if p.join_status in ("single_series", "label_joined") and (p.value or 0.0) >= pool_thr]
        return any(p.replica_key == counter_obs.replica_key for p in sat_reps)

    # Collect healthy observations on candidate dependencies (never from truncated series!)
    def _healthy_ids(exclude_svc: str) -> List[str]:
        res: List[str] = []
        for m in metric_obs:
            if m.service == exclude_svc or m.value is None or m.truncated or m.coverage_status == "PARTIAL":
                continue
            if _matches_signal(m.signal_name, "latency_p95", profile) and m.value < 1.0:
                res.append(m.observation_id)
            elif _matches_signal(m.signal_name, "pool_active", profile) and m.join_status in ("single_series", "label_joined") and m.value < 0.50:
                res.append(m.observation_id)
        return res[:2]

    # 1. Request-level timeout trace checks (claim_scope = affected_request)
    any_timeout_span = False
    for t in trace_obs:
        for sp in t.error_spans:
            if sp.get("error") not in timeout_markers:
                continue
            any_timeout_span = True
            op = sp.get("name", "")
            svc = sp.get("service") or t.bottleneck_service
            sp_id = str(sp.get("span_id") or "")
            if not svc:
                continue
            if op in pool_ops and "pool_acquisition_timeout" in enabled and svc in pool_wait_spikes:
                compatible_counters = [c for c in pool_wait_spikes[svc] if _pool_replica_compatible(svc, c)]
                if compatible_counters:
                    counter_obs = compatible_counters[0]
                    return RuleEvaluationResult(
                        is_sufficient=True,
                        winning_rule="pool_acquisition_timeout",
                        root_cause_service=svc,
                        mechanism="pool_acquisition_timeout",
                        claim_scope="affected_request",
                        claim_subject=f"{svc} on trace {t.trace_id}",
                        supporting_observation_ids=[counter_obs.observation_id, t.observation_id],
                        supporting_signal_names=[counter_obs.signal_name],
                        supporting_trace_id=t.trace_id,
                        supporting_span_id=sp_id or None,
                        healthy_observation_ids=_healthy_ids(svc),
                        localization=loc,
                        coverage_status=cov_status,
                        truncated_series=trunc_notes,
                        invalid_measurements=invalid_measurements,
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
                    claim_scope="affected_request",
                    claim_subject=f"{svc} on trace {t.trace_id}",
                    supporting_observation_ids=[counter_obs.observation_id, t.observation_id],
                    supporting_signal_names=[counter_obs.signal_name],
                    supporting_trace_id=t.trace_id,
                    supporting_span_id=sp_id or None,
                    healthy_observation_ids=_healthy_ids(svc),
                    localization=loc,
                    coverage_status=cov_status,
                    truncated_series=trunc_notes,
                    invalid_measurements=invalid_measurements,
                    next_discriminating_checks=_format_checks(profile, "upstream_connect_timeout", svc),
                    recommended_runbook_action=_format_runbook(profile, "upstream_connect_timeout", svc),
                )

    if any_timeout_span:
        checks = []
        if loc and loc.bottleneck_service:
            checks.append(
                f"Timeout span isolated on {loc.bottleneck_service} ({loc.bottleneck_operation or 'timeout'}) without matching same-replica counter growth; inspect exporter scrape coverage and timeout counters on {loc.bottleneck_service}."
            )
        return RuleEvaluationResult(
            is_sufficient=False,
            localization=loc,
            coverage_status=cov_status,
            truncated_series=trunc_notes,
            invalid_measurements=invalid_measurements,
            gap_reasons=["Trace TimeoutError lacks corroborating monotonic timeout counter on compatible replica/service."] + conflict_gaps + unjoinable_gaps,
            next_discriminating_checks=checks,
        )

    # 2. Evaluate timeout-independent / experimental candidates only if explicitly enabled (and untargeted pool only when trace_id is None)
    candidates: List[RuleEvaluationResult] = []
    if not explicit_trace_id and "pool_acquisition_timeout" in enabled:
        for svc, pool_list in saturated_pools.items():
            if svc not in pool_wait_spikes:
                continue
            # If a sampled trace shows an explicit bottleneck on a DIFFERENT service or explicit non-pool op, do not claim pool exhaustion!
            if loc and loc.bottleneck_service:
                if loc.bottleneck_service != svc:
                    continue
                if loc.bottleneck_operation and loc.bottleneck_operation not in pool_ops:
                    continue

            waits = pool_wait_spikes[svc]
            matched_pool: Optional[NormalizedMetricObservation] = None
            matched_wait: Optional[NormalizedMetricObservation] = None
            matched_scope: Literal["replica_correlated", "service_fleet"] = "service_fleet"
            for p in pool_list:
                for w in waits:
                    ok, sc = _pairs_same_replica_or_fleet(p, w)
                    if ok:
                        matched_pool, matched_wait, matched_scope = p, w, sc
                        break
                if matched_pool is not None:
                    break

            if matched_pool and matched_wait:
                obs_ids = [matched_pool.observation_id, matched_wait.observation_id]
                t_ref = None
                if loc and loc.observation_id and loc.bottleneck_service == svc:
                    obs_ids.append(loc.observation_id)
                    t_ref = loc.trace_id
                subj = f"{svc} [{matched_pool.replica_key}]" if matched_scope == "replica_correlated" else svc
                candidates.append(RuleEvaluationResult(
                    is_sufficient=True,
                    winning_rule="pool_acquisition_timeout",
                    root_cause_service=svc,
                    mechanism="db_pool_exhaustion" if profile.profile_id == "checkout-demo" else "pool_acquisition_timeout",
                    claim_scope=matched_scope,
                    claim_subject=subj,
                    supporting_observation_ids=obs_ids,
                    supporting_signal_names=[matched_pool.signal_name, matched_wait.signal_name],
                    supporting_trace_id=t_ref,
                    supporting_span_id=loc.bottleneck_span_id if loc else None,
                    healthy_observation_ids=_healthy_ids(svc),
                    localization=loc,
                    coverage_status=cov_status,
                    truncated_series=trunc_notes,
                    invalid_measurements=invalid_measurements,
                    next_discriminating_checks=_format_checks(profile, "pool_acquisition_timeout", svc),
                    recommended_runbook_action=_format_runbook(profile, "pool_acquisition_timeout", svc),
                ))

    # Optional experimental rules (disabled in pilot mode unless enabled_only or EXPERIMENTAL_RULES_ENABLED=True)
    def _exp_trace_allows(svc_name: str) -> bool:
        if not explicit_trace_id:
            return True
        return bool(loc and loc.bottleneck_service == svc_name)

    if "cpu_contention" in enabled:
        cpu_sig = profile.signals.get("cpu_utilization")
        cpu_thr = cpu_sig.saturation_threshold if (cpu_sig and cpu_sig.saturation_threshold is not None) else 0.85
        for m in metric_obs:
            if not _matches_signal(m.signal_name, "cpu_utilization", profile):
                continue
            if (
                m.value is None
                or m.unit not in ("", "ratio")
                or m.value < cpu_thr
                or m.value < 0.0
                or m.value > 1.0
                or not _exp_trace_allows(m.service)
            ):
                continue
            lat_obs = next(
                (
                    l for l in metric_obs
                    if l.service == m.service
                    and _matches_signal(l.signal_name, "latency_p95", profile)
                    and l.value is not None
                    and normalize_duration_to_seconds(l.value, getattr(l, "unit", "") or "") >= 1.0
                ),
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
                sc: Literal["replica_correlated", "service_fleet"] = "replica_correlated" if m.replica_key else "service_fleet"
                candidates.append(RuleEvaluationResult(
                    is_sufficient=True,
                    winning_rule="cpu_contention",
                    root_cause_service=m.service,
                    mechanism="cpu_contention",
                    claim_scope=sc,
                    claim_subject=f"{m.service} [{m.replica_key}]" if m.replica_key else m.service,
                    supporting_observation_ids=obs_ids,
                    supporting_signal_names=sigs,
                    supporting_trace_id=t_ref,
                    healthy_observation_ids=_healthy_ids(m.service),
                    localization=loc,
                    coverage_status=cov_status,
                    truncated_series=trunc_notes,
                    invalid_measurements=invalid_measurements,
                    next_discriminating_checks=_format_checks(profile, "cpu_contention", m.service),
                    recommended_runbook_action=_format_runbook(profile, "cpu_contention", m.service),
                ))

    if "memory_pressure_restarts" in enabled or "memory_leak_oomkill" in enabled:
        mem_sig = profile.signals.get("memory_utilization")
        mem_thr = mem_sig.saturation_threshold if (mem_sig and mem_sig.saturation_threshold is not None) else 0.90
        for m in metric_obs:
            if not _matches_signal(m.signal_name, "memory_utilization", profile):
                continue
            if (
                m.value is None
                or m.unit not in ("", "ratio")
                or m.value < mem_thr
                or m.value < 0.0
                or m.value > 1.0
                or not getattr(m, "replica_key", "")
                or not _exp_trace_allows(m.service)
            ):
                continue
            restart_obs = next(
                (
                    r for r in metric_obs
                    if r.service == m.service
                    and _matches_signal(r.signal_name, "container_restarts", profile)
                    and (r.delta or 0.0) > 0.0
                    and len(r.sample_timestamps) >= 2
                    and getattr(r, "replica_key", "") == m.replica_key
                    and str((r.labels or {}).get("reason", "")).lower() in ("", "oomkilled", "oom")
                ),
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
                sc_mem: Literal["replica_correlated", "service_fleet"] = "replica_correlated" if m.replica_key else "service_fleet"
                candidates.append(RuleEvaluationResult(
                    is_sufficient=True,
                    winning_rule="memory_pressure_restarts",
                    root_cause_service=m.service,
                    mechanism="memory_pressure_restarts",
                    claim_scope=sc_mem,
                    claim_subject=f"{m.service} [{m.replica_key}]" if m.replica_key else m.service,
                    supporting_observation_ids=obs_ids,
                    supporting_signal_names=sigs,
                    supporting_trace_id=t_ref,
                    healthy_observation_ids=_healthy_ids(m.service),
                    localization=loc,
                    coverage_status=cov_status,
                    truncated_series=trunc_notes,
                    invalid_measurements=invalid_measurements,
                    next_discriminating_checks=_format_checks(profile, "memory_leak_oomkill", m.service),
                    recommended_runbook_action=_format_runbook(profile, "memory_leak_oomkill", m.service),
                ))

    # Strictly block certifying request-level pool/connect timeout from a slow trace without a matching TimeoutError span when no other candidate matched
    if explicit_trace_id and not candidates:
        contending_svcs = sorted(set(saturated_pools) | set(pool_wait_spikes) | set(connect_wait_spikes))
        gaps = conflict_gaps + unjoinable_gaps + invalid_measurements
        checks: List[str] = []
        if loc and loc.bottleneck_service:
            op_label = loc.bottleneck_operation or "slow_span"
            other_note = f" vs contention observed on {', '.join(contending_svcs)}" if contending_svcs else ""
            gaps.append(
                f"Alerted trace '{explicit_trace_id}' shows delay in {loc.bottleneck_service} ({op_label}) without an acquisition/connect timeout error span."
            )
            checks.append(
                f"Distinguish slow {loc.bottleneck_service} operation '{op_label}' ({loc.exclusive_duration_ms:.1f}ms) in trace {explicit_trace_id}{other_note} before mitigating pool or connect timeouts."
            )
        elif not gaps:
            gaps.append(f"Alerted trace '{explicit_trace_id}' lacks a matching timeout error span on any pool or connect operation.")
        if not checks:
            checks.append(f"Inspect child spans and error status of trace {explicit_trace_id} to isolate the request bottleneck.")
        return RuleEvaluationResult(
            is_sufficient=False,
            localization=loc,
            coverage_status=cov_status,
            truncated_series=trunc_notes,
            invalid_measurements=invalid_measurements,
            gap_reasons=gaps,
            next_discriminating_checks=checks,
        )

    # 3. Conflict resolution across multiple candidate causes or unexplained latency anomalies
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
                coverage_status=cov_status,
                truncated_series=trunc_notes,
                invalid_measurements=invalid_measurements,
                gap_reasons=[
                    f"Simultaneous candidate faults detected across multiple dependencies ({', '.join(distinct_svcs)}) without an isolating trace."
                ],
                next_discriminating_checks=checks,
            )
        chosen = candidates[0]
        if chosen.claim_scope in ("replica_correlated", "service_fleet") and not trace_obs:
            # Check for unexplained critical latency spike on another dependency without an isolating trace
            other_anomalies = sorted({
                m.service for m in metric_obs
                if m.service != chosen.root_cause_service
                and _matches_signal(m.signal_name, "latency_p95", profile)
                and (m.value or 0.0) >= 1.0
            })
            if other_anomalies:
                all_svcs = sorted({chosen.root_cause_service or "", *other_anomalies} - {""})
                return RuleEvaluationResult(
                    is_sufficient=False,
                    localization=loc,
                    coverage_status=cov_status,
                    truncated_series=trunc_notes,
                    invalid_measurements=invalid_measurements,
                    gap_reasons=[
                        f"Simultaneous anomalies detected across multiple dependencies ({', '.join(all_svcs)}) without an isolating trace."
                    ],
                    next_discriminating_checks=[
                        f"Trace both competing dependencies ({', '.join(all_svcs)}) inside the same request path before applying mitigation."
                    ],
                )
        return chosen

    # 4. Inconclusive / localization-only abstain with discriminating checks
    gaps = list(conflict_gaps) + list(unjoinable_gaps) + list(invalid_measurements)
    if trunc_notes:
        gaps.append(f"Partial series coverage ({', '.join(trunc_notes)}); unretained replicas were not inspected.")
    next_checks: List[str] = []
    if loc and loc.bottleneck_service:
        op_txt = loc.bottleneck_operation or "slow_span"
        contenders = sorted(set(saturated_pools) | set(pool_wait_spikes))
        if contenders and loc.bottleneck_service not in contenders:
            gaps.append(
                f"Trace {loc.trace_id} localized bottleneck to {loc.bottleneck_service} ({op_txt}), while pool contention appeared on {', '.join(contenders)}."
            )
            next_checks.append(
                f"Compare slow operation '{op_txt}' on {loc.bottleneck_service} ({loc.exclusive_duration_ms:.1f}ms) against pool wait contention on {', '.join(contenders)} in end-to-end spans."
            )
        else:
            next_checks.append(
                f"Trace {loc.trace_id} localized bottleneck to {loc.bottleneck_service} ({op_txt}, {loc.exclusive_duration_ms:.1f}ms); inspect wait queues, error logs, and saturation counters on {loc.bottleneck_service}."
            )
    if saturated_pools and not pool_wait_spikes:
        gaps.append("Pool occupancy >= 95% observed without corresponding wait timeout counter increase.")
    elif saturated_pools and pool_wait_spikes and not gaps:
        gaps.append("Pool occupancy and wait timeout spikes occurred on different replicas or failed strict join matching.")
    if invalid_measurements and not next_checks:
        next_checks.append(
            "Fix invalid metric mapping (raw cumulative counter or out-of-range ratio) with proper rate()/capacity normalization before re-evaluating."
        )
    return RuleEvaluationResult(
        is_sufficient=False,
        localization=loc,
        coverage_status=cov_status,
        truncated_series=trunc_notes,
        invalid_measurements=invalid_measurements,
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
