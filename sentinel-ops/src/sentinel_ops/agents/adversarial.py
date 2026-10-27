import logging
import time
from typing import Any, Dict, List, Tuple
from sentinel_ops.agents.state import AdversarialVerdict, AtomicClaim, EvidenceItem, InvestigationState
from sentinel_ops.agents.sufficiency import _evidence_in_incident_window
from sentinel_ops.core.config import settings
from sentinel_ops.telemetry.normalize import observations_conflict

logger = logging.getLogger(__name__)


def validate_claims_and_citations(
    claims: List[AtomicClaim],
    evidence: List[EvidenceItem],
) -> Tuple[bool, List[str]]:
    """Enforces atomic claim citation contracts against collected evidence."""
    errors: List[str] = []

    claim_types = {c.claim_type for c in claims}
    if "root_cause" not in claim_types:
        errors.append("Diagnosis lacks an atomic 'root_cause' claim.")
    if "mechanism" not in claim_types:
        errors.append("Diagnosis lacks an atomic 'mechanism' claim.")

    failed_or_empty_ids = {e.id for e in evidence if e.status != "SUCCESS"}
    all_known_ids = {e.id for e in evidence}

    for claim in claims:
        if not claim.cited_evidence_ids:
            errors.append(f"Claim '{claim.claim_id}' contains zero cited evidence IDs.")
            continue

        for cited_id in claim.cited_evidence_ids:
            if cited_id not in all_known_ids:
                errors.append(f"Claim '{claim.claim_id}' cites unknown evidence ID '{cited_id}'.")
            elif cited_id in failed_or_empty_ids:
                errors.append(
                    f"Claim '{claim.claim_id}' cites non-successful evidence ID '{cited_id}' (status not SUCCESS)."
                )

    return len(errors) == 0, errors


def adversarial_reviewer_node(state: InvestigationState) -> Dict[str, Any]:
    """Fresh-Context Skeptic Reviewer: cross-examines atomic claims against citations

    using cold-slate evidence evaluation.
    """
    logger.info("Adversarial skeptic evaluating %d claims...", len(state.structured_claims))

    claims = state.structured_claims
    evidence_map = {e.id: e for e in state.evidence}
    claim_evals = []
    all_supported = True

    # Check for required claim types
    claim_types = {c.claim_type for c in claims}
    if "root_cause" not in claim_types or "mechanism" not in claim_types:
        all_supported = False
        critique = "Diagnosis is incomplete: missing required 'root_cause' or 'mechanism' claim."
        return {
            "adversarial_iterations": state.adversarial_iterations + 1,
            "adversarial_verdict": AdversarialVerdict(
                all_claims_supported=False,
                confidence=0.0,
                claim_evaluations=[],
                critique_hint=critique,
            ),
        }

    for c in claims:
        # Check non-empty citations
        if not c.cited_evidence_ids:
            claim_evals.append({
                "claim_id": c.claim_id,
                "supported": False,
                "reason": "Claim lacks any cited evidence ID.",
            })
            all_supported = False
            continue

        # Check citation validity and status == SUCCESS
        invalid_citations = []
        for eid in c.cited_evidence_ids:
            if eid not in evidence_map:
                invalid_citations.append(f"Unknown ID {eid}")
            else:
                ev_item = evidence_map[eid]
                if ev_item.status != "SUCCESS":
                    invalid_citations.append(f"{eid} has non-SUCCESS status '{ev_item.status}'")
                elif "nan" in ev_item.finding.lower():
                    invalid_citations.append(f"{eid} contains non-finite/NaN measurement ('{ev_item.finding}')")
                elif not _evidence_in_incident_window(ev_item, state.incident_timestamp):
                    invalid_citations.append(f"{eid} observation_window falls outside declared incident window")
                elif (
                    state.trace_id
                    and ev_item.backend_source == "tempo"
                    and ev_item.query_string != state.trace_id
                    and ev_item.query_params.get("trace_id") != state.trace_id
                ):
                    invalid_citations.append(
                        f"{eid} trace '{ev_item.query_string}' does not match requested trace_id '{state.trace_id}'"
                    )

                # Semantic service alignment check
                stmt_lower = c.statement.lower()
                stmt_norm = stmt_lower.replace("_", "-").replace(" ", "-")
                finding_lower = ev_item.finding.lower()
                ev_svc = (ev_item.query_params.get("service") or ev_item.query_params.get("target_service", "")).lower()

                known_services = {
                    "payment": ("payment-service", "paym"),
                    "pricing": ("pricing-service", "pric"),
                    "cart": ("cart-service", "cart"),
                    "checkout": ("checkout-service", "chec"),
                    "auth": ("auth-service", "auth"),
                }
                try:
                    from sentinel_ops.profiles.registry import get_profile
                    prof = get_profile(getattr(state, "profile_id", "checkout-demo"))
                    for sname in prof.resolve_service_names():
                        key = sname.lower()
                        if key not in known_services:
                            known_services[key] = (sname, key[:4])
                except Exception:
                    pass
                services_in_stmt = [
                    (k, v[0], v[1]) for k, v in known_services.items() if k in stmt_norm
                ]
                if services_in_stmt:
                    # The cited evidence must relate to AT LEAST ONE service mentioned in the claim
                    matches_any_service = any(
                        (k in finding_lower or k in ev_svc or abbr in ev_item.id.lower())
                        for k, full, abbr in services_in_stmt
                    )
                    if not matches_any_service:
                        claimed_str = "/".join(full for _, full, _ in services_in_stmt)
                        invalid_citations.append(f"{eid} does not relate to {claimed_str}")

                # Semantic polarity & entailment check:
                # If claim asserts failure/saturation/leak, evidence must not report normal/healthy
                failure_keywords = (
                    "exhaustion", "exhausted", "saturated", "saturation", "timeout",
                    "spiked", "failure", "leak", "leaked", "crashed", "outage",
                    "error", "refusal", "bottleneck", "delay", "destroyed"
                )
                healthy_keywords = (
                    "normal at", "healthy", "stable at", "flat at", "no increase", "0 restarts"
                )
                if c.claim_type in ("root_cause", "mechanism"):
                    if any(w in stmt_lower for w in failure_keywords):
                        if any(h in finding_lower for h in healthy_keywords):
                            invalid_citations.append(
                                f"{eid} does not entail failure claim: evidence reports healthy/normal condition ('{ev_item.finding}')"
                            )
                elif c.claim_type == "competing_hypothesis_falsified":
                    if any(f in finding_lower for f in ("saturated", "spiked", "critical", "exhausted", "timeout spiked")):
                        invalid_citations.append(
                            f"{eid} contradicts falsified hypothesis: evidence reports failure/saturation ('{ev_item.finding}')"
                        )

        if invalid_citations:
            claim_evals.append({
                "claim_id": c.claim_id,
                "supported": False,
                "reason": f"Invalid citations: {', '.join(invalid_citations)}",
            })
            all_supported = False
        else:
            claim_evals.append({
                "claim_id": c.claim_id,
                "supported": True,
                "reason": "Citations verified against successful observation.",
            })

    # Independent claim verification directly over cited observations & spans (ZERO selector re-invocation)
    if all_supported and not state.observations:
        all_supported = False
        claim_evals.append({
            "claim_id": "OBS-CHECK",
            "supported": False,
            "reason": "Independent verifier requires immutable typed observations to substantiate causal claims.",
        })
    elif all_supported and state.observations:
        try:
            from sentinel_ops.profiles.registry import get_profile

            prof = get_profile(getattr(state, "profile_id", "checkout-demo"))
            obs_by_id = {o.observation_id: o for o in state.observations}
            root_claim = next((c for c in claims if c.claim_type == "root_cause"), None)
            if root_claim is None or not state.mechanism:
                all_supported = False
                claim_evals.append({
                    "claim_id": "SCOPE-CHECK",
                    "supported": False,
                    "reason": "Missing root_cause claim or mechanism identifier for independent verification.",
                })
            else:
                cited_obs = []
                missing_obs = False
                for eid in root_claim.cited_evidence_ids:
                    ev = evidence_map.get(eid)
                    oid = ev.query_params.get("observation_id") if ev else None
                    if oid and oid in obs_by_id:
                        cited_obs.append((ev, obs_by_id[oid]))
                    else:
                        missing_obs = True
                        break
                if missing_obs or not cited_obs:
                    all_supported = False
                    claim_evals.append({
                        "claim_id": root_claim.claim_id,
                        "supported": False,
                        "reason": "Root-cause claim citations do not resolve to immutable typed observations.",
                    })
                else:
                    mech = state.mechanism
                    scope = root_claim.claim_scope or ("affected_request" if state.trace_id else "service_fleet")
                    # Reject if any cited observation is invalid, non-SUCCESS, or stale
                    bad_obs = [
                        o for _, o in cited_obs
                        if o.status != "SUCCESS"
                    ]
                    if bad_obs:
                        all_supported = False
                        claim_evals.append({
                            "claim_id": root_claim.claim_id,
                            "supported": False,
                            "reason": f"Cited observation status invalid for diagnosis: {bad_obs[0].status}.",
                        })

                    prom_cited = [o for _, o in cited_obs if getattr(o, "backend_source", None) == "prometheus"]
                    tempo_cited = [(ev, o) for ev, o in cited_obs if getattr(o, "backend_source", None) == "tempo"]

                    # Verify conflicting revisions or invalid measurements across cited series
                    for p in prom_cited:
                        p_rep = getattr(p, "replica_key", "") or ""
                        same_target_revs = [
                            o for o in state.observations
                            if getattr(o, "backend_source", None) == "prometheus"
                            and o.service == p.service
                            and o.signal_name == p.signal_name
                            and ((getattr(o, "replica_key", "") or "") == p_rep or o.join_key == p.join_key)
                        ]
                        if len(same_target_revs) > 1 and observations_conflict(same_target_revs):
                            all_supported = False
                            claim_evals.append({
                                "claim_id": root_claim.claim_id,
                                "supported": False,
                                "reason": f"Conflicting revisions present for {p.service} {p.signal_name} [{p.join_key}].",
                            })
                            break
                        if scope == "service_fleet":
                            fleet_revs = [
                                o for o in state.observations
                                if getattr(o, "backend_source", None) == "prometheus"
                                and o.service == p.service
                                and o.signal_name == p.signal_name
                            ]
                            if any(getattr(o, "counter_reset_detected", False) for o in fleet_revs) or (
                                len(fleet_revs) > 1 and observations_conflict(fleet_revs)
                            ):
                                all_supported = False
                                claim_evals.append({
                                    "claim_id": root_claim.claim_id,
                                    "supported": False,
                                    "reason": f"Conflicting or reset fleet measurements present for {p.service} {p.signal_name}.",
                                })
                                break

                    # Independently check allowed mechanisms without calling selector (FAIL CLOSED on unknown mechanisms)
                    if all_supported and mech in ("pool_acquisition_timeout", "db_pool_exhaustion", "upstream_connect_timeout"):
                        counter_target = "upstream_connect_timeouts" if mech == "upstream_connect_timeout" else "pool_acquire_timeouts"
                        cnt_mapping = prof.signals.get(counter_target)
                        cnt_names = {counter_target}
                        if cnt_mapping:
                            cnt_names.add(cnt_mapping.metric_name)

                        cnt_obs = next((o for o in prom_cited if o.signal_name in cnt_names), None)
                        if cnt_obs is None or (cnt_obs.delta or 0.0) <= 0.0 or len(cnt_obs.sample_timestamps) < 2 or cnt_obs.counter_reset_detected:
                            all_supported = False
                            claim_evals.append({
                                "claim_id": root_claim.claim_id,
                                "supported": False,
                                "reason": f"Independent check failed: missing monotonic positive in-window delta for {counter_target}.",
                            })

                        if all_supported and scope == "affected_request":
                            rule_key = "upstream_connect_timeout" if mech == "upstream_connect_timeout" else "pool_acquisition_timeout"
                            valid_ops = set(prof.trace_contract.operation_aliases.get(rule_key, ["db.connection.acquire"]))
                            t_markers = set(prof.trace_contract.timeout_error_markers or ["TimeoutError"])
                            if not tempo_cited:
                                all_supported = False
                                claim_evals.append({
                                    "claim_id": root_claim.claim_id,
                                    "supported": False,
                                    "reason": "affected_request claim scope requires cited distributed trace observation.",
                                })
                            else:
                                tev, tobs = tempo_cited[0]
                                matching_err_span = next(
                                    (
                                        sp for sp in tobs.error_spans
                                        if sp.get("error") in t_markers
                                        and sp.get("name") in valid_ops
                                        and (not cnt_obs or sp.get("service") == cnt_obs.service)
                                    ),
                                    None,
                                )
                                if matching_err_span is None:
                                    all_supported = False
                                    claim_evals.append({
                                        "claim_id": root_claim.claim_id,
                                        "supported": False,
                                        "reason": "Independent check failed: cited trace lacks timeout error on matching acquisition/connect operation.",
                                    })
                                elif mech != "upstream_connect_timeout" and cnt_obs and cnt_obs.replica_key:
                                    # Verify replica-labeled pool capacity series do not contradict pool-timeout replica wait counter
                                    pool_sig = prof.signals.get("pool_active")
                                    pool_names = {"pool_active", "db_pool_active"}
                                    if pool_sig:
                                        pool_names.add(pool_sig.metric_name)
                                    rep_pools = [
                                        o for o in state.observations
                                        if getattr(o, "backend_source", None) == "prometheus"
                                        and o.service == cnt_obs.service
                                        and o.signal_name in pool_names
                                        and getattr(o, "replica_key", "")
                                    ]
                                    if rep_pools:
                                        thr = pool_sig.saturation_threshold if (pool_sig and pool_sig.saturation_threshold is not None) else 0.95
                                        if not any(o.replica_key == cnt_obs.replica_key and (o.value or 0.0) >= thr for o in rep_pools):
                                            all_supported = False
                                            claim_evals.append({
                                                "claim_id": root_claim.claim_id,
                                                "supported": False,
                                                "reason": "Cross-replica mismatch: pool saturation not observed on the timeout counter's replica.",
                                            })
                        elif all_supported and scope in ("replica_correlated", "service_fleet"):
                            pool_sig = prof.signals.get("pool_active")
                            pool_names = {"pool_active", "db_pool_active"}
                            if pool_sig:
                                pool_names.add(pool_sig.metric_name)
                            thr = pool_sig.saturation_threshold if (pool_sig and pool_sig.saturation_threshold is not None) else 0.95
                            pool_obs = next((o for o in prom_cited if o.signal_name in pool_names), None)
                            if pool_obs is None or pool_obs.value is None or pool_obs.value < thr or pool_obs.join_status not in ("single_series", "label_joined"):
                                all_supported = False
                                claim_evals.append({
                                    "claim_id": root_claim.claim_id,
                                    "supported": False,
                                    "reason": "Independent check failed: cited pool observation does not substantiate joined capacity saturation.",
                                })
                            elif cnt_obs and (pool_obs.replica_key or cnt_obs.replica_key) and pool_obs.replica_key != cnt_obs.replica_key:
                                all_supported = False
                                claim_evals.append({
                                    "claim_id": root_claim.claim_id,
                                    "supported": False,
                                    "reason": f"Cross-replica join prohibited: {pool_obs.replica_key} != {cnt_obs.replica_key}.",
                                })
                    elif all_supported and mech in ("cpu_contention", "memory_pressure_restarts") and settings.EXPERIMENTAL_RULES_ENABLED:
                        if mech == "cpu_contention":
                            cpu_sig = prof.signals.get("cpu_utilization")
                            cpu_names = {"cpu_utilization"}
                            if cpu_sig:
                                cpu_names.add(cpu_sig.metric_name)
                            cpu_thr = cpu_sig.saturation_threshold if (cpu_sig and cpu_sig.saturation_threshold is not None) else 0.85
                            cpu_obs = next((o for o in prom_cited if o.signal_name in cpu_names), None)
                            lat_sig = prof.signals.get("latency_p95")
                            lat_names = {"latency_p95"}
                            if lat_sig:
                                lat_names.add(lat_sig.metric_name)
                            lat_obs = next((o for o in prom_cited if o.signal_name in lat_names), None)
                            lat_sec = None
                            if lat_obs and lat_obs.value is not None:
                                from sentinel_ops.profiles.schema import normalize_duration_to_seconds
                                lat_sec = normalize_duration_to_seconds(lat_obs.value, getattr(lat_obs, "unit", "") or "")
                            has_trace_loc = any(o.bottleneck_service == (cpu_obs.service if cpu_obs else state.root_cause_service) for _, o in tempo_cited)
                            if (
                                cpu_obs is None
                                or cpu_obs.value is None
                                or cpu_obs.unit not in ("", "ratio")
                                or not (cpu_thr <= cpu_obs.value <= 1.0)
                                or ((lat_sec is None or lat_sec < 1.0) and not has_trace_loc)
                            ):
                                all_supported = False
                                claim_evals.append({
                                    "claim_id": root_claim.claim_id,
                                    "supported": False,
                                    "reason": "Independent check failed: cited evidence does not substantiate bounded cpu_contention.",
                                })
                        else:
                            mem_sig = prof.signals.get("memory_utilization")
                            mem_names = {"memory_utilization"}
                            if mem_sig:
                                mem_names.add(mem_sig.metric_name)
                            mem_thr = mem_sig.saturation_threshold if (mem_sig and mem_sig.saturation_threshold is not None) else 0.90
                            mem_obs = next((o for o in prom_cited if o.signal_name in mem_names), None)
                            rst_sig = prof.signals.get("container_restarts")
                            rst_names = {"container_restarts"}
                            if rst_sig:
                                rst_names.add(rst_sig.metric_name)
                            rst_obs = next((o for o in prom_cited if o.signal_name in rst_names), None)
                            if (
                                mem_obs is None
                                or rst_obs is None
                                or mem_obs.value is None
                                or mem_obs.unit not in ("", "ratio")
                                or not (mem_thr <= mem_obs.value <= 1.0)
                                or not mem_obs.replica_key
                                or rst_obs.replica_key != mem_obs.replica_key
                                or (rst_obs.delta or 0.0) <= 0.0
                                or len(rst_obs.sample_timestamps) < 2
                            ):
                                all_supported = False
                                claim_evals.append({
                                    "claim_id": root_claim.claim_id,
                                    "supported": False,
                                    "reason": "Independent check failed: memory_pressure_restarts requires same-replica memory saturation and positive restarts.",
                                })
                    elif all_supported:
                        all_supported = False
                        claim_evals.append({
                            "claim_id": root_claim.claim_id,
                            "supported": False,
                            "reason": f"Mechanism '{mech}' is unsupported or disabled in current policy and cannot pass independent verification.",
                        })

                    # Check falsification claims cannot cite truncated/partial series
                    if all_supported:
                        for c in claims:
                            if c.claim_type == "competing_hypothesis_falsified":
                                for eid in c.cited_evidence_ids:
                                    ev = evidence_map.get(eid)
                                    oid = ev.query_params.get("observation_id") if ev else None
                                    obs_ref = obs_by_id.get(oid) if oid else None
                                    if obs_ref is not None and (getattr(obs_ref, "truncated", False) or getattr(obs_ref, "coverage_status", "") == "PARTIAL"):
                                        all_supported = False
                                        claim_evals.append({
                                            "claim_id": c.claim_id,
                                            "supported": False,
                                            "reason": f"Partial/truncated series ({obs_ref.observation_id}) cannot certify fleet-wide falsification.",
                                        })
                                        break
        except Exception as exc:
            # Fail closed on unexpected verifier errors
            all_supported = False
            claim_evals.append({
                "claim_id": "VERIFIER-ERROR",
                "supported": False,
                "reason": f"Independent verifier aborted safely: {exc}",
            })

    critique = None if all_supported else "One or more claims cite inconclusive or failed evidence."
    supported_count = sum(1 for ev in claim_evals if ev["supported"])
    total_claims = len(claim_evals)
    calculated_confidence = round(supported_count / total_claims, 2) if total_claims > 0 else 0.0

    verdict = AdversarialVerdict(
        all_claims_supported=all_supported,
        confidence=calculated_confidence if all_supported else 0.10,
        claim_evaluations=claim_evals,
        critique_hint=critique,
    )

    return {
        "adversarial_iterations": state.adversarial_iterations + 1,
        "adversarial_verdict": verdict,
    }


def route_adversarial_review(state: InvestigationState) -> str:
    """Routes based on adversarial verdict and safety limits."""
    # Enforce run deadline
    if state.deadline_timestamp and time.monotonic() >= state.deadline_timestamp:
        logger.warning("Adversarial: Deadline exceeded during review cycles. Routing to operational failure.")
        return "operational_failure"

    verdict = state.adversarial_verdict
    if verdict and verdict.all_claims_supported:
        logger.info("Adversarial: All claims entailed -> Routing to Blast Radius calculation.")
        return "blast_radius"

    if state.adversarial_iterations < settings.MAX_ADVERSARIAL_ITERATIONS:
        logger.warning(
            "Adversarial: Claims rejected, returning for synthesizer revision (attempt %d/%d)",
            state.adversarial_iterations,
            settings.MAX_ADVERSARIAL_ITERATIONS,
        )
        return "synthesizer"

    logger.warning("Adversarial: Max review iterations exhausted without entailment -> ABSTAINING.")
    return "insufficient_evidence"
