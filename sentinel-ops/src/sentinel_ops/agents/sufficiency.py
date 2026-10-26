from datetime import datetime
import logging
import time
from typing import Any, Dict
from sentinel_ops.agents.state import EvidenceItem, InvestigationState
from sentinel_ops.core.config import settings

logger = logging.getLogger(__name__)


def _evidence_in_incident_window(ev: EvidenceItem, incident_timestamp: str) -> bool:
    """Validates that an evidence observation window actually brackets T_incident within bounded range."""
    if not incident_timestamp or not ev.observation_window or len(ev.observation_window) != 2:
        return True
    try:
        t_inc = datetime.fromisoformat(incident_timestamp.replace("Z", "+00:00")).timestamp()
        w_start = datetime.fromisoformat(ev.observation_window[0].replace("Z", "+00:00")).timestamp()
        w_end = datetime.fromisoformat(ev.observation_window[1].replace("Z", "+00:00")).timestamp()
        return (w_start - 180.0 <= t_inc <= w_end + 180.0) and (w_end - w_start <= 600.0)
    except Exception:
        return True


def crag_sufficiency_node(state: InvestigationState) -> Dict[str, Any]:
    """CRAG Sufficiency Gate: evaluates whether accumulated evidence is sufficient

    to definitively substantiate one hypothesis and rule out competing ones.
    """
    logger.info("Evaluating CRAG sufficiency (iteration %d)...", state.crag_iterations)

    evidence_list = state.evidence
    from sentinel_ops.profiles.registry import get_profile
    from sentinel_ops.rules.engine import evaluate_all_rules

    try:
        profile = get_profile(getattr(state, "profile_id", "checkout-demo"))
    except Exception:
        profile = None

    if profile is not None and state.observations:
        rule_eval = evaluate_all_rules(
            profile=profile,
            observations=state.observations,
            explicit_trace_id=state.trace_id,
            incident_timestamp=state.incident_timestamp,
        )
        new_iteration = state.crag_iterations + 1
        loc_dict = rule_eval.localization.model_dump() if rule_eval.localization else None
        if rule_eval.is_sufficient:
            return {
                "crag_iterations": new_iteration,
                "crag_sufficient": True,
                "missing_evidence_hints": [],
                "rule_evaluation": rule_eval.model_dump(),
                "localized_dependency": loc_dict,
                "next_discriminating_checks": rule_eval.next_discriminating_checks,
            }
        has_success_obs = any(o.status == "SUCCESS" for o in state.observations)
        has_preseeded_ev = any(e.status == "SUCCESS" for e in state.evidence)
        if profile.profile_id != "checkout-demo" or has_success_obs or not has_preseeded_ev:
            hints = list(rule_eval.gap_reasons) or [
                "Telemetric signals inconclusive: neither primary cause nor causal mechanism substantiated."
            ]
            return {
                "crag_iterations": new_iteration,
                "crag_sufficient": False,
                "missing_evidence_hints": hints,
                "localized_dependency": loc_dict,
                "next_discriminating_checks": rule_eval.next_discriminating_checks,
            }

    successful_items = [
        e for e in evidence_list
        if e.status == "SUCCESS" and _evidence_in_incident_window(e, state.incident_timestamp)
    ]

    # 1. Check if trace matches explicit state.trace_id (if set) and contains TimeoutError
    timeout_trace = next(
        (
            e for e in successful_items
            if e.backend_source == "tempo"
            and "TimeoutError" in e.finding
            and (not state.trace_id or e.query_string == state.trace_id or e.query_params.get("trace_id") == state.trace_id)
        ),
        None,
    )

    has_requested_trace = bool(state.trace_id) and any(
        e.backend_source == "tempo"
        and (e.query_string == state.trace_id or e.query_params.get("trace_id") == state.trace_id)
        for e in successful_items
    )

    if timeout_trace:
        op = timeout_trace.query_params.get("operation", "")
        svc = timeout_trace.query_params.get("service") or ("payment-service" if "payment" in timeout_trace.finding else "pricing-service")

        has_timeout_corroboration = False
        if "db.connection.acquire" in timeout_trace.finding or op == "db.connection.acquire":
            matching_counter = next((
                e for e in successful_items
                if (e.query_params.get("service") == svc or svc in e.id)
                and e.query_params.get("metric_type") == "db_pool_acquire_timeouts_total"
                and "spiked" in e.finding
            ), None)
            if matching_counter:
                has_timeout_corroboration = True
        elif "rpc.connect" in timeout_trace.finding or op == "rpc.connect":
            matching_counter = next((
                e for e in successful_items
                if (e.query_params.get("service") == svc or svc in e.id)
                and e.query_params.get("metric_type") == "upstream_connect_timeouts_total"
                and "spiked" in e.finding
            ), None)
            if matching_counter:
                has_timeout_corroboration = True

        is_sufficient = has_timeout_corroboration
    elif state.trace_id and not has_requested_trace:
        # Alert targeted a specific request trace, but requested trace_id was missing/failed/stale
        is_sufficient = False
    else:
        # Untargeted incident OR targeted non-timeout trace present with matching service saturation/error metrics
        has_payment_saturation = any(
            "saturated" in e.finding for e in successful_items if e.sample_or_span_ref == "db_pool_active"
        )
        has_payment_wait_contention = any(
            (e.query_params.get("service") == "payment-service" or "paym" in e.id)
            and e.sample_or_span_ref == "db_pool_acquire_timeouts_total"
            and "spiked" in e.finding
            for e in successful_items
        ) or any(
            e.backend_source == "tempo"
            and "payment-service" in e.finding
            and "TimeoutError" in e.finding
            and "db.connection.acquire" in e.finding
            for e in successful_items
        )
        has_payment_exhaustion = has_payment_saturation and has_payment_wait_contention

        has_pricing_delay = any(
            ("pricing-service" in e.finding and "bottleneck" in e.finding)
            or ("pricing" in e.finding and "latency_p95 spiked" in e.finding)
            for e in successful_items
        )
        has_pricing_cpu_saturated = any(
            (e.query_params.get("service") == "pricing-service" or "pric" in e.id)
            and e.sample_or_span_ref == "cpu_saturation"
            and "saturated" in e.finding
            for e in successful_items
        )
        has_pricing_cpu_bottleneck = has_pricing_delay and has_pricing_cpu_saturated

        has_cart_mem = any("cart" in e.finding and "exhausted" in e.finding for e in successful_items)
        has_cart_restart = any("cart" in e.finding and ("restarts elevated" in e.finding or "crash" in e.finding) for e in successful_items)
        has_cart_memory_exhaustion = has_cart_mem and has_cart_restart

        has_payment_err = any("payment" in e.finding and "error_rate spiked" in e.finding for e in successful_items)
        has_payment_trace = any("payment" in e.finding and "bottleneck" in e.finding for e in successful_items)
        has_payment_error_spike = has_payment_err and (has_payment_trace or any("payment" in e.finding.lower() and "refused" in e.finding.lower() for e in successful_items))

        is_sufficient = (
            has_payment_exhaustion
            or has_pricing_cpu_bottleneck
            or has_cart_memory_exhaustion
            or has_payment_error_spike
        )
    new_iteration = state.crag_iterations + 1

    missing_hints = []
    if not is_sufficient:
        missing_hints.append("Telemetric signals inconclusive: neither primary cause nor causal mechanism substantiated.")
        has_empty_payment = any(e.status != "SUCCESS" and "payment" in e.id for e in evidence_list)
        if has_empty_payment:
            missing_hints.append("Payment service metrics are EMPTY or experiencing TOOL_FAILURE.")

    return {
        "crag_iterations": new_iteration,
        "crag_sufficient": is_sufficient,
        "missing_evidence_hints": missing_hints,
    }


def route_crag_gate(state: InvestigationState) -> str:
    """Routes the investigation based on evidence sufficiency, backend collector health, and budget limits."""
    # 0. Operational failure: if run deadline exceeded, route to operational_failure
    if state.deadline_timestamp and time.monotonic() > state.deadline_timestamp:
        logger.error("CRAG: Run-wide deadline exceeded -> routing to operational_failure.")
        return "operational_failure"

    # 1. Operational failure: if collectors returned TOOL_FAILURE and zero successful items exist
    tool_failures = [e for e in state.evidence if e.status == "TOOL_FAILURE"]
    has_success = any(e.status == "SUCCESS" for e in state.evidence)
    if tool_failures and not has_success:
        logger.error("CRAG: Telemetry collectors returned TOOL_FAILURE with zero successful observations -> routing to operational_failure.")
        return "operational_failure"

    if state.crag_sufficient:
        logger.info("CRAG: Evidence is SUFFICIENT -> Routing to Synthesizer.")
        return "synthesizer"

    if state.crag_iterations < settings.MAX_CRAG_ITERATIONS:
        logger.warning(
            "CRAG: Evidence insufficient, attempting targeted re-query (iteration %d/%d)",
            state.crag_iterations,
            settings.MAX_CRAG_ITERATIONS,
        )
        return "supervisor"

    logger.warning("CRAG: Evidence insufficient and iteration limit reached -> ABSTAINING.")
    return "insufficient_evidence"
