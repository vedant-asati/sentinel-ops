import logging
from typing import Any, Dict
from sentinel_ops.agents.state import InvestigationState
from sentinel_ops.core.config import settings

logger = logging.getLogger(__name__)


def crag_sufficiency_node(state: InvestigationState) -> Dict[str, Any]:
    """CRAG Sufficiency Gate: evaluates whether accumulated evidence is sufficient

    to definitively substantiate one hypothesis and rule out competing ones.
    """
    logger.info("Evaluating CRAG sufficiency (iteration %d)...", state.crag_iterations)

    evidence_list = state.evidence
    successful_items = [e for e in evidence_list if e.status == "SUCCESS"]

    # 1. Payment DB pool saturation check
    has_payment_saturation = any(
        "saturated" in e.finding for e in successful_items if e.sample_or_span_ref == "db_pool_active"
    )

    # 2. Pricing bottleneck check
    has_pricing_bottleneck = any(
        ("pricing-service" in e.finding and "bottleneck" in e.finding)
        or ("pricing" in e.finding and "spiked" in e.finding)
        for e in successful_items
    )

    # 3. Cart memory exhaustion: requires memory exhaustion AND (container restarts elevated OR trace bottleneck)
    has_cart_mem = any("cart" in e.finding and "exhausted" in e.finding for e in successful_items)
    has_cart_restart = any("cart" in e.finding and ("restarts elevated" in e.finding or "crash" in e.finding) for e in successful_items)
    has_cart_trace = any("cart" in e.finding and "bottleneck" in e.finding for e in successful_items)
    has_cart_memory_exhaustion = has_cart_mem and (has_cart_restart or has_cart_trace)

    # 4. Payment error rate spike: requires error rate spike AND trace bottleneck or connection refusal
    has_payment_err = any("payment" in e.finding and "error_rate spiked" in e.finding for e in successful_items)
    has_payment_trace = any("payment" in e.finding and "bottleneck" in e.finding for e in successful_items)
    has_payment_error_spike = has_payment_err and (has_payment_trace or any("refused" in e.finding.lower() for e in successful_items))

    is_sufficient = (
        has_payment_saturation
        or has_pricing_bottleneck
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
    """Routes the investigation based on evidence sufficiency and budget limits."""
    # Operational failure: if all telemetry collection returned TOOL_FAILURE
    if state.evidence and all(e.status == "TOOL_FAILURE" for e in state.evidence):
        logger.error("CRAG: All telemetry collectors returned TOOL_FAILURE -> routing to operational_failure.")
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
