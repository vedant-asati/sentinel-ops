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

    # Check for distinguishing signals
    has_payment_saturation = any(
        "saturated" in e.finding for e in successful_items if e.sample_or_span_ref == "db_pool_active"
    )
    has_pricing_bottleneck = any(
        ("pricing-service" in e.finding and "bottleneck" in e.finding)
        or ("pricing" in e.finding and "spiked" in e.finding)
        for e in successful_items
    )

    is_sufficient = has_payment_saturation or has_pricing_bottleneck
    new_iteration = state.crag_iterations + 1

    missing_hints = []
    if not is_sufficient:
        missing_hints.append("Telemetric signals inconclusive: neither payment DB saturation nor pricing CPU latency confirmed.")
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
