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
        hints = list(rule_eval.gap_reasons) or [
            "Telemetric signals inconclusive: neither primary cause nor causal mechanism substantiated."
        ]
        return {
            "crag_iterations": new_iteration,
            "crag_sufficient": False,
            "missing_evidence_hints": hints,
            "rule_evaluation": rule_eval.model_dump(),
            "localized_dependency": loc_dict,
            "next_discriminating_checks": rule_eval.next_discriminating_checks,
        }

    # No typed observations available -> abstain safely without restoring legacy conclusions
    new_iteration = state.crag_iterations + 1
    return {
        "crag_iterations": new_iteration,
        "crag_sufficient": False,
        "missing_evidence_hints": [
            "No normalized typed observations were collected for evaluation."
        ],
    }


def route_crag_gate(state: InvestigationState) -> str:
    """Routes the investigation based on evidence sufficiency, backend collector health, and budget limits."""
    # 0. Operational failure: if run deadline exceeded, route to operational_failure
    if state.deadline_timestamp and time.monotonic() > state.deadline_timestamp:
        logger.error("CRAG: Run-wide deadline exceeded -> routing to operational_failure.")
        return "operational_failure"

    # 1. Operational failure: ONLY when collectors hit TOOL_FAILURE with zero non-error observations (never on INVALID_MEASUREMENT!)
    tool_failures = [e for e in state.evidence if e.status == "TOOL_FAILURE"]
    has_non_tool_err = any(e.status in ("SUCCESS", "INVALID_MEASUREMENT") for e in state.evidence)
    if tool_failures and not has_non_tool_err:
        logger.error("CRAG: Telemetry collectors returned TOOL_FAILURE with zero usable observations -> routing to operational_failure.")
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
