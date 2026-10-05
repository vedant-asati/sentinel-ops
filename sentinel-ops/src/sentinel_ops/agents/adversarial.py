import logging
from typing import Any, Dict
from sentinel_ops.agents.state import AdversarialVerdict, InvestigationState
from sentinel_ops.core.config import settings

logger = logging.getLogger(__name__)


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
            elif evidence_map[eid].status != "SUCCESS":
                invalid_citations.append(f"{eid} has non-SUCCESS status '{evidence_map[eid].status}'")

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

    critique = None if all_supported else "One or more claims cite inconclusive or failed evidence."
    verdict = AdversarialVerdict(
        all_claims_supported=all_supported,
        confidence=0.95 if all_supported else 0.10,
        claim_evaluations=claim_evals,
        critique_hint=critique,
    )

    return {
        "adversarial_iterations": state.adversarial_iterations + 1,
        "adversarial_verdict": verdict,
    }


def route_adversarial_review(state: InvestigationState) -> str:
    """Routes based on adversarial verdict and safety limits."""
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
