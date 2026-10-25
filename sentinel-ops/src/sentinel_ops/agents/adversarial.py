import logging
import time
from typing import Any, Dict, List, Tuple
from sentinel_ops.agents.state import AdversarialVerdict, AtomicClaim, EvidenceItem, InvestigationState
from sentinel_ops.agents.sufficiency import _evidence_in_incident_window
from sentinel_ops.core.config import settings

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
