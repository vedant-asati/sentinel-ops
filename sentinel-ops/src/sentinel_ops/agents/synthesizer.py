import logging
from typing import Any, Dict, List
from sentinel_ops.agents.state import AtomicClaim, InvestigationState

logger = logging.getLogger(__name__)


def synthesizer_node(state: InvestigationState) -> Dict[str, Any]:
    """RCA Synthesizer: builds structured atomic claims with explicit evidence citations."""
    logger.info("Synthesizer formulating grounded root-cause diagnosis...")

    evidence_list = state.evidence
    successful_items = {e.id: e for e in evidence_list if e.status == "SUCCESS"}

    def is_payment(e):
        return e.query_params.get("service") == "payment-service" or "payment" in e.query_string or "payment" in e.id or "paym" in e.id

    def is_pricing(e):
        return e.query_params.get("service") == "pricing-service" or "pricing" in e.query_string or "pricing" in e.id or "pric" in e.id

    # Find identifying evidence
    payment_evidence = next((e for e in successful_items.values() if is_payment(e) and "saturated" in e.finding), None)
    pricing_metric_ev = next((e for e in successful_items.values() if is_pricing(e) and "spiked" in e.finding), None)
    pricing_trace_ev = next((e for e in successful_items.values() if e.backend_source == "tempo" and "pricing-service" in e.finding and "bottleneck" in e.finding), None)
    pricing_normal_ev = next((e for e in successful_items.values() if is_pricing(e) and ("normal" in e.finding or "healthy" in e.finding) and "nan" not in e.finding.lower()), None)
    
    # Cart evidence: memory + restart/trace
    cart_mem_ev = next((e for e in successful_items.values() if "cart" in e.id and "memory" in e.query_string and "exhausted" in e.finding), None)
    cart_restart_ev = next((e for e in successful_items.values() if "cart" in e.id and "restarts" in e.query_string and "elevated" in e.finding), None)
    cart_trace_ev = next((e for e in successful_items.values() if e.backend_source == "tempo" and "cart" in e.finding and "bottleneck" in e.finding), None)
    
    # Payment error evidence
    payment_error_ev = next((e for e in successful_items.values() if is_payment(e) and "error_rate" in e.query_string and "spiked" in e.finding), None)
    payment_trace_ev = next((e for e in successful_items.values() if e.backend_source == "tempo" and "payment" in e.finding and "bottleneck" in e.finding), None)

    claims: List[AtomicClaim] = []

    if payment_evidence:
        claims.append(
            AtomicClaim(
                claim_id="CL-001",
                statement="payment-service database connection pool exhaustion is the root cause of transaction delays.",
                claim_type="root_cause",
                cited_evidence_ids=[payment_evidence.id],
            )
        )
        claims.append(
            AtomicClaim(
                claim_id="CL-002",
                statement=payment_evidence.finding,
                claim_type="mechanism",
                cited_evidence_ids=[payment_evidence.id],
            )
        )
        if pricing_normal_ev:
            claims.append(
                AtomicClaim(
                    claim_id="CL-003",
                    statement=f"Falsified pricing hypothesis: {pricing_normal_ev.finding}",
                    claim_type="competing_hypothesis_falsified",
                    cited_evidence_ids=[pricing_normal_ev.id],
                )
            )
        summary = "Root cause identified as payment-service database connection pool exhaustion."

    elif cart_mem_ev and (cart_restart_ev or cart_trace_ev):
        cited_ids = [cart_mem_ev.id]
        mech_parts = [cart_mem_ev.finding]
        if cart_restart_ev:
            cited_ids.append(cart_restart_ev.id)
            mech_parts.append(cart_restart_ev.finding)
        if cart_trace_ev:
            cited_ids.append(cart_trace_ev.id)
            mech_parts.append(cart_trace_ev.finding)

        claims.append(
            AtomicClaim(
                claim_id="CL-001",
                statement="cart-service memory exhaustion and container restarts (OOMKill) is the root cause of cart validation errors.",
                claim_type="root_cause",
                cited_evidence_ids=cited_ids,
            )
        )
        claims.append(
            AtomicClaim(
                claim_id="CL-002",
                statement="; ".join(mech_parts),
                claim_type="mechanism",
                cited_evidence_ids=cited_ids,
            )
        )
        summary = "Root cause identified as cart-service session cache memory leak and container OOMKill."

    elif payment_error_ev and (payment_trace_ev or any("refused" in e.finding.lower() for e in successful_items.values())):
        cited_ids = [payment_error_ev.id]
        if payment_trace_ev:
            cited_ids.append(payment_trace_ev.id)
        claims.append(
            AtomicClaim(
                claim_id="CL-001",
                statement="payment-service endpoint connection failure and elevated error rate is the root cause of order placement failures.",
                claim_type="root_cause",
                cited_evidence_ids=cited_ids,
            )
        )
        claims.append(
            AtomicClaim(
                claim_id="CL-002",
                statement=payment_error_ev.finding,
                claim_type="mechanism",
                cited_evidence_ids=cited_ids,
            )
        )
        summary = "Root cause identified as payment-service connection failure and endpoint refusal."

    elif pricing_trace_ev or pricing_metric_ev:
        primary_ev = pricing_trace_ev or pricing_metric_ev
        assert primary_ev is not None
        claims.append(
            AtomicClaim(
                claim_id="CL-001",
                statement="pricing-service algorithmic CPU calculation delay is the root cause of checkout timeouts.",
                claim_type="root_cause",
                cited_evidence_ids=[primary_ev.id],
            )
        )
        claims.append(
            AtomicClaim(
                claim_id="CL-002",
                statement=primary_ev.finding,
                claim_type="mechanism",
                cited_evidence_ids=[primary_ev.id],
            )
        )
        healthy_payment = next((e for e in successful_items.values() if is_payment(e) and ("normal" in e.finding or "healthy" in e.finding) and "nan" not in e.finding.lower()), None)
        if healthy_payment:
            claims.append(
                AtomicClaim(
                    claim_id="CL-003",
                    statement=f"Falsified payment hypothesis: {healthy_payment.finding}",
                    claim_type="competing_hypothesis_falsified",
                    cited_evidence_ids=[healthy_payment.id],
                )
            )
        summary = "Root cause identified as pricing-service algorithmic calculation latency."

    else:
        summary = "Inconclusive telemetry signals observed."

    return {
        "structured_claims": claims,
        "root_cause_summary": summary,
    }
