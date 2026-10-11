from sentinel_ops.agents.adversarial import validate_claims_and_citations
from sentinel_ops.agents.state import AtomicClaim, EvidenceItem


def test_claim_citation_success():
    evidence = [
        EvidenceItem(
            id="EV-001",
            backend_source="prometheus",
            query_string="db_pool",
            query_params={},
            observation_window=("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"),
            sample_or_span_ref="payment_db_pool_active",
            finding="Pool active = 2 out of 2",
            raw_payload="...",
            status="SUCCESS",
        )
    ]
    claims = [
        AtomicClaim(
            claim_id="CL-001",
            statement="payment-service is the root cause of checkout failure",
            claim_type="root_cause",
            cited_evidence_ids=["EV-001"],
        ),
        AtomicClaim(
            claim_id="CL-002",
            statement="Database connection pool was saturated at 2 connections",
            claim_type="mechanism",
            cited_evidence_ids=["EV-001"],
        ),
    ]

    valid, errs = validate_claims_and_citations(claims, evidence)
    assert valid is True
    assert len(errs) == 0


def test_claim_citation_rejects_empty_or_failed_evidence():
    evidence = [
        EvidenceItem(
            id="EV-002",
            backend_source="tempo",
            query_string="trace_1",
            query_params={},
            observation_window=("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"),
            sample_or_span_ref="span_1",
            finding="No spans found",
            raw_payload="...",
            status="EMPTY",
        )
    ]
    claims = [
        AtomicClaim(
            claim_id="CL-001",
            statement="pricing-service caused latency",
            claim_type="root_cause",
            cited_evidence_ids=["EV-002"], # Invalid because status is EMPTY!
        ),
        AtomicClaim(
            claim_id="CL-002",
            statement="CPU throttling occurred",
            claim_type="mechanism",
            cited_evidence_ids=["EV-002"],
        ),
    ]

    valid, errs = validate_claims_and_citations(claims, evidence)
    assert valid is False
    assert any("status not SUCCESS" in e for e in errs)
