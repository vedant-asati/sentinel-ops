from sentinel_ops.agents.state import AtomicClaim, EvidenceItem


def validate_claims_and_citations(
    claims: list[AtomicClaim],
    evidence: list[EvidenceItem]
) -> tuple[bool, list[str]]:
    """Enforces atomic claim validation rules from the senior design review."""
    errors = []
    
    # 1. Check claim types
    claim_types = {c.claim_type for c in claims}
    if "root_cause" not in claim_types:
        errors.append("Diagnosis lacks an atomic 'root_cause' claim.")
    if "mechanism" not in claim_types:
        errors.append("Diagnosis lacks an atomic 'mechanism' claim.")

    # 2. Map evidence by ID and status
    successful_ids = {e.id for e in evidence if e.status == "SUCCESS"}
    failed_or_empty_ids = {e.id for e in evidence if e.status != "SUCCESS"}
    all_known_ids = {e.id for e in evidence}

    # 3. Check citations for every claim
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
