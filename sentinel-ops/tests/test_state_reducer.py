from sentinel_ops.agents.state import EvidenceItem, merge_evidence_items


def test_merge_evidence_deduplicates_by_id():
    """Verifies that concurrent parallel writes to evidence merge cleanly without duplicate IDs."""
    existing = [
        EvidenceItem(
            id="EV-001",
            backend_source="prometheus",
            query_string="query_promql",
            query_params={"service": "payment-service"},
            observation_window=("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"),
            sample_or_span_ref="payment_db_pool_active",
            finding="Pool is saturated at 2 connections",
            raw_payload="[[1732458720, '2.0']]",
            status="SUCCESS",
        )
    ]
    
    # Incoming batch with 1 existing ID (duplicate) and 1 new ID
    incoming = [
        EvidenceItem(
            id="EV-001", # Duplicate
            backend_source="prometheus",
            query_string="query_promql",
            query_params={"service": "payment-service"},
            observation_window=("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"),
            sample_or_span_ref="payment_db_pool_active",
            finding="Duplicate entry",
            raw_payload="...",
            status="SUCCESS",
        ),
        EvidenceItem(
            id="EV-002", # New
            backend_source="tempo",
            query_string="trace_chk_01",
            query_params={"service": "payment-service"},
            observation_window=("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"),
            sample_or_span_ref="span_123",
            finding="Payment span took 4120ms",
            raw_payload="...",
            status="SUCCESS",
        )
    ]

    merged = merge_evidence_items(existing, incoming)

    assert len(merged) == 2
    assert [item.id for item in merged] == ["EV-001", "EV-002"]
    assert merged[0].finding == "Pool is saturated at 2 connections"
