import pytest
from sentinel_ops.agents.graph import compile_investigation_graph
from sentinel_ops.agents.state import EvidenceItem, InvestigationState


@pytest.mark.asyncio
async def test_graph_compilation():
    graph = compile_investigation_graph()
    assert graph is not None


@pytest.mark.asyncio
async def test_case_01_payment_db_pool_investigation():
    graph = compile_investigation_graph()

    # Pre-seed simulated payment db pool saturated evidence
    initial_state = {
        "incident_id": "test_case_01",
        "alert_text": "checkout-service p95 latency spike",
        "incident_timestamp": "2026-11-24T14:32:00Z",
        "target_service": "checkout-service",
        "evidence": [
            EvidenceItem(
                id="EV-prom-paym-db_p",
                backend_source="prometheus",
                query_string="payment_db_pool_active",
                query_params={"service": "payment-service"},
                observation_window=("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"),
                sample_or_span_ref="db_pool_active",
                finding="payment_db_pool_active saturated at 2.0 (pool size = 2)",
                raw_payload="[[1732458720, '2.0']]",
                status="SUCCESS",
            ),
            EvidenceItem(
                id="EV-prom-pric-late",
                backend_source="prometheus",
                query_string="pricing_latency_p95",
                query_params={"service": "pricing-service"},
                observation_window=("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"),
                sample_or_span_ref="latency_p95",
                finding="pricing-service latency_p95 normal at 0.024s (healthy)",
                raw_payload="[[1732458720, '0.024']]",
                status="SUCCESS",
            ),
        ],
    }

    config = {"configurable": {"thread_id": "thread_case_01"}}
    final_state = await graph.ainvoke(initial_state, config=config)

    assert final_state["terminal_status"] == "SUPPORTED_DIAGNOSIS"
    assert "payment-service" in final_state["root_cause_summary"]
    assert final_state["adversarial_verdict"].all_claims_supported is True
    assert len(final_state["structured_claims"]) >= 2
    assert final_state["blast_radius_score"] is not None
    assert "checkout-service" in final_state["affected_callers"]


@pytest.mark.asyncio
async def test_case_02_pricing_latency_investigation():
    graph = compile_investigation_graph()

    initial_state = {
        "incident_id": "test_case_02",
        "alert_text": "checkout-service p95 latency spike",
        "incident_timestamp": "2026-11-24T15:10:00Z",
        "target_service": "checkout-service",
        "evidence": [
            EvidenceItem(
                id="EV-prom-paym-db_p",
                backend_source="prometheus",
                query_string="payment_db_pool_active",
                query_params={"service": "payment-service"},
                observation_window=("2026-11-24T15:10:00Z", "2026-11-24T15:15:00Z"),
                sample_or_span_ref="db_pool_active",
                finding="payment_db_pool_active normal at 1.0 (pool size = 100)",
                raw_payload="[[1732461000, '1.0']]",
                status="SUCCESS",
            ),
            EvidenceItem(
                id="EV-tempo-chec",
                backend_source="tempo",
                query_string="trace_chk_02",
                query_params={"target_service": "checkout-service"},
                observation_window=("2026-11-24T15:10:00Z", "2026-11-24T15:15:00Z"),
                sample_or_span_ref="span_waterfall",
                finding="Distributed trace trace_chk_02 waterfall: bottleneck in pricing-service (3820.0ms)",
                raw_payload="{'bottleneck_service': 'pricing-service'}",
                status="SUCCESS",
            ),
        ],
    }

    config = {"configurable": {"thread_id": "thread_case_02"}}
    final_state = await graph.ainvoke(initial_state, config=config)

    assert final_state["terminal_status"] == "SUPPORTED_DIAGNOSIS"
    assert "pricing-service" in final_state["root_cause_summary"]
    assert final_state["adversarial_verdict"].all_claims_supported is True
    assert any(c.claim_type == "competing_hypothesis_falsified" for c in final_state["structured_claims"])


@pytest.mark.asyncio
async def test_case_03_abstention_on_withheld_evidence():
    graph = compile_investigation_graph()

    # Pre-seed empty / failed evidence
    initial_state = {
        "incident_id": "test_case_03",
        "alert_text": "checkout-service p95 latency spike",
        "incident_timestamp": "2026-11-24T16:00:00Z",
        "target_service": "checkout-service",
        "crag_iterations": 2,  # Max retries exhausted
        "evidence": [
            EvidenceItem(
                id="EV-prom-paym-db_p",
                backend_source="prometheus",
                query_string="payment_db_pool_active",
                query_params={"service": "payment-service"},
                observation_window=("2026-11-24T16:00:00Z", "2026-11-24T16:05:00Z"),
                sample_or_span_ref="db_pool_active",
                finding="No db_pool_active metrics returned for payment-service (EMPTY)",
                raw_payload="",
                status="EMPTY",
            ),
        ],
    }

    config = {"configurable": {"thread_id": "thread_case_03"}}
    final_state = await graph.ainvoke(initial_state, config=config)

    assert final_state["terminal_status"] == "INSUFFICIENT_EVIDENCE"
    assert "Abstaining" in final_state["terminal_reason"] or "Refusing" in final_state["terminal_reason"]
