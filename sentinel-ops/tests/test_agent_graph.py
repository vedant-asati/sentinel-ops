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

    initial_state = {
        "incident_id": "test_case_01",
        "alert_text": "checkout-service p95 latency spike",
        "incident_timestamp": "2026-11-24T14:32:00Z",
        "target_service": "checkout-service",
        "simulated_telemetry": {
            "prometheus": {
                "payment-service": {
                    "db_pool_active": {"status": "SUCCESS", "values": [[1795530720, "2.0"], [1795530735, "2.0"]]},
                    "db_pool_size": {"status": "SUCCESS", "values": [[1795530720, "2.0"], [1795530735, "2.0"]]},
                    "db_pool_acquire_timeouts_total": {"status": "SUCCESS", "values": [[1795530720, "2"], [1795530750, "11"]]},
                },
                "pricing-service": {
                    "latency_p95": {"status": "SUCCESS", "values": [[1795530720, "0.025"], [1795530735, "0.024"]]},
                },
            },
            "tempo": {
                "trace_chk_01": {
                    "status": "SUCCESS",
                    "timestamp": 1795530735,
                    "bottleneck_service": "payment-service",
                    "bottleneck_duration_ms": 4120.0,
                }
            },
        },
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
async def test_case_02_pricing_latency_localizes_and_abstains_in_pilot_mode():
    """In default pilot mode (pool-timeout family only), CPU latency localizes pricing-service and safely abstains."""
    graph = compile_investigation_graph()

    initial_state = {
        "incident_id": "test_case_02",
        "alert_text": "checkout-service p95 latency spike",
        "incident_timestamp": "2026-11-24T15:10:00Z",
        "target_service": "checkout-service",
        "simulated_telemetry": {
            "prometheus": {
                "payment-service": {
                    "db_pool_active": {"status": "SUCCESS", "values": [[1795533000, "1.0"], [1795533015, "1.0"]]},
                    "db_pool_size": {"status": "SUCCESS", "values": [[1795533000, "100.0"], [1795533015, "100.0"]]},
                },
                "pricing-service": {
                    "latency_p95": {"status": "SUCCESS", "values": [[1795533000, "3.85"], [1795533015, "3.92"]]},
                    "cpu_saturation": {"status": "SUCCESS", "values": [[1795533000, "0.95"], [1795533015, "0.98"]]},
                },
            },
            "tempo": {
                "trace_chk_02": {
                    "status": "SUCCESS",
                    "timestamp": 1795533015,
                    "bottleneck_service": "pricing-service",
                    "bottleneck_duration_ms": 3820.0,
                }
            },
        },
    }

    config = {"configurable": {"thread_id": "thread_case_02"}}
    final_state = await graph.ainvoke(initial_state, config=config)

    assert final_state["terminal_status"] == "INSUFFICIENT_EVIDENCE"
    assert final_state["localized_dependency"]["bottleneck_service"] == "pricing-service"
    assert any("pricing-service" in chk for chk in final_state["next_discriminating_checks"])


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
        "simulated_telemetry": {
            "prometheus": {
                "payment-service": {"db_pool_active": {"status": "EMPTY"}},
            },
            "tempo": {},
        },
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
