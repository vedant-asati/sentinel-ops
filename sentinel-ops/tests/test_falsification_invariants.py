import math
import pytest
from benchmarks.baselines.single_pass_llm import SinglePassLLMBaseline
from benchmarks.runner import SentinelOpsLangGraphAgent, load_fixtures
from sentinel_ops.agents.specialists import metrics_specialist_node, trace_specialist_node
from sentinel_ops.agents.supervisor import compute_incident_window
from sentinel_ops.mcp.tempo_adapter import TempoAdapter
from sentinel_ops.mcp.prometheus_adapter import PrometheusAdapter


def test_run_isolation_instance_reuse():
    """P0 Probe: Ensure reusing an agent instance across runs never bleeds previous state."""
    cases = {c["id"]: c for c in load_fixtures()}
    changed = dict(
        cases["case_01"],
        incident_timestamp=cases["case_02"]["incident_timestamp"],
        mock_telemetry=cases["case_02"]["mock_telemetry"],
    )
    
    used = SentinelOpsLangGraphAgent()
    first_res = used.diagnose(cases["case_01"])
    assert first_res["diagnosed_root_cause"] == "payment-service"

    fresh_res = SentinelOpsLangGraphAgent().diagnose(changed)
    second_res = used.diagnose(changed)
    
    # Must diagnose pricing-service on both fresh and reused instances
    assert fresh_res["diagnosed_root_cause"] == "pricing-service"
    assert second_res["diagnosed_root_cause"] == "pricing-service"


@pytest.mark.asyncio
async def test_nan_metric_rejection():
    """P0 Probe: Ensure NaN or non-finite metric values are marked TOOL_FAILURE, never 'normal at nans'."""
    payload = {
        "service": "pricing-service",
        "metric_type": "latency_p95",
        "observation_window": ("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"),
        "simulated_telemetry": {
            "prometheus": {
                "pricing-service": {
                    "latency_p95": {
                        "status": "SUCCESS",
                        "values": [[1795530750, "NaN"]],
                    }
                }
            }
        },
    }
    result = await metrics_specialist_node(payload)
    ev = result["evidence"][0]
    assert ev.status == "TOOL_FAILURE"
    assert "Invalid or non-finite" in ev.finding
    assert "normal" not in ev.finding


@pytest.mark.asyncio
async def test_replay_mode_zero_live_calls():
    """P0 Probe: Missing fixture telemetry in replay mode produces typed EMPTY, zero live calls."""
    payload = {
        "service": "pricing-service",
        "metric_type": "latency_p95",
        "simulated_telemetry": {
            "prometheus": {
                # pricing-service omitted entirely
            }
        },
    }
    result = await metrics_specialist_node(payload)
    ev = result["evidence"][0]
    assert ev.status == "EMPTY"
    assert "not present in replay snapshot" in ev.finding


def test_symptom_only_abstention():
    """P0 Probe: Single memory gauge sample without container restart or trace evidence must ABSTAIN."""
    case = {
        "id": "synthetic_symptom_only",
        "alert_text": "checkout-service reports high memory on cart-service",
        "incident_timestamp": "2026-11-24T14:32:00Z",
        "target_service": "checkout-service",
        "mock_telemetry": {
            "prometheus": {
                "cart-service": {
                    "memory_usage": {
                        "status": "SUCCESS",
                        "values": [[1732468500, "0.95"]],
                    },
                    # NO container_restarts, NO errors
                },
                "payment-service": {
                    "db_pool_active": {"status": "SUCCESS", "values": [[1732468500, "1.0"]]},
                },
                "pricing-service": {
                    "latency_p95": {"status": "SUCCESS", "values": [[1732468500, "0.02"]]},
                },
            },
            # NO tempo traces
        },
    }
    agent = SentinelOpsLangGraphAgent()
    res = agent.diagnose(case)
    # Symptom-only telemetry without crash/termination records must abstain
    assert res["terminal_status"] == "INSUFFICIENT_EVIDENCE"


def test_dynamic_incident_window():
    """P0 Probe: Observation window must be dynamically computed from anchor, not hardcoded."""
    anchor = "2026-12-05T10:00:00Z"
    start, end = compute_incident_window(anchor, before_minutes=2, after_minutes=3)
    assert start == "2026-12-05T09:58:00Z"
    assert end == "2026-12-05T10:03:00Z"


@pytest.mark.asyncio
async def test_trace_exclusive_time_bottleneck():
    """P1 Probe: Tempo bottleneck is determined by exclusive self-time, not root span total time."""
    payload = {
        "target_service": "checkout-service",
        "simulated_telemetry": {
            "tempo": {
                "trace_hierarchy": {
                    "status": "SUCCESS",
                    "spans": [
                        {
                            "span_id": "span_root",
                            "parent_span_id": None,
                            "service": "checkout-service",
                            "duration_ms": 500.0,
                        },
                        {
                            "span_id": "span_child",
                            "parent_span_id": "span_root",
                            "service": "pricing-service",
                            "duration_ms": 450.0,
                        },
                    ],
                }
            }
        },
    }
    res = await trace_specialist_node(payload)
    ev = res["evidence"][0]
    assert ev.status == "SUCCESS"
    # Pricing has 450ms exclusive; Checkout has 500 - 450 = 50ms exclusive
    assert "bottleneck in pricing-service (450.0ms exclusive)" in ev.finding


def test_baseline_observable_telemetry_no_case_id():
    """P1 Probe: SinglePass baseline diagnoses based on telemetry signals, not case ID."""
    cases = {c["id"]: c for c in load_fixtures()}
    c1 = dict(cases["case_01"], id="custom_renamed_case_999")
    baseline = SinglePassLLMBaseline()
    res = baseline.diagnose(c1)
    assert res["diagnosed_root_cause"] == "payment-service"


@pytest.mark.asyncio
async def test_operational_failure_routing_on_all_tool_failures():
    """P1 Probe: When all collectors experience TOOL_FAILURE, graph routes to operational_failure."""
    from sentinel_ops.agents.graph import compile_investigation_graph

    graph = compile_investigation_graph()
    initial_state = {
        "incident_id": "test_crash",
        "alert_text": "checkout-service outage",
        "incident_timestamp": "2026-11-24T14:32:00Z",
        "target_service": "checkout-service",
        "simulated_telemetry": {
            "prometheus": {
                "payment-service": {
                    "db_pool_active": {"status": "TOOL_FAILURE", "error": "503 Service Unavailable"}
                },
                "pricing-service": {
                    "latency_p95": {"status": "TOOL_FAILURE", "error": "503 Service Unavailable"}
                },
            },
            "tempo": {
                "chk-root-trace": {"status": "TOOL_FAILURE", "error": "Connection timeout"}
            },
        },
    }
    config = {"configurable": {"thread_id": "test_op_fail_thread"}}
    res = await graph.ainvoke(initial_state, config=config)
    assert res["terminal_status"] == "OPERATIONAL_FAILURE"
    assert "operational error" in res["terminal_reason"].lower()


def test_capacity_occupancy_distinction():
    """P0 Probe: Active connections must be compared with capacity, not assumed saturated at active=2."""
    from sentinel_ops.agents.specialists import interpret_metric
    
    # Active = 2, Capacity = 100 -> 2% occupancy, NOT saturated
    status, finding, _ = interpret_metric("payment-service", "db_pool_active", [[1795530720, "2.0"]], capacity=100.0)
    assert status == "SUCCESS"
    assert "normal" in finding
    assert "saturated" not in finding
    assert "2% capacity, healthy" in finding

    # Active = 2, Capacity = 2 -> 100% occupancy, SATURATED
    status, finding, _ = interpret_metric("payment-service", "db_pool_active", [[1795530720, "2.0"]], capacity=2.0)
    assert status == "SUCCESS"
    assert "saturated" in finding
    assert "100% capacity exhausted" in finding


def test_evidence_reducer_retry_upgrade():
    """P1 Probe: Evidence reducer must upgrade a failed/empty observation when a retry succeeds."""
    from sentinel_ops.agents.state import EvidenceItem, merge_evidence_items

    existing = [
        EvidenceItem(
            id="EV-prom-paym-db_p",
            backend_source="prometheus",
            query_string="query",
            query_params={"service": "payment-service"},
            observation_window=("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"),
            sample_or_span_ref="db_pool_active",
            finding="Query failed: 503 Service Unavailable",
            raw_payload="",
            status="TOOL_FAILURE",
        )
    ]
    retry_incoming = [
        EvidenceItem(
            id="EV-prom-paym-db_p",
            backend_source="prometheus",
            query_string="query",
            query_params={"service": "payment-service"},
            observation_window=("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"),
            sample_or_span_ref="db_pool_active",
            finding="payment_db_pool_active saturated at 2.0 / 2.0 (100% capacity exhausted)",
            raw_payload="[[1795530720, '2.0']]",
            status="SUCCESS",
        )
    ]
    merged = merge_evidence_items(existing, retry_incoming)
    assert len(merged) == 1
    assert merged[0].status == "SUCCESS"
    assert "saturated" in merged[0].finding


def test_adversarial_semantic_service_mismatch_rejection():
    """P0 Probe: Adversarial reviewer rejects claims that cite evidence from unrelated services."""
    from sentinel_ops.agents.adversarial import adversarial_reviewer_node
    from sentinel_ops.agents.state import AtomicClaim, EvidenceItem, InvestigationState

    cart_evidence = EvidenceItem(
        id="EV-prom-cart-memo",
        backend_source="prometheus",
        query_string="cart_memory",
        query_params={"service": "cart-service"},
        observation_window=("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"),
        sample_or_span_ref="memory_usage",
        finding="cart-service memory_usage critically exhausted at 95%",
        raw_payload="",
        status="SUCCESS",
    )
    # Fraudulent claim: claims payment-service root cause but cites cart-service evidence!
    bad_claim_1 = AtomicClaim(
        claim_id="CL-001",
        statement="payment-service database connection pool exhaustion is root cause",
        claim_type="root_cause",
        cited_evidence_ids=["EV-prom-cart-memo"],
    )
    bad_claim_2 = AtomicClaim(
        claim_id="CL-002",
        statement="payment-service pool saturated",
        claim_type="mechanism",
        cited_evidence_ids=["EV-prom-cart-memo"],
    )
    state = InvestigationState(
        incident_id="fraud_test",
        alert_text="test alert",
        incident_timestamp="2026-11-24T14:32:00Z",
        target_service="checkout-service",
        evidence=[cart_evidence],
        structured_claims=[bad_claim_1, bad_claim_2],
    )
    res = adversarial_reviewer_node(state)
    verdict = res["adversarial_verdict"]
    assert verdict.all_claims_supported is False
    assert any("does not relate to payment-service" in str(ev["reason"]) for ev in verdict.claim_evaluations)


@pytest.mark.asyncio
async def test_deadline_expiration_routes_to_operational_failure():
    """P1 Probe: When shared deadline budget is expired, graph immediately aborts with OPERATIONAL_FAILURE."""
    import time
    from sentinel_ops.agents.graph import compile_investigation_graph

    graph = compile_investigation_graph()
    initial_state = {
        "incident_id": "test_deadline_expired",
        "alert_text": "checkout-service outage",
        "incident_timestamp": "2026-11-24T14:32:00Z",
        "target_service": "checkout-service",
        "deadline_timestamp": time.monotonic() - 1.0,  # Already expired in the past!
        "simulated_telemetry": {
            "prometheus": {
                "payment-service": {"db_pool_active": {"status": "SUCCESS", "values": [[1795530720, "2.0"]]}}
            },
            "tempo": {},
        },
    }
    config = {"configurable": {"thread_id": "test_deadline_thread"}}
    res = await graph.ainvoke(initial_state, config=config)
    assert res["terminal_status"] == "OPERATIONAL_FAILURE"
    assert "deadline" in res["terminal_reason"].lower()


@pytest.mark.asyncio
async def test_p1_1_future_counter_outside_window_abstains():
    """P1.1 Probe: Counter shifted +1h outside incident observation window [T-120s, T+180s] must abstain."""
    from sentinel_ops.agents.graph import compile_investigation_graph

    graph = compile_investigation_graph()
    # Incident window at 14:32:00Z = [1795530600, 1795530900]; +3600s shifted samples = 1795534320/1795534350
    future_state = {
        "incident_id": "test_p1_1_future_counter",
        "alert_text": "Payment DB timeouts",
        "incident_timestamp": "2026-11-24T14:32:00Z",
        "target_service": "checkout-service",
        "simulated_telemetry": {
            "prometheus": {
                "payment-service": {
                    "db_pool_active": {"status": "SUCCESS", "values": [[1795534320, "2.0"], [1795534350, "2.0"]]},
                    "db_pool_size": {"status": "SUCCESS", "values": [[1795534320, "2.0"], [1795534350, "2.0"]]},
                    "db_pool_acquire_timeouts_total": {"status": "SUCCESS", "values": [[1795534320, "2"], [1795534350, "15"]]},
                }
            },
            "tempo": {},
        },
        "crag_iterations": 0,
    }
    res = await graph.ainvoke(future_state, config={"configurable": {"thread_id": "p1_1_future"}})
    assert res["terminal_status"] == "INSUFFICIENT_EVIDENCE"


@pytest.mark.asyncio
async def test_p1_1_missing_requested_trace_id_with_decoy_abstains():
    """P1.1 Probe: Missing requested trace_id must NOT substitute another trace in simulated_telemetry.tempo."""
    from sentinel_ops.agents.graph import compile_investigation_graph

    graph = compile_investigation_graph()
    res = await graph.ainvoke(
        {
            "incident_id": "test_p1_1_missing_trace",
            "alert_text": "Checkout timeout on trace_requested_missing",
            "incident_timestamp": "2026-11-24T14:32:00Z",
            "target_service": "checkout-service",
            "trace_id": "trace_requested_missing",
            "simulated_telemetry": {
                "prometheus": {
                    "payment-service": {
                        "db_pool_active": {"status": "SUCCESS", "values": [[1795530720, "2.0"], [1795530735, "2.0"]]},
                        "db_pool_size": {"status": "SUCCESS", "values": [[1795530720, "2.0"], [1795530735, "2.0"]]},
                        "db_pool_acquire_timeouts_total": {"status": "SUCCESS", "values": [[1795530720, "2"], [1795530735, "11"]]},
                    }
                },
                "tempo": {
                    "trace_decoy_other": {
                        "status": "SUCCESS",
                        "timestamp": 1795530720,
                        "spans": [
                            {"span_id": "r", "parent_span_id": "", "service": "checkout-service", "name": "checkout", "duration_ms": 2000.0},
                            {"span_id": "p", "parent_span_id": "r", "service": "payment-service", "name": "db.connection.acquire", "duration_ms": 1950.0, "error": "TimeoutError"},
                        ],
                    }
                },
            },
            "crag_iterations": 0,
        },
        config={"configurable": {"thread_id": "p1_1_decoy"}},
    )
    assert res["terminal_status"] == "INSUFFICIENT_EVIDENCE"


def test_p1_1_decision_gates_reject_stale_and_wrong_trace_evidence():
    """P1.1 Probe: Direct checks at sufficiency and adversarial decision points reject stale/wrong-trace EvidenceItems."""
    from sentinel_ops.agents.sufficiency import crag_sufficiency_node
    from sentinel_ops.agents.adversarial import adversarial_reviewer_node
    from sentinel_ops.agents.state import AtomicClaim, EvidenceItem, InvestigationState

    stale_ev = EvidenceItem(
        id="EV-prom-stale",
        backend_source="prometheus",
        query_string="payment_db_pool_active",
        query_params={"service": "payment-service", "metric_type": "db_pool_active"},
        observation_window=("2026-11-24T15:30:00Z", "2026-11-24T15:35:00Z"),
        sample_or_span_ref="db_pool_active",
        finding="saturated at 2.0 / 2.0",
        raw_payload="2.0",
        status="SUCCESS",
    )
    stale_wait = EvidenceItem(
        id="EV-prom-stale-wait",
        backend_source="prometheus",
        query_string="payment_db_pool_acquire_timeouts_total",
        query_params={"service": "payment-service", "metric_type": "db_pool_acquire_timeouts_total"},
        observation_window=("2026-11-24T15:30:00Z", "2026-11-24T15:35:00Z"),
        sample_or_span_ref="db_pool_acquire_timeouts_total",
        finding="+10 acquire timeouts",
        raw_payload="10",
        status="SUCCESS",
    )
    decoy_trace = EvidenceItem(
        id="EV-tempo-wrong",
        backend_source="tempo",
        query_string="trace_wrong",
        query_params={"target_service": "checkout-service", "trace_id": "trace_wrong"},
        observation_window=("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"),
        sample_or_span_ref="span_waterfall",
        finding="TimeoutError in payment-service on db.connection.acquire",
        raw_payload="...",
        status="SUCCESS",
    )
    state = InvestigationState(
        incident_id="gate_reject",
        alert_text="Timeout",
        incident_timestamp="2026-11-24T14:32:00Z",
        target_service="checkout-service",
        trace_id="trace_expected",
        evidence=[stale_ev, stale_wait, decoy_trace],
        structured_claims=[
            AtomicClaim(claim_id="CL-1", statement="payment-service db_pool_exhaustion", claim_type="root_cause", cited_evidence_ids=["EV-prom-stale"])
        ],
    )
    suff_res = crag_sufficiency_node(state)
    assert suff_res["crag_sufficient"] is False
    adv_res = adversarial_reviewer_node(state)
    assert adv_res["adversarial_verdict"].all_claims_supported is False
