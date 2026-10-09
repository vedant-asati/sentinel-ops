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
    changed = dict(cases["case_01"], mock_telemetry=cases["case_02"]["mock_telemetry"])
    
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
                        "values": [[1732468500, "NaN"]],
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
