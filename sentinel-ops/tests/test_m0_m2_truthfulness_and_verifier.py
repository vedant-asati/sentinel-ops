"""Full-graph regression tests covering Milestones M0, M1, and M2.

Verifies:
- Containment of reviewed false diagnoses (service-label collapse, cross-pod mem/restarts, raw & in-range cumulative CPU).
- Legacy path inability to restore rejected diagnoses.
- Observation revision provenance, attempt_id linking, conflicting revision preservation, exact timestamp ratio joins, and 6-pod truncation disclosure.
- Independent adversarial verifier rejection of forged selector outputs and slow non-timeout span localization.
"""

import json
import pytest

from sentinel_ops.agents.adversarial import adversarial_reviewer_node
from sentinel_ops.agents.graph import compile_investigation_graph
from sentinel_ops.agents.state import AtomicClaim, EvidenceItem, InvestigationState, merge_observations
from sentinel_ops.agents.synthesizer import format_incident_brief
from sentinel_ops.core.config import settings
from sentinel_ops.storage.repository import parse_exported_brief
from sentinel_ops.telemetry.models import NormalizedMetricObservation, NormalizedTraceObservation
from sentinel_ops.telemetry.normalize import normalize_prometheus_response


@pytest.mark.asyncio
async def test_m0_service_label_collapse_cannot_pair_cross_pod_signals():
    """Pod A pool saturation + Pod B acquire timeout carrying redundant service label must abstain across graph, JSON, and Markdown."""
    graph = compile_investigation_graph()
    tid = "a0" * 16
    state = await graph.ainvoke(
        {
            "incident_id": "m0_label_collapse",
            "alert_text": f"Checkout latency spike on {tid}",
            "incident_timestamp": "2026-11-24T14:32:00Z",
            "target_service": "checkout-service",
            "trace_id": tid,
            "use_llm": False,
            "simulated_telemetry": {
                "prometheus": {
                    "payment-service": {
                        "db_pool_active": {
                            "status": "SUCCESS",
                            "result": [{"metric": {"service": "payment-service", "pod": "pay-a"}, "values": [[1795530720, "2"], [1795530735, "2"]]}],
                        },
                        "db_pool_size": {
                            "status": "SUCCESS",
                            "result": [{"metric": {"service": "payment-service", "pod": "pay-a"}, "values": [[1795530720, "2"], [1795530735, "2"]]}],
                        },
                        "db_pool_acquire_timeouts_total": {
                            "status": "SUCCESS",
                            "result": [{"metric": {"service": "payment-service", "pod": "pay-b"}, "values": [[1795530720, "1"], [1795530735, "9"]]}],
                        },
                    }
                },
                "tempo": {
                    tid: {
                        "status": "SUCCESS",
                        "timestamp": 1795530735,
                        "spans": [
                            {"span_id": "r", "parent_span_id": "", "service": "checkout-service", "name": "checkout", "duration_ms": 3000.0},
                            {"span_id": "p", "parent_span_id": "r", "service": "payment-service", "name": "db.connection.acquire", "duration_ms": 2950.0, "error": "TimeoutError"},
                        ],
                    }
                },
            },
        },
        config={"configurable": {"thread_id": "m0_collapse"}},
    )

    assert state["terminal_status"] == "INSUFFICIENT_EVIDENCE"
    assert state.get("recommended_runbook_action") is None
    md = format_incident_brief(state, fmt="markdown")
    js = parse_exported_brief(format_incident_brief(state, fmt="json"))
    assert js["terminal_status"] == "INSUFFICIENT_EVIDENCE"
    assert js["advisory_runbook_action"] is None
    assert "INSUFFICIENT_EVIDENCE" in md


@pytest.mark.asyncio
async def test_m0_pod_a_memory_and_pod_b_flat_restarts_never_certifies(monkeypatch):
    """Pod A 99% memory + Pod B flat cumulative restarts must abstain even if experimental rules are enabled."""
    monkeypatch.setattr(settings, "EXPERIMENTAL_RULES_ENABLED", True)
    graph = compile_investigation_graph()
    state = await graph.ainvoke(
        {
            "incident_id": "m0_mem_restart_split",
            "alert_text": "Cart memory pressure alert",
            "incident_timestamp": "2026-11-24T14:32:00Z",
            "target_service": "checkout-service",
            "use_llm": False,
            "simulated_telemetry": {
                "prometheus": {
                    "cart-service": {
                        "memory_usage": {
                            "status": "SUCCESS",
                            "result": [{"metric": {"pod": "cart-a"}, "values": [[1795530720, "0.98"], [1795530735, "0.99"]]}],
                        },
                        "container_restarts": {
                            "status": "SUCCESS",
                            "result": [{"metric": {"pod": "cart-b"}, "values": [[1795530720, "3"], [1795530735, "3"]]}],
                        },
                    }
                },
                "tempo": {},
            },
        },
        config={"configurable": {"thread_id": "m0_mem_split"}},
    )

    assert state["terminal_status"] == "INSUFFICIENT_EVIDENCE"
    assert state.get("mechanism") is None
    assert state.get("recommended_runbook_action") is None


@pytest.mark.parametrize("raw_cpu_val", ["120.0", "0.4"])
@pytest.mark.asyncio
async def test_m0_cumulative_cpu_seconds_never_renders_as_utilization(raw_cpu_val, monkeypatch):
    """Both out-of-range (120.0) and in-range (0.4) cumulative CPU counters become INVALID_MEASUREMENT, never utilization or TOOL_FAILURE."""
    monkeypatch.setattr(settings, "EXPERIMENTAL_RULES_ENABLED", True)
    graph = compile_investigation_graph()
    state = await graph.ainvoke(
        {
            "incident_id": f"m0_cpu_{raw_cpu_val}",
            "alert_text": "Pricing slow latency",
            "incident_timestamp": "2026-11-24T14:32:00Z",
            "target_service": "checkout-service",
            "use_llm": False,
            "simulated_telemetry": {
                "prometheus": {
                    "pricing-service": {
                        "cpu_saturation": {
                            "status": "SUCCESS",
                            "result": [{"metric": {"container": "pricing-service"}, "values": [[1795530720, raw_cpu_val]]}],
                        },
                        "latency_p95": {
                            "status": "SUCCESS",
                            "result": [{"metric": {"service": "pricing-service"}, "values": [[1795530720, "2.5"]]}],
                        },
                    }
                },
                "tempo": {},
            },
        },
        config={"configurable": {"thread_id": f"m0_cpu_{raw_cpu_val}"}},
    )

    assert state["terminal_status"] == "INSUFFICIENT_EVIDENCE"  # NOT OPERATIONAL_FAILURE!
    cpu_obs = [o for o in state["observations"] if getattr(o, "signal_name", "") == "cpu_saturation"]
    assert cpu_obs and all(o.status == "INVALID_MEASUREMENT" for o in cpu_obs)
    assert "40%" not in " ".join(e.finding for e in state["evidence"])
    assert "12000%" not in " ".join(e.finding for e in state["evidence"])


@pytest.mark.asyncio
async def test_m0_legacy_evidence_path_cannot_restore_rejected_diagnosis():
    """Pre-seeded legacy EvidenceItems claiming saturation cannot override insufficient observations."""
    graph = compile_investigation_graph()
    fake_legacy_ev = [
        EvidenceItem(
            id="EV-prom-paym-db_p",
            backend_source="prometheus",
            query_string="payment_db_pool_active",
            query_params={"service": "payment-service", "metric_type": "db_pool_active"},
            observation_window=("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"),
            sample_or_span_ref="db_pool_active",
            finding="payment_db_pool_active saturated at 2.0 / 2.0",
            raw_payload="2.0",
            status="SUCCESS",
        ),
        EvidenceItem(
            id="EV-prom-paym-db_acq",
            backend_source="prometheus",
            query_string="payment_db_pool_acquire_timeouts_total",
            query_params={"service": "payment-service", "metric_type": "db_pool_acquire_timeouts_total"},
            observation_window=("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"),
            sample_or_span_ref="db_pool_acquire_timeouts_total",
            finding="payment-service db_pool_acquire_timeouts_total spiked with delta +9 timeouts",
            raw_payload="11",
            status="SUCCESS",
        ),
    ]
    state = await graph.ainvoke(
        {
            "incident_id": "m0_legacy_blocked",
            "alert_text": "Checkout slow",
            "incident_timestamp": "2026-11-24T14:32:00Z",
            "target_service": "checkout-service",
            "evidence": fake_legacy_ev,
            "simulated_telemetry": {"prometheus": {}, "tempo": {}},
        },
        config={"configurable": {"thread_id": "m0_legacy"}},
    )
    assert state["terminal_status"] == "INSUFFICIENT_EVIDENCE"


def test_m1_sample_revision_links_identical_attempts_and_preserves_conflicts():
    """Identical observations accumulate attempt_ids; conflicting retries stay distinct side-by-side."""
    win = ("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z")
    obs_a1 = normalize_prometheus_response(
        attempt_id="att_1",
        service="payment-service",
        signal_name="db_pool_acquire_timeouts_total",
        response={"status": "SUCCESS", "result": [{"metric": {"pod": "p0"}, "values": [[1795530720, "1"], [1795530735, "10"]]}]},
        window=win,
    )
    obs_a2_same = normalize_prometheus_response(
        attempt_id="att_2",
        service="payment-service",
        signal_name="db_pool_acquire_timeouts_total",
        response={"status": "SUCCESS", "result": [{"metric": {"pod": "p0"}, "values": [[1795530720, "1"], [1795530735, "10"]]}]},
        window=win,
    )
    obs_a3_conflict = normalize_prometheus_response(
        attempt_id="att_3",
        service="payment-service",
        signal_name="db_pool_acquire_timeouts_total",
        response={"status": "SUCCESS", "result": [{"metric": {"pod": "p0"}, "values": [[1795530720, "1"], [1795530735, "1"]]}]},
        window=win,
    )

    merged_same = merge_observations(obs_a1, obs_a2_same)
    assert len(merged_same) == 1
    assert merged_same[0].attempt_ids == ("att_1", "att_2")

    merged_conflict = merge_observations(merged_same, obs_a3_conflict)
    assert len(merged_conflict) == 2
    assert {o.delta for o in merged_conflict} == {0.0, 9.0}


def test_m1_exact_timestamp_ratio_join_rejects_mismatched_timestamps():
    """Numerator and denominator at different timestamps cannot silently join."""
    win = ("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z")
    obs = normalize_prometheus_response(
        attempt_id="att_ts",
        service="payment-service",
        signal_name="db_pool_active",
        response={"status": "SUCCESS", "result": [{"metric": {"pod": "p0"}, "values": [[1795530720, "2.0"]]}]},
        capacity_response={"status": "SUCCESS", "result": [{"metric": {"pod": "p0"}, "values": [[1795530750, "2.0"]]}]},
        window=win,
    )
    assert len(obs) == 1
    assert obs[0].join_status == "unjoinable"
    assert obs[0].value is None


@pytest.mark.asyncio
async def test_m1_six_pod_truncation_discloses_partial_coverage_and_blocks_fleet_falsification():
    """6-replica response capped at 5 marks coverage=PARTIAL and discloses omission in brief."""
    graph = compile_investigation_graph()
    tid = "b0" * 16
    six_pods = [{"metric": {"service": "pricing-service", "pod": f"p-{i}"}, "values": [[1795530720, "0.02"], [1795530735, "0.02"]]} for i in range(6)]
    six_pods[5]["values"] = [[1795530720, "4.5"], [1795530735, "4.5"]]  # hidden 6th replica slow

    state = await graph.ainvoke(
        {
            "incident_id": "m1_six_pods",
            "alert_text": f"Checkout slow {tid}",
            "incident_timestamp": "2026-11-24T14:32:00Z",
            "target_service": "checkout-service",
            "trace_id": tid,
            "simulated_telemetry": {
                "prometheus": {
                    "pricing-service": {"latency_p95": {"status": "SUCCESS", "result": six_pods}},
                    "payment-service": {
                        "db_pool_active": {"status": "SUCCESS", "result": [{"metric": {"pod": "pay-0"}, "values": [[1795530720, "2"], [1795530735, "2"]]}]},
                        "db_pool_size": {"status": "SUCCESS", "result": [{"metric": {"pod": "pay-0"}, "values": [[1795530720, "2"], [1795530735, "2"]]}]},
                        "db_pool_acquire_timeouts_total": {"status": "SUCCESS", "result": [{"metric": {"pod": "pay-0"}, "values": [[1795530720, "1"], [1795530735, "8"]]}]},
                    },
                },
                "tempo": {
                    tid: {
                        "status": "SUCCESS",
                        "timestamp": 1795530735,
                        "spans": [
                            {"span_id": "r", "parent_span_id": "", "service": "checkout-service", "name": "checkout", "duration_ms": 2000.0},
                            {"span_id": "p", "parent_span_id": "r", "service": "payment-service", "name": "db.connection.acquire", "duration_ms": 1950.0, "error": "TimeoutError"},
                        ],
                    }
                },
            },
        },
        config={"configurable": {"thread_id": "m1_trunc"}},
    )

    assert state["terminal_status"] == "SUPPORTED_DIAGNOSIS"
    # Critical: truncated pricing-service series MUST NOT appear as a falsifying fleet-healthy claim!
    assert not any(c.claim_type == "competing_hypothesis_falsified" for c in state["structured_claims"])
    js = json.loads(format_incident_brief(state, fmt="json"))
    assert js["coverage_status"] == "PARTIAL"
    assert any("5/6" in s for s in js["truncated_series"])


def test_m2_independent_verifier_rejects_forged_slow_trace_claim():
    """Even if selector state is forged, independent verifier rejects affected_request claims lacking a TimeoutError span."""
    win = ("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z")
    tid = "c0" * 16
    cnt_obs = NormalizedMetricObservation(
        observation_id="OBS-cnt",
        attempt_id="a1",
        service="payment-service",
        signal_name="db_pool_acquire_timeouts_total",
        value=9.0,
        delta=5.0,
        sample_timestamps=(1795530720.0, 1795530735.0),
        requested_window=win,
        status="SUCCESS",
        finding="payment-service db_pool_acquire_timeouts_total spiked with delta +5 timeouts",
    )
    slow_only_trace = NormalizedTraceObservation(
        observation_id="OBS-trace",
        attempt_id="a2",
        target_service="checkout-service",
        trace_id=tid,
        trace_timestamp=1795530735.0,
        bottleneck_service="payment-service",
        bottleneck_operation="render_receipt",
        bottleneck_duration_ms=2500.0,
        error_spans=[],
        spans=[{"span_id": "s1", "service": "payment-service", "name": "render_receipt", "duration_ms": 2500.0}],
        requested_window=win,
        status="SUCCESS",
        finding=f"Distributed trace {tid} waterfall: bottleneck in payment-service (2500.0ms exclusive)",
    )
    ev1 = EvidenceItem(
        id="EV-1",
        backend_source="prometheus",
        query_string="cnt",
        query_params={"service": "payment-service", "metric_type": "db_pool_acquire_timeouts_total", "observation_id": "OBS-cnt"},
        observation_window=win,
        sample_or_span_ref="db_pool_acquire_timeouts_total",
        finding=cnt_obs.finding,
        raw_payload="9",
        status="SUCCESS",
    )
    ev2 = EvidenceItem(
        id="EV-2",
        backend_source="tempo",
        query_string=tid,
        query_params={"service": "payment-service", "trace_id": tid, "observation_id": "OBS-trace"},
        observation_window=win,
        sample_or_span_ref="s1",
        finding=slow_only_trace.finding,
        raw_payload="...",
        status="SUCCESS",
    )
    forged_state = InvestigationState(
        incident_id="m2_forged",
        alert_text="slow",
        incident_timestamp="2026-11-24T14:32:00Z",
        target_service="checkout-service",
        trace_id=tid,
        mechanism="pool_acquisition_timeout",
        evidence=[ev1, ev2],
        observations=[cnt_obs, slow_only_trace],
        structured_claims=[
            AtomicClaim(
                claim_id="CL-001",
                statement="payment-service pool_acquisition_timeout is root cause",
                claim_type="root_cause",
                claim_subject=f"payment-service on trace {tid}",
                claim_scope="affected_request",
                cited_evidence_ids=["EV-1", "EV-2"],
            ),
            AtomicClaim(
                claim_id="CL-002",
                statement="pool timeouts + slow trace",
                claim_type="mechanism",
                claim_subject=f"payment-service on trace {tid}",
                claim_scope="affected_request",
                cited_evidence_ids=["EV-1", "EV-2"],
            ),
        ],
    )
    res = adversarial_reviewer_node(forged_state)
    assert res["adversarial_verdict"].all_claims_supported is False


@pytest.mark.asyncio
async def test_m2_slow_receipt_span_with_contention_elsewhere_localizes_and_discriminates():
    """Slow receipt-rendering span on pricing-service while payment-service has pool contention must localize and output discriminating check."""
    graph = compile_investigation_graph()
    tid = "d0" * 16
    state = await graph.ainvoke(
        {
            "incident_id": "m2_slow_receipt",
            "alert_text": f"Checkout slow on {tid}",
            "incident_timestamp": "2026-11-24T14:32:00Z",
            "target_service": "checkout-service",
            "trace_id": tid,
            "simulated_telemetry": {
                "prometheus": {
                    "payment-service": {
                        "db_pool_active": {"status": "SUCCESS", "result": [{"metric": {"pod": "pay-0"}, "values": [[1795530720, "2"], [1795530735, "2"]]}]},
                        "db_pool_size": {"status": "SUCCESS", "result": [{"metric": {"pod": "pay-0"}, "values": [[1795530720, "2"], [1795530735, "2"]]}]},
                        "db_pool_acquire_timeouts_total": {"status": "SUCCESS", "result": [{"metric": {"pod": "pay-0"}, "values": [[1795530720, "1"], [1795530735, "9"]]}]},
                    }
                },
                "tempo": {
                    tid: {
                        "status": "SUCCESS",
                        "timestamp": 1795530735,
                        "spans": [
                            {"span_id": "r", "parent_span_id": "", "service": "checkout-service", "name": "checkout", "duration_ms": 2200.0},
                            {"span_id": "rcpt", "parent_span_id": "r", "service": "pricing-service", "name": "render_receipt", "duration_ms": 2150.0},
                        ],
                    }
                },
            },
        },
        config={"configurable": {"thread_id": "m2_slow_receipt"}},
    )
    assert state["terminal_status"] == "INSUFFICIENT_EVIDENCE"
    assert state["localized_dependency"]["bottleneck_service"] == "pricing-service"
    assert state["localized_dependency"]["bottleneck_operation"] == "render_receipt"
    checks = " ".join(state["next_discriminating_checks"])
    assert "render_receipt" in checks
    assert "payment-service" in checks
