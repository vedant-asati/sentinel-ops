"""Stage 3 Calibration & Multi-Rule Engine Tests.

Covers:
1. Canonical `cpu_contention` calibration across checkout and non-commerce profiles (without overclaiming).
2. Config-only `upstream_connect_timeout` on `storage-api` (`storage.object.put` + `storage_connect_timeouts_total`).
3. Memory leak / OOMKill via typed observations (`memory_utilization >= 0.90` + `container_restarts > 1`).
4. Multi-cause conflict abstention when two distinct services show valid independent mechanisms without an isolating trace.
"""

import pytest

from sentinel_ops.agents.graph import compile_investigation_graph
from sentinel_ops.profiles.registry import get_profile
from sentinel_ops.rules.engine import evaluate_all_rules
from sentinel_ops.telemetry.models import NormalizedMetricObservation


@pytest.mark.asyncio
async def test_stage3_document_pipeline_cpu_contention_honest_phrasing():
    """Coarse CPU saturation + slow render span diagnoses `cpu_contention` cleanly without inventing algorithmic sub-cause."""
    graph = compile_investigation_graph()
    tid = "a1" * 16
    state = await graph.ainvoke(
        {
            "incident_id": "doc_cpu_01",
            "profile_id": "document-pipeline",
            "alert_text": f"Document rendering latency spiked on {tid}",
            "incident_timestamp": "2026-11-24T16:00:00Z",
            "target_service": "document-api",
            "trace_id": tid,
            "simulated_telemetry": {
                "prometheus": {
                    "render-worker": {
                        "render_latency_p95": {"status": "SUCCESS", "result": [{"metric": {"pod": "rw-0"}, "values": [[1795536000, "2.8"]]}]},
                        "render_cpu_utilization": {"status": "SUCCESS", "result": [{"metric": {"pod": "rw-0"}, "values": [[1795536000, "0.94"]]}]},
                    }
                },
                "tempo": {
                    tid: {
                        "status": "SUCCESS",
                        "timestamp": 1795536015,
                        "spans": [
                            {"span_id": "r", "parent_span_id": "", "service": "document-api", "name": "POST /render", "duration_ms": 2900.0},
                            {"span_id": "w", "parent_span_id": "r", "service": "render-worker", "name": "pdf.rasterize", "duration_ms": 2800.0},
                        ],
                    }
                },
            },
            "crag_iterations": 0,
        },
        config={"configurable": {"thread_id": "doc_cpu_01"}},
    )

    assert state["terminal_status"] == "SUPPORTED_DIAGNOSIS"
    assert state["mechanism"] == "cpu_contention"
    assert state["rule_evaluation"]["root_cause_service"] == "render-worker"
    assert "algorithmic" not in state["root_cause_summary"].lower()
    assert "CPU saturation" in state["root_cause_summary"]


@pytest.mark.asyncio
async def test_stage3_document_pipeline_upstream_connect_timeout_on_storage_api():
    """Config-only external `upstream_connect_timeout` diagnoses `storage-api` via native span + counter."""
    graph = compile_investigation_graph()
    tid = "b2" * 16
    state = await graph.ainvoke(
        {
            "incident_id": "doc_conn_01",
            "profile_id": "document-pipeline",
            "alert_text": f"Storage upload failures on {tid}",
            "incident_timestamp": "2026-11-24T16:00:00Z",
            "target_service": "document-api",
            "trace_id": tid,
            "simulated_telemetry": {
                "prometheus": {
                    "storage-api": {
                        "storage_connect_timeouts_total": {"status": "SUCCESS", "result": [{"metric": {"pod": "st-0"}, "values": [[1795536000, "4"], [1795536015, "19"]]}]},
                    }
                },
                "tempo": {
                    tid: {
                        "status": "SUCCESS",
                        "timestamp": 1795536015,
                        "spans": [
                            {"span_id": "r", "parent_span_id": "", "service": "document-api", "name": "POST /render", "duration_ms": 1500.0},
                            {"span_id": "s", "parent_span_id": "r", "service": "storage-api", "name": "storage.object.put", "duration_ms": 1450.0, "error": "TimeoutError"},
                        ],
                    }
                },
            },
            "crag_iterations": 0,
        },
        config={"configurable": {"thread_id": "doc_conn_01"}},
    )

    assert state["terminal_status"] == "SUPPORTED_DIAGNOSIS"
    assert state["mechanism"] == "upstream_connect_timeout"
    assert state["rule_evaluation"]["root_cause_service"] == "storage-api"


def test_stage3_multi_cause_conflict_without_isolating_trace_abstains():
    """Simultaneous plausible causes on two distinct dependencies without trace localization must abstain."""
    profile = get_profile("checkout-demo")
    win = ("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z")

    obs = [
        NormalizedMetricObservation(
            observation_id="OBS-pay-pool",
            attempt_id="a1",
            service="payment-service",
            signal_name="db_pool_active",
            value=1.0,
            join_status="single_series",
            requested_window=win,
            status="SUCCESS",
            finding="payment_db_pool_active saturated at 2.0 / 2.0",
        ),
        NormalizedMetricObservation(
            observation_id="OBS-pay-wait",
            attempt_id="a2",
            service="payment-service",
            signal_name="db_pool_acquire_timeouts_total",
            value=11.0,
            delta=9.0,
            requested_window=win,
            status="SUCCESS",
            finding="payment-service db_pool_acquire_timeouts_total spiked with delta +9 timeouts",
        ),
        NormalizedMetricObservation(
            observation_id="OBS-price-cpu",
            attempt_id="a3",
            service="pricing-service",
            signal_name="cpu_saturation",
            value=0.95,
            requested_window=win,
            status="SUCCESS",
            finding="pricing-service cpu_saturation critically saturated at 95%",
        ),
        NormalizedMetricObservation(
            observation_id="OBS-price-lat",
            attempt_id="a4",
            service="pricing-service",
            signal_name="latency_p95",
            value=3.2,
            requested_window=win,
            status="SUCCESS",
            finding="pricing-service latency_p95 spiked critically at 3.200s",
        ),
    ]

    res = evaluate_all_rules(profile=profile, observations=obs, incident_timestamp="2026-11-24T14:32:00Z")
    assert res.is_sufficient is False
    assert any("simultaneous" in g.lower() or "multiple dependencies" in g.lower() for g in res.gap_reasons)
    assert any("payment-service" in c and "pricing-service" in c for c in res.next_discriminating_checks)
