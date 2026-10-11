"""Observability Contract CI Tests.

Verifies that telemetry instrumentation (metrics, histograms, wait counters, OTLP traces)
can strictly distinguish competing root-cause mechanisms without false positives.
"""

import importlib.util
from pathlib import Path
import sys
from unittest.mock import patch
from fastapi.testclient import TestClient
import pytest

from sentinel_ops.agents.graph import compile_investigation_graph
from sentinel_ops.mcp.prometheus_adapter import METRIC_QUERY_TEMPLATES, PrometheusAdapter
from sentinel_ops.mcp.tempo_adapter import analyze_trace_spans, _extract_service_name
from sentinel_ops.agents.specialists import trace_specialist_node


def _load_synthetic_services_module():
    svc_path = Path(__file__).resolve().parents[1] / "deploy" / "synthetic" / "services.py"
    spec = importlib.util.spec_from_file_location("synthetic_services", svc_path)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


def test_prometheus_latency_template_uses_true_histogram_quantile():
    """Contract: latency_p95 PromQL template computes true histogram_quantile, never raw bucket count."""
    template = METRIC_QUERY_TEMPLATES["latency_p95"]
    assert "histogram_quantile(0.95" in template
    assert "db_pool_acquire_timeouts_total" in METRIC_QUERY_TEMPLATES
    assert "upstream_connect_timeouts_total" in METRIC_QUERY_TEMPLATES


def test_synthetic_service_fault_emits_wait_counters_and_histograms():
    """Contract: Fault injection + /work traffic produces wait timeouts and valid cumulative histogram buckets."""
    mod = _load_synthetic_services_module()
    mod.FAULT_STATE["duration_buckets"] = {0.1: 0, 0.5: 0, 1.0: 0, 5.0: 0, "+Inf": 0}
    mod.FAULT_STATE["duration_sum"] = 0.0
    mod.FAULT_STATE["duration_count"] = 0

    with patch.object(mod, "_post_otlp_sync", return_value=True):
        client = TestClient(mod.app)
        resp_inject = client.post("/fault/inject?fault_type=db_pool_exhaustion")
        assert resp_inject.status_code == 200

        resp_work = client.get("/work", headers={"X-Trace-Id": "a" * 32})
        assert resp_work.status_code == 504
        assert resp_work.headers.get("X-Trace-Id") == "a" * 32
        assert resp_work.json()["operation"] == "db.connection.acquire"

        metrics_text = client.get("/metrics").text
        assert "payment_db_pool_acquire_timeouts_total" in metrics_text
        assert 'http_request_duration_seconds_bucket{service=' in metrics_text
        assert 'le="+Inf"' in metrics_text
        assert "http_request_duration_seconds_count" in metrics_text
        assert float(mod.FAULT_STATE["db_pool_acquire_timeouts_total"]) >= 1

        client.post("/fault/inject?fault_type=recover")


def test_otlp_trace_payload_matches_tempo_adapter_contract():
    """Contract: OTLP JSON spans emitted by synthetic service parse cleanly in TempoAdapter helpers."""
    mod = _load_synthetic_services_module()
    otlp = mod.build_otlp_span_payload(
        trace_id="b" * 32,
        span_id="1" * 16,
        parent_span_id="0" * 16,
        service_name="payment-service",
        operation_name="db.connection.acquire",
        start_ns=1_000_000_000,
        end_ns=1_150_000_000,
        error_message="TimeoutError",
    )
    res_span = otlp["resourceSpans"][0]
    svc = _extract_service_name(res_span["resource"]["attributes"])
    assert svc == "payment-service"

    spans = res_span["scopeSpans"][0]["spans"]
    parsed_spans = [
        {
            "span_id": s["spanId"],
            "parent_span_id": s.get("parentSpanId", ""),
            "service": svc,
            "name": s["name"],
            "duration_ms": (int(s["endTimeUnixNano"]) - int(s["startTimeUnixNano"])) / 1_000_000,
            "start_nano": int(s["startTimeUnixNano"]),
            "end_nano": int(s["endTimeUnixNano"]),
            "error": s["status"].get("message") or None,
        }
        for s in spans
    ]
    analysis = analyze_trace_spans(parsed_spans, "b" * 32)
    assert analysis["status"] == "SUCCESS"
    assert analysis["bottleneck_service"] == "payment-service"
    assert analysis["bottleneck_duration_ms"] == 150.0


@pytest.mark.asyncio
async def test_live_and_replay_parity_on_concurrent_span_self_time():
    """Contract: Replay trace specialist and live TempoAdapter share identical exclusive self-time bottleneck math."""
    spans = [
        {"span_id": "root", "parent_span_id": "", "service": "checkout-service", "name": "checkout", "duration_ms": 100.0, "start_nano": 0, "end_nano": 100_000_000},
        {"span_id": "c1", "parent_span_id": "root", "service": "pricing-service", "name": "price", "duration_ms": 60.0, "start_nano": 0, "end_nano": 60_000_000},
        {"span_id": "c2", "parent_span_id": "root", "service": "cart-service", "name": "cart", "duration_ms": 60.0, "start_nano": 0, "end_nano": 60_000_000},
    ]
    adapter_res = analyze_trace_spans(spans, "trace_concurrent")
    # Parallel 0..60ms children leave 40ms exclusive parent time in checkout-service (< 60ms child bottleneck)
    replay_res = await trace_specialist_node({
        "target_service": "checkout-service",
        "trace_id": "trace_concurrent",
        "simulated_telemetry": {
            "tempo": {
                "trace_concurrent": {"status": "SUCCESS", "spans": spans}
            }
        },
    })
    ev = replay_res["evidence"][0]
    assert ev.status == "SUCCESS"
    assert f"bottleneck in {adapter_res['bottleneck_service']} ({adapter_res['bottleneck_duration_ms']:.1f}ms exclusive)" in ev.finding


@pytest.mark.asyncio
async def test_contract_distinguishes_saturated_with_waits_vs_busy_without_waits():
    """Contract: Targeted trace incident distinguishes pool saturation with wait timeouts vs busy pool without waits."""
    graph = compile_investigation_graph()
    tid = "c" * 32
    base_prom = {
        "payment-service": {
            "db_pool_active": {"status": "SUCCESS", "values": [[1795530720, "2.0"], [1795530750, "2.0"]]},
            "db_pool_size": {"status": "SUCCESS", "values": [[1795530720, "2.0"], [1795530750, "2.0"]]},
            "db_pool_acquire_timeouts_total": {"status": "SUCCESS", "values": [[1795530720, "5"], [1795530750, "14"]]},
        }
    }
    base_tempo = {
        tid: {
            "status": "SUCCESS",
            "timestamp": 1795530750,
            "spans": [
                {"span_id": "r", "parent_span_id": None, "service": "checkout-service", "name": "checkout", "duration_ms": 2000.0},
                {"span_id": "p", "parent_span_id": "r", "service": "payment-service", "name": "db.connection.acquire", "duration_ms": 1950.0, "error": "TimeoutError"},
            ],
        }
    }

    # 1. Saturated pool + increasing wait timeouts -> SUPPORTED_DIAGNOSIS
    supported_state = await graph.ainvoke(
        {
            "incident_id": "contract_with_waits",
            "alert_text": f"Checkout timeout trace {tid}",
            "incident_timestamp": "2026-11-24T14:32:30Z",
            "target_service": "checkout-service",
            "trace_id": tid,
            "simulated_telemetry": {"prometheus": base_prom, "tempo": base_tempo},
            "crag_iterations": 0,
        },
        config={"configurable": {"thread_id": "contract_waits_1"}},
    )
    assert supported_state["terminal_status"] == "SUPPORTED_DIAGNOSIS"
    assert supported_state["mechanism"] == "pool_acquisition_timeout"

    # 2. Busy pool (2/2) + flat counter (zero waits) -> must abstain (INSUFFICIENT_EVIDENCE)
    flat_prom = {
        "payment-service": {
            "db_pool_active": {"status": "SUCCESS", "values": [[1795530720, "2.0"], [1795530750, "2.0"]]},
            "db_pool_size": {"status": "SUCCESS", "values": [[1795530720, "2.0"], [1795530750, "2.0"]]},
            "db_pool_acquire_timeouts_total": {"status": "SUCCESS", "values": [[1795530720, "5"], [1795530750, "5"]]},
        }
    }
    abstained_state = await graph.ainvoke(
        {
            "incident_id": "contract_flat_waits",
            "alert_text": f"Checkout timeout trace {tid}",
            "incident_timestamp": "2026-11-24T14:32:30Z",
            "target_service": "checkout-service",
            "trace_id": tid,
            "simulated_telemetry": {"prometheus": flat_prom, "tempo": base_tempo},
            "crag_iterations": 0,
        },
        config={"configurable": {"thread_id": "contract_waits_2"}},
    )
    assert abstained_state["terminal_status"] == "INSUFFICIENT_EVIDENCE"
