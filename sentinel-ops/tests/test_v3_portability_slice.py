"""Stage 2 Portability Proof: Config-Only Onboarding of Non-Commerce SystemProfile.

Proves that onboarding an external service topology (`document-api -> render-worker -> storage-api`)
with different service names, metric names, labels (`app=...`), and span operations (`pdf.pool.checkout`)
works end-to-end via SystemProfile configuration alone without Python edits.
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch
import pytest

from sentinel_ops.agents.graph import compile_investigation_graph
from sentinel_ops.cli import run_triage
from sentinel_ops.memory.graph_rag import TopologyGraphRAG
from sentinel_ops.profiles.registry import get_profile


@pytest.mark.asyncio
async def test_document_pipeline_positive_pool_acquisition_timeout_config_only():
    """Config-only external profile diagnoses `render-worker` pool acquisition timeout with native citations."""
    profile = get_profile("document-pipeline")
    assert "document-api" in profile.services
    assert "render-worker" in profile.services

    graph = compile_investigation_graph()
    tid = "f" * 32
    state = await graph.ainvoke(
        {
            "incident_id": "doc_pos_01",
            "profile_id": "document-pipeline",
            "alert_text": f"Document conversion API stalling on {tid}",
            "incident_timestamp": "2026-11-24T16:00:00Z",
            "target_service": "document-api",
            "trace_id": tid,
            "simulated_telemetry": {
                "prometheus": {
                    "render-worker": {
                        "worker_pool_busy": {
                            "status": "SUCCESS",
                            "result": [{"metric": {"app": "render-worker", "pod": "rw-0"}, "values": [[1795536000, "16"], [1795536015, "16"]]}],
                        },
                        "worker_pool_max": {
                            "status": "SUCCESS",
                            "result": [{"metric": {"app": "render-worker", "pod": "rw-0"}, "values": [[1795536000, "16"], [1795536015, "16"]]}],
                        },
                        "worker_pool_wait_timeouts_total": {
                            "status": "SUCCESS",
                            "result": [{"metric": {"app": "render-worker", "pod": "rw-0"}, "values": [[1795536000, "3"], [1795536015, "14"]]}],
                        },
                    }
                },
                "tempo": {
                    tid: {
                        "status": "SUCCESS",
                        "timestamp": 1795536015,
                        "spans": [
                            {"span_id": "r", "parent_span_id": "", "service": "document-api", "name": "POST /render", "duration_ms": 4200.0},
                            {"span_id": "w", "parent_span_id": "r", "service": "render-worker", "name": "pdf.pool.checkout", "duration_ms": 4150.0, "error": "TimeoutError"},
                        ],
                    }
                },
            },
            "crag_iterations": 0,
        },
        config={"configurable": {"thread_id": "doc_pos_01"}},
    )

    assert state["terminal_status"] == "SUPPORTED_DIAGNOSIS"
    assert state["mechanism"] == "pool_acquisition_timeout"
    assert state["rule_evaluation"]["root_cause_service"] == "render-worker"
    assert "document-api" in state["affected_callers"]
    assert "WORKER_POOL_SIZE" in (state.get("recommended_runbook_action") or "")
    root_claim = next(c for c in state["structured_claims"] if c.claim_type == "root_cause")
    assert "render-worker" in root_claim.statement
    assert len(root_claim.cited_evidence_ids) >= 2


@pytest.mark.asyncio
async def test_document_pipeline_busy_without_waits_abstains_with_localization():
    """Config-only busy pool without wait timeout delta must abstain while localizing render-worker."""
    graph = compile_investigation_graph()
    tid = "1" * 32
    state = await graph.ainvoke(
        {
            "incident_id": "doc_neg_busy",
            "profile_id": "document-pipeline",
            "alert_text": f"Document conversion slow on {tid}",
            "incident_timestamp": "2026-11-24T16:00:00Z",
            "target_service": "document-api",
            "trace_id": tid,
            "simulated_telemetry": {
                "prometheus": {
                    "render-worker": {
                        "worker_pool_busy": {"status": "SUCCESS", "result": [{"metric": {"pod": "rw-0"}, "values": [[1795536000, "16"], [1795536015, "16"]]}]},
                        "worker_pool_max": {"status": "SUCCESS", "result": [{"metric": {"pod": "rw-0"}, "values": [[1795536000, "16"], [1795536015, "16"]]}]},
                        "worker_pool_wait_timeouts_total": {"status": "SUCCESS", "result": [{"metric": {"pod": "rw-0"}, "values": [[1795536000, "3"], [1795536015, "3"]]}]},
                    }
                },
                "tempo": {
                    tid: {
                        "status": "SUCCESS",
                        "timestamp": 1795536015,
                        "spans": [
                            {"span_id": "r", "parent_span_id": "", "service": "document-api", "name": "POST /render", "duration_ms": 2200.0},
                            {"span_id": "w", "parent_span_id": "r", "service": "render-worker", "name": "pdf.pool.checkout", "duration_ms": 2150.0},
                        ],
                    }
                },
            },
            "crag_iterations": 0,
        },
        config={"configurable": {"thread_id": "doc_neg_busy"}},
    )

    assert state["terminal_status"] == "INSUFFICIENT_EVIDENCE"
    assert state["localized_dependency"]["bottleneck_service"] == "render-worker"
    assert any("render-worker" in chk for chk in state["next_discriminating_checks"])


@pytest.mark.asyncio
async def test_document_pipeline_live_adapter_uses_profile_promql_and_services():
    """Live PrometheusAdapter accepts native render-worker service and custom worker_pool PromQL template."""
    from sentinel_ops.agents.specialists import metrics_specialist_node

    captured_calls = []

    async def fake_query_metric(service, metric_type, window, **kwargs):
        captured_calls.append((service, metric_type, kwargs))
        promql = kwargs.get("promql_templates", {}).get(metric_type, "")
        if metric_type == "worker_pool_busy":
            return {
                "status": "SUCCESS",
                "promql": promql.format(service=service),
                "result": [{"metric": {"app": service, "pod": "rw-1"}, "values": [[1795536000, "8"], [1795536015, "8"]]}],
            }
        if metric_type == "worker_pool_max":
            return {
                "status": "SUCCESS",
                "promql": promql.format(service=service),
                "result": [{"metric": {"app": service, "pod": "rw-1"}, "values": [[1795536000, "8"], [1795536015, "8"]]}],
            }
        return {"status": "EMPTY", "promql": metric_type, "result": []}

    mock_adapter = AsyncMock()
    mock_adapter.query_metric = AsyncMock(side_effect=fake_query_metric)

    with patch("sentinel_ops.agents.specialists.get_prometheus_adapter", return_value=mock_adapter):
        res = await metrics_specialist_node({
            "profile_id": "document-pipeline",
            "service": "render-worker",
            "metric_type": "worker_pool_busy",
            "observation_window": ("2026-11-24T15:58:00Z", "2026-11-24T16:03:00Z"),
            "incident_timestamp": "2026-11-24T16:00:00Z",
        })

    assert len(captured_calls) == 2
    assert captured_calls[0][0] == "render-worker"
    assert "render-worker" in captured_calls[0][2]["allowed_services"]
    assert res["observations"][0].value == 1.0
    assert res["observations"][0].join_status == "label_joined"
    assert "saturated" in res["evidence"][0].finding


def test_profile_preflight_graphrag_isolation_and_cli_intake():
    """Preflight distinguishes SUPPORTED vs LOCALIZATION_ONLY vs UNSUPPORTED, and GraphRAG isolates profiles."""
    doc_profile = get_profile("document-pipeline")
    full_pf = doc_profile.preflight()
    assert full_pf["pool_acquisition_timeout"].status == "SUPPORTED"

    degraded_pf = doc_profile.preflight(available_signals={"latency_p95", "render_latency_p95"})
    assert degraded_pf["pool_acquisition_timeout"].status == "LOCALIZATION_ONLY"
    assert "worker_pool_wait_timeouts_total" not in degraded_pf["pool_acquisition_timeout"].missing_signals
    assert "pool_acquire_timeouts" in degraded_pf["pool_acquisition_timeout"].missing_signals

    rag = TopologyGraphRAG(profile=doc_profile)
    assert rag.retrieve("checkout payment db pool", "document-api", "2026-11-24T16:00:00Z") == []

    cli_pf = run_triage(profile_id="document-pipeline", preflight=True)
    assert cli_pf["profile_id"] == "document-pipeline"
    assert cli_pf["preflight"]["pool_acquisition_timeout"]["status"] == "SUPPORTED"
