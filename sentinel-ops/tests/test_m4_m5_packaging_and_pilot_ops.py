"""Milestone M4 & M5 Tests: Packaging, Two-Stage Preflight, Semaphores, Idempotency, Recovery, and Profile-Driven MCP."""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock
from fastapi.testclient import TestClient
import pytest

from sentinel_ops.cli import _probe_live_preflight, run_triage
from sentinel_ops.core.config import settings
from sentinel_ops.mcp.server import handle_jsonrpc_request, list_tools
from sentinel_ops.profiles.registry import BUNDLED_PROFILES_DIR, get_profile
from sentinel_ops.server.app import app, reset_investigation_service
from sentinel_ops.service.runner import InvestigationService
from sentinel_ops.storage.repository import RunRecord, SQLiteRunRepository
from sentinel_ops.telemetry.reader import LiveTelemetryReader


def test_m4_bundled_profiles_packaged_inside_src_and_mapping_preflight():
    """Bundled YAML profiles exist inside src/sentinel_ops/profiles/bundled and Stage 1 flags cumulative ratio mapping."""
    assert (BUNDLED_PROFILES_DIR / "checkout_demo.v1.yaml").is_file()
    assert (BUNDLED_PROFILES_DIR / "document_pipeline.v1.yaml").is_file()

    checkout = get_profile("checkout-demo")
    warnings = checkout.validate_mappings()
    assert any("container_cpu_usage_seconds_total" in w for w in warnings)

    res = run_triage(profile_id="document-pipeline", preflight=True)
    assert res["profile_id"] == "document-pipeline"
    assert res["mapping_warnings"] == []


@pytest.mark.asyncio
async def test_m4_stage2_live_preflight_empty_window_reports_inconclusive(monkeypatch):
    """Empty incident window during Stage 2 live preflight reports inconclusive availability cleanly."""
    from sentinel_ops.mcp import prometheus_adapter, tempo_adapter

    prom_mock = AsyncMock()
    prom_mock.query_metric = AsyncMock(return_value={"status": "EMPTY", "result": []})
    prom_mock.aclose = AsyncMock()
    tempo_mock = AsyncMock()
    tempo_mock.search_traces = AsyncMock(return_value=None)
    tempo_mock.aclose = AsyncMock()

    monkeypatch.setattr(prometheus_adapter, "PrometheusAdapter", lambda: prom_mock)
    monkeypatch.setattr(tempo_adapter, "TempoAdapter", lambda: tempo_mock)

    profile = get_profile("document-pipeline")
    probe = await _probe_live_preflight(profile, "document-api", ("2026-11-24T16:00:00Z", "2026-11-24T16:05:00Z"))
    assert probe["window_inconclusive"] is True
    assert probe["trace_availability"] == "INCONCLUSIVE_EMPTY_WINDOW"


@pytest.mark.asyncio
async def test_m5_live_reader_acquires_backend_semaphore_and_honors_deadline():
    """LiveTelemetryReader acquires backend_semaphores within deadline and aborts cleanly if slot stays held."""
    sem_prom = asyncio.Semaphore(1)
    prom_adapter = AsyncMock()
    prom_adapter.query_metric = AsyncMock(return_value={"status": "EMPTY", "result": []})
    tempo_adapter = AsyncMock()

    reader = LiveTelemetryReader(
        prom_adapter=prom_adapter,
        tempo_adapter=tempo_adapter,
        backend_semaphores={"prometheus": sem_prom, "tempo": asyncio.Semaphore(1)},
    )
    # 1. Held semaphore exhausts tight deadline -> BUDGET_EXCEEDED without blocking indefinitely
    await sem_prom.acquire()
    try:
        import time
        obs, atts = await reader.read_metric(
            service="payment-service",
            metric_type="db_pool_active",
            window=("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"),
            deadline_ts=time.monotonic() + 0.05,
        )
        assert obs[0].status == "TOOL_FAILURE"
        assert atts[0].status == "BUDGET_EXCEEDED"
    finally:
        sem_prom.release()

    # 2. Released semaphore executes cleanly and releases slot
    obs2, atts2 = await reader.read_metric(
        service="payment-service",
        metric_type="db_pool_active",
        window=("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"),
    )
    assert obs2[0].status == "EMPTY"
    assert atts2[0].status == "EMPTY"
    assert not sem_prom.locked()


def test_m5_api_idempotency_conflict_and_sqlite_crash_recovery(tmp_path: Path):
    """Startup recovers abandoned runs; idempotency keys dedupe matching payloads and return 409 on conflict."""
    db_path = tmp_path / "pilot_ops.db"
    repo_pre = SQLiteRunRepository(db_path)
    repo_pre.create_run(RunRecord(
        run_id="crashed_run_1",
        case_id="case_01",
        environment="default",
        profile_id="checkout-demo",
        profile_version="1.0.0",
        status="RUNNING",
        created_at="2026-11-24T14:00:00Z",
    ))

    svc = InvestigationService(repository=SQLiteRunRepository(db_path))
    reset_investigation_service(svc)
    try:
        recovered = svc.repo.get_run("crashed_run_1")
        assert recovered is not None and recovered.status == "FAILED"
        assert any("Interrupted" in str(ev["data"]) for ev in recovered.events)

        client = TestClient(app)
        r1 = client.post("/api/runs", json={"case_id": "case_01", "idempotency_key": "k-123"})
        assert r1.status_code == 202
        rid1 = r1.json()["run_id"]

        r2 = client.post("/api/runs", json={"case_id": "case_01"}, headers={"Idempotency-Key": "k-123"})
        assert r2.status_code == 202
        assert r2.json()["run_id"] == rid1

        conflict = client.post("/api/runs", json={"case_id": "case_03", "idempotency_key": "k-123"})
        assert conflict.status_code == 409
    finally:
        reset_investigation_service(None)


def test_m5_mcp_follows_active_system_profile(monkeypatch):
    """MCP list_tools dynamically reflects active DEFAULT_PROFILE_ID (e.g. document-pipeline)."""
    monkeypatch.setattr(settings, "DEFAULT_PROFILE_ID", "document-pipeline")
    tools = list_tools()
    prom_tool = next(t for t in tools if t["name"] == "promql_range_query")
    assert "render-worker" in prom_tool["parameters"]["properties"]["service"]["enum"]
    assert "worker_pool_busy" in prom_tool["parameters"]["properties"]["metric_type"]["enum"]


@pytest.mark.asyncio
async def test_m5_env_scope_blocks_events_and_cancel(tmp_path: Path, monkeypatch):
    """Cross-environment access is blocked on both SSE event stream and run cancel."""
    monkeypatch.setattr(settings, "SENTINEL_ENV_SCOPE", "staging")
    svc = InvestigationService(repository=SQLiteRunRepository(tmp_path / "env.db"))
    reset_investigation_service(svc)
    try:
        client = TestClient(app)
        created = client.post("/api/runs", json={"case_id": "case_01", "environment": "staging"})
        assert created.status_code == 202
        rid = created.json()["run_id"]

        assert client.get(f"/api/runs/{rid}/events", headers={"X-Sentinel-Env": "prod"}).status_code == 403
        assert client.post(f"/api/runs/{rid}/cancel", headers={"X-Sentinel-Env": "prod"}).status_code == 403
        assert client.post(
            "/api/remediation/case_01/approve",
            json={"decision": "approved", "operator_id": "ops1", "environment": "prod"},
        ).status_code == 403
    finally:
        reset_investigation_service(None)
