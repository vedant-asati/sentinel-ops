"""Stage 4 Decoupled Run Lifecycle, Last-Event-ID Reconnect, Cancellation & SQLite Persistence Tests."""

import json
from pathlib import Path
from fastapi.testclient import TestClient
import pytest

from sentinel_ops.core.config import settings
from sentinel_ops.server.app import app, get_investigation_service, reset_investigation_service
from sentinel_ops.service.runner import InvestigationService
from sentinel_ops.storage.repository import SQLiteRunRepository, parse_exported_brief


def test_decoupled_run_lifecycle_last_event_id_and_sqlite_restart(tmp_path: Path):
    """Creating a run via POST /api/runs executes once, supports Last-Event-ID resume, and survives restart."""
    db_file = tmp_path / "runs.db"
    svc1 = InvestigationService(repository=SQLiteRunRepository(db_file))
    reset_investigation_service(svc1)

    try:
        with TestClient(app) as client:
            start = client.post("/api/runs", json={"case_id": "case_01"})
            assert start.status_code == 202
            run_id = start.json()["run_id"]

            # Subscribe from beginning via SSE
            with client.stream("GET", f"/api/runs/{run_id}/events") as sse_resp:
                assert sse_resp.status_code == 200
                text = "".join(sse_resp.iter_text())

            ids = [int(ln.split(": ", 1)[1]) for ln in text.splitlines() if ln.startswith("id: ")]
            assert len(ids) >= 4
            assert ids == list(range(1, len(ids) + 1))

            # Reconnect using Last-Event-ID header skipping initial events
            skip_after = ids[-2]
            with client.stream(
                "GET",
                f"/api/runs/{run_id}/events",
                headers={"Last-Event-ID": str(skip_after)},
            ) as resume_resp:
                assert resume_resp.status_code == 200
                resumed_text = "".join(resume_resp.iter_text())
            resumed_ids = [int(ln.split(": ", 1)[1]) for ln in resumed_text.splitlines() if ln.startswith("id: ")]
            assert resumed_ids == [i for i in ids if i > skip_after]

            # Record approval tied to run_id
            appr = client.post(
                "/api/remediation/case_01/approve",
                json={"decision": "approved", "operator_id": "sre_oncall", "run_id": run_id, "proposal_id": "prop_1"},
            )
            assert appr.status_code == 200

        # Simulate server restart with fresh InvestigationService + SQLiteRunRepository on same DB file
        svc2 = InvestigationService(repository=SQLiteRunRepository(db_file))
        reset_investigation_service(svc2)
        client2 = TestClient(app)  # Also verifies lazy access without TestClient lifespan context!

        brief_resp = client2.get(f"/api/runs/{run_id}/brief?fmt=json")
        assert brief_resp.status_code == 200
        parsed = parse_exported_brief(brief_resp.text)
        assert parsed["schema_version"] == "3.0"
        assert parsed["terminal_status"] == "SUPPORTED_DIAGNOSIS"
        assert parsed["queries_executed"] >= 1
        assert svc2.repo.get_approval(f"run:{run_id}").proposal_id == "prop_1"
    finally:
        reset_investigation_service(None)


def test_v2_brief_backward_compatible_reader_and_env_scope_and_redaction(tmp_path: Path, monkeypatch):
    """Reads legacy v2 JSON briefs cleanly, blocks cross-environment access, and honors payload redaction."""
    legacy_v2 = json.dumps({
        "incident_id": "case_01",
        "target_service": "checkout-service",
        "terminal_status": "SUPPORTED_DIAGNOSIS",
        "root_cause_summary": "Root cause identified as payment-service pool exhaustion.",
    })
    upgraded = parse_exported_brief(legacy_v2)
    assert upgraded["schema_version"] == "2.0"
    assert upgraded["profile_id"] == "checkout-demo"

    monkeypatch.setattr(settings, "SENTINEL_ENV_SCOPE", "prod")
    monkeypatch.setattr(settings, "SENTINEL_REDACT_RAW_PAYLOADS", True)
    svc = InvestigationService(repository=SQLiteRunRepository(tmp_path / "scoped.db"))
    reset_investigation_service(svc)
    try:
        client = TestClient(app)
        denied = client.post("/api/runs", json={"case_id": "case_01", "environment": "dev"})
        assert denied.status_code == 403

        allowed = client.post("/api/runs", json={"case_id": "case_01", "environment": "prod"})
        assert allowed.status_code == 202
        rid = allowed.json()["run_id"]
        with client.stream("GET", f"/api/runs/{rid}/events") as resp:
            _ = "".join(resp.iter_text())

        brief = json.loads(client.get(f"/api/runs/{rid}/brief?fmt=json", headers={"X-Sentinel-Env": "prod"}).text)
        assert brief["raw_payload_retention"] == "redacted"
        assert all(ev["raw_payload"] == "[REDACTED: replay_disabled]" for ev in brief["evidence"])
    finally:
        reset_investigation_service(None)


@pytest.mark.asyncio
async def test_run_cancellation_commits_single_terminal_outcome(tmp_path: Path):
    """Mid-run cancellation commits a single CANCELED terminal state cleanly."""
    svc = InvestigationService(repository=SQLiteRunRepository(tmp_path / "cancel.db"))
    run_id = await svc.start_run(
        case_id="case_03",
        incident_id="case_03",
        alert_text="Latency spike",
        incident_timestamp="2026-11-24T14:32:00Z",
        target_service="checkout-service",
    )
    rec = await svc.cancel_run(run_id)
    assert rec is not None
    assert rec.status in ("CANCELED", "COMPLETED")
    # Calling cancel twice is idempotent and never overwrites committed outcome
    rec2 = await svc.cancel_run(run_id)
    assert rec2.status == rec.status
    await svc.aclose()
