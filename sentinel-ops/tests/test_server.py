import pytest
from fastapi.testclient import TestClient
from sentinel_ops.server.app import app


@pytest.fixture
def client():
    return TestClient(app)


def test_list_incidents(client: TestClient):
    resp = client.get("/api/incidents")
    assert resp.status_code == 200
    data = resp.json()
    assert "incidents" in data
    assert len(data["incidents"]) >= 3


def test_get_dashboard_html(client: TestClient):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "Sentinel-Ops Cyber Command Center" in resp.text
    assert "HUMAN-IN-THE-LOOP APPROVAL GATE" in resp.text


def test_approve_remediation(client: TestClient):
    resp = client.post(
        "/api/remediation/case_01/approve",
        json={"decision": "approved", "operator_id": "test_sre"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "recorded"
    assert data["ledger"]["decision"] == "approved"


def test_get_incident_brief_endpoint(client: TestClient):
    resp_md = client.get("/api/brief/case_01?fmt=markdown")
    assert resp_md.status_code == 200
    assert "# On-Call Incident Brief:" in resp_md.text
    assert "[EV-" in resp_md.text

    resp_json = client.get("/api/brief/case_03?fmt=json")
    assert resp_json.status_code == 200
    assert "INSUFFICIENT_EVIDENCE" in resp_json.text


def test_sse_stream_exports_immutable_run_id_brief(client: TestClient):
    """Contract (P1.5): Export endpoint serves the exact stored run_id investigation without re-running."""
    import json as _json

    with client.stream("GET", "/api/triage/case_01/stream") as resp:
        assert resp.status_code == 200
        body = "".join(resp.iter_text())

    run_id = None
    for line in body.splitlines():
        if line.startswith("data: "):
            payload = _json.loads(line[len("data: "):])
            if "run_id" in payload:
                run_id = payload["run_id"]
                break
    assert run_id, f"Expected run_id in SSE events, got: {body[:300]}"

    brief_json_resp = client.get(f"/api/runs/{run_id}/brief?fmt=json")
    assert brief_json_resp.status_code == 200
    parsed = _json.loads(brief_json_resp.text)
    assert parsed["incident_id"] == "case_01"
    assert isinstance(parsed["evidence"], list) and len(parsed["evidence"]) >= 1
    assert parsed["terminal_status"] == "SUPPORTED_DIAGNOSIS"

    brief_md_resp = client.get(f"/api/brief/case_01?fmt=markdown&run_id={run_id}")
    assert brief_md_resp.status_code == 200
    assert "# On-Call Incident Brief: `case_01`" in brief_md_resp.text

    missing = client.get("/api/runs/nonexistent_run_999/brief?fmt=json")
    assert missing.status_code == 404


def test_mcp_http_endpoint_and_ui_export_buttons(client: TestClient):
    """Contract (Phase B): HTTP POST /mcp exposes all 5 MCP tools and Dashboard exposes brief export buttons."""
    html = client.get("/").text
    assert "EXPORT BRIEF (.MD)" in html
    assert "EXPORT BRIEF (.JSON)" in html
    assert "currentRunId" in html

    resp = client.post("/mcp", json={"jsonrpc": "2.0", "id": 10, "method": "tools/list"})
    assert resp.status_code == 200
    payload = resp.json()
    names = {t["name"] for t in payload["result"]["tools"]}
    assert len(names) == 5
    assert "tempo_search_traces" in names
