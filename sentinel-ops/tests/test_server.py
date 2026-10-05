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
