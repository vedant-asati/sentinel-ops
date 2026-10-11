import json
import pytest
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient

from sentinel_ops.server.app import app, APPROVAL_LEDGER, load_fixture, FIXTURES_DIR


@pytest.fixture
def client():
    return TestClient(app)


def test_fuzz_remediation_approval_unbounded_memory_leak(client: TestClient):
    """INVARIANT: APPROVAL_LEDGER enforces upper bound (maxsize=1000) to prevent memory DoS."""
    for i in range(1200):
        case_id = f"fuzz_case_{i}"
        resp = client.post(
            f"/api/remediation/{case_id}/approve",
            json={"decision": "approved", "operator_id": "sre_01"},
        )
        assert resp.status_code == 200

    assert len(APPROVAL_LEDGER) <= 1000
    assert "fuzz_case_0" not in APPROVAL_LEDGER
    for i in range(1200):
        APPROVAL_LEDGER.pop(f"fuzz_case_{i}", None)


def test_fuzz_remediation_approval_arbitrary_payload_and_xss(client: TestClient):
    """SECURITY INVARIANT: Reject arbitrary decisions, SQLi operator IDs, and XSS case IDs with 422."""
    xss_payload = "<script>alert(document.cookie)</script>"
    sqli_payload = "' OR 1=1; DROP TABLE ledgers; --"
    case_with_xss = "case_01_<img_src=x_onerror=alert(1)>"

    resp_bad_decision = client.post(
        "/api/remediation/case_01/approve",
        json={"decision": xss_payload, "operator_id": "operator_01"},
    )
    assert resp_bad_decision.status_code == 422

    resp_bad_op = client.post(
        "/api/remediation/case_01/approve",
        json={"decision": "approved", "operator_id": sqli_payload},
    )
    assert resp_bad_op.status_code == 422

    resp_bad_case = client.post(
        f"/api/remediation/{case_with_xss}/approve",
        json={"decision": "approved", "operator_id": "operator_01"},
    )
    assert resp_bad_case.status_code == 422
    assert case_with_xss not in APPROVAL_LEDGER


def test_fixture_case_id_substring_collision():
    """INVARIANT: load_fixture resolves only by exact ID or stem, blocking substring collisions."""
    assert load_fixture("") is None
    assert load_fixture("case") is None
    assert load_fixture("02") is None

    exact = load_fixture("case_02")
    assert exact is not None
    assert exact["id"] == "case_02"


def test_stream_triage_crashes_mid_stream_on_malformed_fixture(client: TestClient, tmp_path: Path):
    """CRITICAL BUG / RUNTIME CRASH:
    If a fixture is loaded that lacks 'alert_text' or contains unexpected types,
    /api/triage/{case_id}/stream sends HTTP 200 headers, then crashes with an unhandled
    KeyError inside the async event_generator.
    Because HTTP 200 was already returned, the SSE connection terminates abruptly and leaves
    the client UI frozen in an indefinite loading state.
    """
    bad_fixture = tmp_path / "case_broken.yaml"
    bad_fixture.write_text("id: case_broken\ntitle: Broken\n", encoding="utf-8")

    with patch("sentinel_ops.server.app.FIXTURES_DIR", tmp_path):
        with client.stream("GET", "/api/triage/case_broken/stream") as resp:
            assert resp.status_code == 200
            lines = list(resp.iter_lines())
            # INVARIANT: Stream gracefully emits error event rather than crashing with unhandled exception
            assert any("error" in line.lower() for line in lines)


@pytest.mark.asyncio
async def test_stream_triage_concurrency_load_starvation():
    """STRESS TEST: Rapid concurrent triage stream calls.
    Verifies that multiple concurrent triage streams can run without deadlock.
    """
    from httpx import ASGITransport, AsyncClient

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Request case_03 which abstains without triggering the NameError bug
        tasks = [ac.get("/api/triage/case_03/stream") for _ in range(5)]
        import asyncio
        responses = await asyncio.gather(*tasks)
        for r in responses:
            assert r.status_code == 200
