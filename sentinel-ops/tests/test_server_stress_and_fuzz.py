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
    """VULNERABILITY: APPROVAL_LEDGER is an unbounded in-memory dict with no size limit or TTL.
    An attacker can spam unique case_ids to cause memory exhaustion (DoS).
    """
    initial_len = len(APPROVAL_LEDGER)
    for i in range(500):
        case_id = f"fuzz_case_{i}_{'x' * 50}"
        resp = client.post(
            f"/api/remediation/{case_id}/approve",
            json={"decision": "approved", "operator_id": "attacker"},
        )
        assert resp.status_code == 200
    
    assert len(APPROVAL_LEDGER) == initial_len + 500
    assert f"fuzz_case_0_{'x' * 50}" in APPROVAL_LEDGER


def test_fuzz_remediation_approval_arbitrary_payload_and_xss(client: TestClient):
    """VULNERABILITY: No input validation on 'decision' or 'operator_id'.
    Accepts arbitrary malicious strings, SQL-like syntax, and XSS payloads into server state.
    """
    xss_payload = "<script>alert(document.cookie)</script>"
    sqli_payload = "' OR 1=1; DROP TABLE ledgers; --"
    case_with_xss = "case_01_<img_src=x_onerror=alert(1)>"

    resp = client.post(
        f"/api/remediation/{case_with_xss}/approve",
        json={"decision": xss_payload, "operator_id": sqli_payload},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["ledger"]["decision"] == xss_payload
    assert data["ledger"]["operator_id"] == sqli_payload
    assert APPROVAL_LEDGER[case_with_xss]["decision"] == xss_payload


def test_fixture_case_id_substring_collision():
    """VULNERABILITY: load_fixture uses `if case_id in file.stem:`.
    Non-specific or short case_id queries collide with unexpected fixtures.
    """
    # Empty string matches whichever file happens to be first in FIXTURES_DIR.glob
    fixture_empty = load_fixture("")
    assert fixture_empty is not None
    assert fixture_empty["id"] in ["case_01", "case_02", "case_03", "case_04", "case_05"]

    # 'case' matches the first fixture found, not an exact match
    fixture_case = load_fixture("case")
    assert fixture_case is not None

    # '02' matches case_02
    fixture_02 = load_fixture("02")
    assert fixture_02 is not None
    assert fixture_02["id"] == "case_02"


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
