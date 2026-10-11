#!/usr/bin/env python3
"""Sentinel-Ops System Hardening & Stress Verification Harness.

Verifies that previously reproduced vulnerabilities across FastAPI, state concurrency,
HTTP connection pooling, and CLI signal/exit handling remain securely mitigated.
"""

import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from rich.console import Console
from rich.panel import Panel

console = Console()


def section_header(title: str):
    console.print(f"\n[bold magenta]{'=' * 80}[/bold magenta]")
    console.print(f"[bold cyan]VERIFYING HARDENING: {title}[/bold cyan]")
    console.print(f"[bold magenta]{'=' * 80}[/bold magenta]\n")


def verify_server_hardening():
    section_header("1. FastAPI Server (server/app.py) Bounds, Input Validation & Lookups")
    from fastapi.testclient import TestClient
    from sentinel_ops.server.app import app, APPROVAL_LEDGER, load_fixture

    client = TestClient(app)

    # 1.1 Bounded APPROVAL_LEDGER
    for i in range(1100):
        resp = client.post(
            f"/api/remediation/stress_{i}/approve",
            json={"decision": "approved", "operator_id": "sre_stress_01"},
        )
        assert resp.status_code == 200
    assert len(APPROVAL_LEDGER) <= 1000
    console.print(f"✔ Bounded Ledger confirmed (len={len(APPROVAL_LEDGER)} <= 1000)")
    for i in range(1100):
        APPROVAL_LEDGER.pop(f"stress_{i}", None)

    # 1.2 XSS / SQLi Rejection
    xss_payload = "<script>alert(1)</script>"
    resp_xss = client.post("/api/remediation/case_01/approve", json={"decision": xss_payload, "operator_id": "sre_01"})
    assert resp_xss.status_code == 422
    resp_sqli = client.post("/api/remediation/case_01/approve", json={"decision": "approved", "operator_id": "root' OR '1'='1"})
    assert resp_sqli.status_code == 422
    console.print("✔ Strict 422 Pydantic validation rejects XSS and SQLi payloads.")

    # 1.3 Exact Fixture Matching
    assert load_fixture("") is None
    assert load_fixture("case") is None
    assert load_fixture("case_01") is not None
    console.print("✔ Exact load_fixture lookup blocks substring collisions.")

    # 1.4 Corrupt YAML resilience
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        (tmp_path / "corrupt.yaml").write_text("invalid: [yaml: unclosed", encoding="utf-8")
        with patch("sentinel_ops.server.app.FIXTURES_DIR", tmp_path):
            r = client.get("/api/incidents")
            assert r.status_code == 200
    console.print("✔ /api/incidents skips corrupt YAML without 500 crashes.")


def verify_concurrency_and_immutability():
    section_header("2. Concurrency, Immutability & Deadlines (state.py, deadline.py)")
    from pydantic import ValidationError
    from sentinel_ops.agents.state import EvidenceItem, merge_evidence_items
    from sentinel_ops.core.deadline import DeadlineTracker, RunDeadlineExceeded

    item_empty = EvidenceItem(
        id="EV-prom-paym-db_p",
        backend_source="prometheus",
        query_string="q",
        query_params={"service": "payment-service"},
        observation_window=("T1", "T2"),
        sample_or_span_ref="ref",
        finding="No metric samples found",
        raw_payload="",
        status="EMPTY",
    )
    item_failure = EvidenceItem(
        id="EV-prom-paym-db_p",
        backend_source="prometheus",
        query_string="q",
        query_params={"service": "payment-service"},
        observation_window=("T1", "T2"),
        sample_or_span_ref="ref",
        finding="Connection timeout",
        raw_payload="",
        status="TOOL_FAILURE",
    )
    assert merge_evidence_items([item_empty], [item_failure])[0].status == "TOOL_FAILURE"
    assert merge_evidence_items([item_failure], [item_empty])[0].status == "TOOL_FAILURE"
    console.print("✔ Commutative evidence reducer preserves TOOL_FAILURE > EMPTY regardless of order.")

    try:
        item_empty.finding = "mutated"  # type: ignore
        raise AssertionError("EvidenceItem allowed mutation")
    except ValidationError:
        console.print("✔ EvidenceItem immutability (frozen=True) enforced.")

    tracker = DeadlineTracker(deadline_seconds=0.0001)
    time.sleep(0.005)
    try:
        tracker.bounded_timeout(5.0)
        raise AssertionError("bounded_timeout failed to raise RunDeadlineExceeded")
    except RunDeadlineExceeded:
        console.print("✔ Socket protected by RunDeadlineExceeded on expired budgets.")


def verify_pooled_adapters_and_cli():
    section_header("3. Pooled Telemetry Clients & CLI Exit/Signal Safety")
    from sentinel_ops.mcp.prometheus_adapter import PrometheusAdapter
    from sentinel_ops.mcp.tempo_adapter import TempoAdapter

    prom = PrometheusAdapter()
    tempo = TempoAdapter()
    assert prom._get_client() is prom.client
    assert tempo._get_client() is tempo.client
    console.print("✔ Persistent pooled httpx.AsyncClient initialized on telemetry adapters.")

    p_eof = subprocess.run([sys.executable, "-m", "sentinel_ops.cli", "--case-id", "case_01", "--no-dpo"], cwd=str(REPO_ROOT), input="", text=True, capture_output=True)
    assert p_eof.returncode == 0 and "EOFError" not in p_eof.stderr
    console.print("✔ Non-interactive closed stdin handled gracefully without EOFError.")

    p_abs = subprocess.run([sys.executable, "-m", "sentinel_ops.cli", "--case-id", "case_03", "--auto-approve", "--no-dpo"], cwd=str(REPO_ROOT), text=True, capture_output=True)
    assert p_abs.returncode == 2
    console.print("✔ Semantic CLI exit code 2 verified for INSUFFICIENT_EVIDENCE abstention.")


def main():
    console.print(
        Panel(
            "[bold white]Sentinel-Ops SRE: Hardening & Stress Verification Harness[/bold white]",
            title="[bold green]SYSTEM HARDENING VERIFICATION[/bold green]",
            border_style="green",
        )
    )
    verify_server_hardening()
    verify_concurrency_and_immutability()
    verify_pooled_adapters_and_cli()
    console.print("\n[bold green]✔ All hardening invariants verified successfully.[/bold green]\n")


if __name__ == "__main__":
    main()
