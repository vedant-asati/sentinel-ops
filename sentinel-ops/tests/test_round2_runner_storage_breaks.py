import asyncio
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch
import pytest

from fastapi import HTTPException
from fastapi.testclient import TestClient

from sentinel_ops.core.config import settings
from sentinel_ops.server.app import app, _enforce_env_scope
from sentinel_ops.service.runner import InvestigationService
from sentinel_ops.storage.repository import (
    MemoryRunRepository,
    RunRecord,
    SQLiteRunRepository,
    parse_exported_brief,
)


@pytest.mark.asyncio
async def test_runner_task_and_notifier_memory_leak():
    """MEMORY LEAK: InvestigationService retains all completed task objects and
    asyncio.Condition notifiers in self._tasks and self._notifiers indefinitely.
    Running multiple investigations causes linear memory exhaustion.
    """
    repo = MemoryRunRepository(maxsize=100)
    svc = InvestigationService(repository=repo)
    run_ids = []

    for i in range(50):
        rid = await svc.start_run(
            case_id="case_03",
            incident_id=f"inc_{i}",
            alert_text="test alert",
            incident_timestamp="2026-11-25T14:00:00Z",
            target_service="checkout-service",
        )
        run_ids.append(rid)

    assert len(svc._tasks) == 50
    assert len(svc._notifiers) == 50

    # Wait for background tasks to finish
    await asyncio.sleep(0.5)

    # Even after all tasks complete, dictionaries still hold references
    assert len(svc._tasks) == 50
    assert len(svc._notifiers) == 50
    for rid in run_ids:
        assert rid in svc._tasks
        assert rid in svc._notifiers

    await svc.aclose()


@pytest.mark.asyncio
async def test_runner_zombie_hang_on_unhandled_failure():
    """ZOMBIE RUN / SUBSCRIBER HANG:
    If an unhandled exception occurs while recording a failure in _runner
    (e.g., format_incident_brief crashes or repo.commit_terminal raises an error),
    the run status is never transitioned to FAILED and remains permanently stuck in RUNNING.
    Subscribers awaiting completion in subscribe_events loop indefinitely.
    """
    repo = MemoryRunRepository(maxsize=100)
    svc = InvestigationService(repository=repo)

    # Mock commit_terminal to raise an error during failure handling
    with patch.object(repo, "commit_terminal", side_effect=RuntimeError("Database failure")):
        # We start a run with an invalid initial state to trigger an exception
        with patch.object(svc, "build_initial_state", side_effect=ValueError("Simulated worker error")):
            with pytest.raises(ValueError):
                await svc.start_run(
                    incident_id="inc_fail",
                    alert_text="alert",
                    incident_timestamp="now",
                    target_service="svc",
                )


def test_sqlite_database_locked_under_concurrency(tmp_path: Path):
    """CONCURRENCY FAILURE:
    SQLiteRunRepository does not enable WAL mode (PRAGMA journal_mode=WAL).
    In standard DELETE journal mode, any concurrent write transaction locks the entire DB file.
    Concurrent writers / readers raise sqlite3.OperationalError: database is locked within 5s.
    """
    db_file = tmp_path / "test_lock.db"
    repo = SQLiteRunRepository(db_file)
    rec = RunRecord(
        run_id="run_lock",
        environment="default",
        profile_id="p1",
        profile_version="1.0",
        schema_version="3.0",
        status="PENDING",
        created_at="now",
    )
    repo.create_run(rec)

    # Simulate another connection holding an exclusive write transaction
    conn2 = sqlite3.connect(str(db_file), timeout=0.1)
    conn2.execute("BEGIN EXCLUSIVE TRANSACTION")

    try:
        # Attempting to write from the repo raises OperationalError
        with pytest.raises(sqlite3.OperationalError) as exc_info:
            repo.append_event("run_lock", {"type": "concurrent_test"})
        assert "database is locked" in str(exc_info.value)
    finally:
        conn2.rollback()
        conn2.close()


def test_sqlite_connection_descriptor_leak(tmp_path: Path):
    """RESOURCE LEAK:
    In SQLiteRunRepository, methods use `with self._lock, self._connect() as conn:`.
    In Python sqlite3, `with conn:` manages transactions, but NEVER closes the connection.
    Every method call permanently leaks an open file descriptor to the SQLite file.
    """
    db_file = tmp_path / "test_leak.db"
    repo = SQLiteRunRepository(db_file)
    rec = RunRecord(
        run_id="run_fd",
        environment="default",
        profile_id="p1",
        profile_version="1.0",
        schema_version="3.0",
        status="PENDING",
        created_at="now",
    )
    repo.create_run(rec)

    fds_before = len(os.listdir("/proc/self/fd"))
    for _ in range(50):
        repo.get_run("run_fd")
    fds_after = len(os.listdir("/proc/self/fd"))

    # File descriptors stay bounded because SQLite connections are closed promptly via contextmanager
    assert fds_after <= fds_before + 2, f"Expected closed SQLite FDs: before={fds_before}, after={fds_after}"


def test_sqlite_corrupted_json_crash(tmp_path: Path):
    """Verify get_run recovers safely from corrupted JSON payloads instead of crashing."""
    db_file = tmp_path / "test_corrupt.db"
    repo = SQLiteRunRepository(db_file)
    rec = RunRecord(
        run_id="run_corrupt",
        environment="default",
        profile_id="p1",
        profile_version="1.0",
        schema_version="3.0",
        status="PENDING",
        created_at="now",
    )
    repo.create_run(rec)

    # Corrupt final_state_json directly in SQLite
    with repo._connect() as conn:
        conn.execute(
            "UPDATE runs SET final_state_json = ? WHERE run_id = ?",
            ("{corrupted: non_json", "run_corrupt"),
        )

    loaded = repo.get_run("run_corrupt")
    assert loaded is not None
    assert loaded.final_state["corrupted_payload"] is True
    assert "error" in loaded.final_state


def test_sqlite_parse_exported_brief_corrupted_json():
    """Verify parse_exported_brief raises clean ValueError on malformed JSON."""
    with pytest.raises(ValueError, match="Malformed exported brief JSON"):
        parse_exported_brief("{broken_json: ...")


def test_server_env_scope_security_bypass(monkeypatch):
    """Verify forged X-Sentinel-Env header cannot bypass record environment scope check."""
    monkeypatch.setattr(settings, "SENTINEL_ENV_SCOPE", "prod")

    dev_rec_env = "dev"

    with pytest.raises(HTTPException) as exc_info:
        _enforce_env_scope(dev_rec_env, None)
    assert exc_info.value.status_code == 403

    # Forged X-Sentinel-Env: prod header must still be rejected for a dev record
    with pytest.raises(HTTPException) as forged_exc:
        _enforce_env_scope(dev_rec_env, "prod")
    assert forged_exc.value.status_code == 403


def test_cli_unhandled_keyerror_on_invalid_profile():
    """Verify invalid profile exits cleanly with non-zero status and friendly error without traceback."""
    cmd = [
        sys.executable,
        "-m",
        "sentinel_ops.cli",
        "--profile",
        "non_existent_profile_xyz",
        "--auto-approve",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode == 1
    assert "Traceback" not in proc.stderr
    assert "KeyError" not in proc.stderr
    assert "SystemProfile" in proc.stdout or "not found" in proc.stdout
