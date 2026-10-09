import os
import sys
import tempfile
from pathlib import Path
import pytest

from sentinel_ops.dpo.trajectory_logger import DPOTrajectoryLogger
from sentinel_ops.mcp.prometheus_adapter import PrometheusAdapter
from sentinel_ops.mcp.tempo_adapter import TempoAdapter
from sentinel_ops.server.app import APPROVAL_LEDGER


def test_approval_ledger_memory_leak_under_continuous_loop():
    """MEMORY LEAK: APPROVAL_LEDGER retains every approval indefinitely without eviction or bounds.
    Simulating a continuous loop of operator approvals demonstrates unbounded growth.
    """
    initial_count = len(APPROVAL_LEDGER)
    iterations = 2000

    for i in range(iterations):
        APPROVAL_LEDGER[f"leak_case_{i}"] = {
            "case_id": f"leak_case_{i}",
            "decision": "approved",
            "operator_id": "operator_test",
            "timestamp": "2026-11-24T20:30:00Z",
            "large_metadata": "X" * 1024,  # 1 KB per entry
        }

    # INVARIANT: APPROVAL_LEDGER is bounded and evicts oldest items to prevent memory exhaustion
    assert len(APPROVAL_LEDGER) <= 1000
    # Clean up test keys to prevent polluting subsequent tests
    for i in range(iterations):
        APPROVAL_LEDGER.pop(f"leak_case_{i}", None)


def test_telemetry_adapters_instantiate_client_per_query():
    """SOCKET / DESCRIPTOR LEAK:
    PrometheusAdapter and TempoAdapter instantiate a new httpx.AsyncClient for every single
    query method call instead of managing a persistent, pooled HTTP client.
    Under high concurrency or continuous loops, this churns TCP sockets, depletes ephemeral ports,
    and causes TIME_WAIT socket exhaustion.
    """
    prom = PrometheusAdapter(base_url="http://localhost:59090")
    tempo = TempoAdapter(base_url="http://localhost:53201")

    # In PrometheusAdapter.query_metric:
    # "async with httpx.AsyncClient(timeout=self.timeout) as client:"
    # Verify neither adapter retains an initialized persistent client
    assert not hasattr(prom, "client") or getattr(prom, "client", None) is None
    assert not hasattr(tempo, "client") or getattr(tempo, "client", None) is None


def test_dpo_trajectory_logger_concurrent_writes_no_lock(tmp_path: Path):
    """RACE CONDITION & FILE CORRUPTION:
    DPOTrajectoryLogger.log_pair opens the JSONL file in append mode without file locking (flock).
    Concurrent writes from multiple agent processes can interleave lines or corrupt JSON syntax.
    """
    jsonl_path = tmp_path / "trajectories.jsonl"
    logger = DPOTrajectoryLogger(output_path=jsonl_path)

    import threading
    errors = []

    def log_worker(worker_id: int):
        try:
            for j in range(25):
                logger.log_pair(
                    incident_id=f"case_{worker_id}_{j}",
                    prompt=f"Alert text for worker {worker_id}",
                    target_service="checkout-service",
                    chosen_steps=[{"step": "grounded_step", "worker": worker_id}],
                    rejected_steps=[{"step": "hallucinated_step", "worker": worker_id}],
                )
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=log_worker, args=(i,)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0
    # Read back trajectories and verify line count
    entries = logger.read_trajectories()
    assert len(entries) == 6 * 25
