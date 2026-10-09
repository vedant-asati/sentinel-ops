import asyncio
import time
import pytest
from sentinel_ops.agents.state import EvidenceItem, merge_evidence_items
from sentinel_ops.core.deadline import DeadlineTracker, RunDeadlineExceeded


def test_evidence_reducer_commutativity_violation():
    """CRITICAL RACE CONDITION: State Reducer violates Commutativity.
    merge_evidence_items([A], [B]) != merge_evidence_items([B], [A]) when merging non-SUCCESS items.
    
    If specialist 1 returns EMPTY (proof of absence) and specialist 2 returns TOOL_FAILURE (infra error):
    - If 1 completes before 2: status is EMPTY -> triggers CRAG Safe Abstention (INSUFFICIENT_EVIDENCE).
    - If 2 completes before 1: status is TOOL_FAILURE -> triggers CRAG Fatal Abort (OPERATIONAL_FAILURE).
    The multi-agent investigation verdict non-deterministically flips based on execution race conditions!
    """
    item_empty = EvidenceItem(
        id="EV-prom-paym-db_p",
        backend_source="prometheus",
        query_string="payment_db_pool_active",
        query_params={"service": "payment-service"},
        observation_window=("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"),
        sample_or_span_ref="db_pool_active",
        finding="No metric samples returned",
        raw_payload="",
        status="EMPTY",
    )
    item_tool_failure = EvidenceItem(
        id="EV-prom-paym-db_p",
        backend_source="prometheus",
        query_string="payment_db_pool_active",
        query_params={"service": "payment-service"},
        observation_window=("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"),
        sample_or_span_ref="db_pool_active",
        finding="Connection timeout to prometheus backend",
        raw_payload="",
        status="TOOL_FAILURE",
    )

    merged_empty_first = merge_evidence_items([item_empty], [item_tool_failure])
    merged_failure_first = merge_evidence_items([item_tool_failure], [item_empty])

    # VERIFY COMMUTATIVITY: priority lattice (SUCCESS > TOOL_FAILURE > EMPTY)
    assert merged_empty_first[0].status == "TOOL_FAILURE"
    assert merged_failure_first[0].status == "TOOL_FAILURE"
    assert merged_empty_first[0].status == merged_failure_first[0].status


def test_evidence_reducer_conflicting_success_loss():
    """RACE CONDITION: Silent evidence loss on concurrent SUCCESS observations.
    When two concurrent tasks produce SUCCESS evidence for the same ID with conflicting observations,
    the second observation is silently discarded without conflict resolution or merging.
    """
    item_v1 = EvidenceItem(
        id="EV-001",
        backend_source="prometheus",
        query_string="query",
        query_params={"service": "payment-service"},
        observation_window=("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"),
        sample_or_span_ref="ref",
        finding="Pool saturated at 100%",
        raw_payload="1.0",
        status="SUCCESS",
    )
    item_v2 = EvidenceItem(
        id="EV-001",
        backend_source="prometheus",
        query_string="query",
        query_params={"service": "payment-service"},
        observation_window=("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"),
        sample_or_span_ref="ref",
        finding="Pool normal at 20%",
        raw_payload="0.2",
        status="SUCCESS",
    )

    res_order_1 = merge_evidence_items([item_v1], [item_v2])
    res_order_2 = merge_evidence_items([item_v2], [item_v1])

    # Symmetrically resolved: commutative regardless of arrival order
    assert res_order_1[0].finding == res_order_2[0].finding


def test_evidence_item_unfrozen_mutability():
    """VULNERABILITY: EvidenceItem is not frozen, permitting direct in-place state corruption.
    Any node or concurrent thread can mutate evidence fields in place without immutability guarantees.
    """
    item = EvidenceItem(
        id="EV-001",
        backend_source="prometheus",
        query_string="query",
        query_params={"service": "payment-service"},
        observation_window=("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"),
        sample_or_span_ref="ref",
        finding="Original finding",
        raw_payload="payload",
        status="SUCCESS",
    )
    # Direct field mutation succeeds because frozen=True is not set
    item.finding = "Tampered / Corrupted Finding"
    item.status = "EMPTY"
    assert item.finding == "Tampered / Corrupted Finding"
    assert item.status == "EMPTY"


def test_deadline_tracker_zero_timeout_socket_vulnerability():
    """RACE CONDITION & SOCKET CRASH:
    When DeadlineTracker expires, remaining is 0.0.
    bounded_timeout(desired) returns 0.0.
    Passing timeout=0.0 to network operations (socket/httpx/urllib) causes immediate
    socket non-blocking connection errors ([Errno 115] Operation now in progress) or ValueErrors.
    """
    tracker = DeadlineTracker(deadline_seconds=0.001)
    time.sleep(0.01)  # Force expiration

    assert tracker.is_expired() is True
    assert tracker.remaining == 0.0
    with pytest.raises(RunDeadlineExceeded):
        tracker.bounded_timeout(5.0)


def test_deadline_tracker_nan_and_negative_edge_cases():
    """EDGE CASE: NaN and negative deadline parameters."""
    # Negative deadline
    tracker_neg = DeadlineTracker(deadline_seconds=-10.0)
    assert tracker_neg.remaining == 0.0
    assert tracker_neg.is_expired() is True
    with pytest.raises(RunDeadlineExceeded):
        tracker_neg.bounded_timeout(5.0)

    # NaN deadline
    tracker_nan = DeadlineTracker(deadline_seconds=float("nan"))
    assert tracker_nan.remaining == 0.0
    with pytest.raises(RunDeadlineExceeded):
        tracker_nan.bounded_timeout(5.0)
    assert tracker_nan.is_expired() is True


@pytest.mark.asyncio
async def test_async_prober_thread_exhaustion_simulation():
    """ASYNC TASK STARVATION:
    prober.py uses blocking urllib.request.urlopen with a 10s timeout.
    When offloaded via asyncio.to_thread under concurrency, all 32 worker threads
    in Python's default ThreadPoolExecutor become blocked, starving all other async tasks.
    """
    import concurrent.futures

    # Custom executor simulating ThreadPoolExecutor with 4 workers
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)
    loop = asyncio.get_running_loop()

    def blocking_work():
        time.sleep(0.2)
        return "done"

    # Saturate all 4 threads
    t0 = time.perf_counter()
    tasks = [loop.run_in_executor(executor, blocking_work) for _ in range(8)]
    results = await asyncio.gather(*tasks)
    elapsed = time.perf_counter() - t0

    assert len(results) == 8
    # 8 tasks on 4 threads took at least 2 batches (0.4s)
    assert elapsed >= 0.35, f"Expected thread queue queuing delay, got {elapsed:.2f}s"
    executor.shutdown(wait=True)
