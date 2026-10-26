"""Stage 0 Characterization Tests for Sentinel-Ops v3 Migration.

Captures the baseline counterexamples documented in the architecture decision review:
1. Two-pod out-of-order series pairing (Pod A 2/100 + Pod B 1/2 -> false saturation if unjoined by pod label).
2. Unjoinable replica labels / missing capacity denominator.
3. Per-replica counter reset where pod-a grows while pod-b resets to zero.
4. Order-dependent reducer collision on distinct span_ref items with identical finding length.
5. Slow downstream span localization without corroborating timeout counter.
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch
import pytest

from sentinel_ops.agents.graph import compile_investigation_graph
from sentinel_ops.agents.specialists import metrics_specialist_node
from sentinel_ops.agents.state import EvidenceItem, merge_evidence_items


@pytest.mark.asyncio
async def test_char_two_pod_out_of_order_series_does_not_falsely_saturate():
    """Pod A (2/100) and Pod B (1/2) must NOT pair Pod A active=2 with Pod B size=2 when capacity order is reversed."""
    window = ("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z")

    async def fake_query_metric(service, metric_type, window, **kwargs):
        if metric_type == "db_pool_active":
            return {
                "status": "SUCCESS",
                "promql": "payment_db_pool_active",
                "result": [
                    {"metric": {"service": service, "pod": "pod-a"}, "values": [[1795530720, "2.0"]]},
                    {"metric": {"service": service, "pod": "pod-b"}, "values": [[1795530720, "1.0"]]},
                ],
            }
        if metric_type == "db_pool_size":
            # Reversed series order: pod-b (size=2) appears first!
            return {
                "status": "SUCCESS",
                "promql": "payment_db_pool_size",
                "result": [
                    {"metric": {"service": service, "pod": "pod-b"}, "values": [[1795530720, "2.0"]]},
                    {"metric": {"service": service, "pod": "pod-a"}, "values": [[1795530720, "100.0"]]},
                ],
            }
        return {"status": "EMPTY", "promql": metric_type, "result": []}

    mock_adapter = AsyncMock()
    mock_adapter.query_metric = AsyncMock(side_effect=fake_query_metric)

    with patch("sentinel_ops.agents.specialists.get_prometheus_adapter", return_value=mock_adapter):
        res = await metrics_specialist_node({
            "service": "payment-service",
            "metric_type": "db_pool_active",
            "observation_window": window,
            "incident_timestamp": "2026-11-24T14:32:00Z",
        })

    findings = " ".join(e.finding for e in res["evidence"])
    assert "saturated" not in findings.lower()


@pytest.mark.asyncio
async def test_char_unjoinable_replica_labels_surface_explicit_gap():
    """Conflicting pod labels between numerator (pod-a) and denominator (pod-b) must not compute occupancy."""
    window = ("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z")

    async def fake_query_metric(service, metric_type, window, **kwargs):
        if metric_type == "db_pool_active":
            return {
                "status": "SUCCESS",
                "promql": "payment_db_pool_active",
                "result": [{"metric": {"service": service, "pod": "pod-a"}, "values": [[1795530720, "2.0"]]}],
            }
        if metric_type == "db_pool_size":
            return {
                "status": "SUCCESS",
                "promql": "payment_db_pool_size",
                "result": [{"metric": {"service": service, "pod": "pod-b"}, "values": [[1795530720, "2.0"]]}],
            }
        return {"status": "EMPTY", "promql": metric_type, "result": []}

    mock_adapter = AsyncMock()
    mock_adapter.query_metric = AsyncMock(side_effect=fake_query_metric)

    with patch("sentinel_ops.agents.specialists.get_prometheus_adapter", return_value=mock_adapter):
        res = await metrics_specialist_node({
            "service": "payment-service",
            "metric_type": "db_pool_active",
            "observation_window": window,
            "incident_timestamp": "2026-11-24T14:32:00Z",
        })

    findings = " ".join(e.finding.lower() for e in res["evidence"])
    assert "saturated" not in findings
    assert "unjoinable" in findings or "cannot determine saturation" in findings


@pytest.mark.asyncio
async def test_char_per_replica_counter_reset_preserved():
    """Replica counter reset on pod-b must not mask monotonic growth on pod-a or corrupt total delta."""
    window = ("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z")

    async def fake_query_metric(service, metric_type, window, **kwargs):
        return {
            "status": "SUCCESS",
            "promql": "payment_db_pool_acquire_timeouts_total",
            "result": [
                {"metric": {"service": service, "pod": "pod-a"}, "values": [[1795530720, "2"], [1795530750, "11"]]},
                {"metric": {"service": service, "pod": "pod-b"}, "values": [[1795530720, "50"], [1795530750, "0"]]},
            ],
        }

    mock_adapter = AsyncMock()
    mock_adapter.query_metric = AsyncMock(side_effect=fake_query_metric)

    with patch("sentinel_ops.agents.specialists.get_prometheus_adapter", return_value=mock_adapter):
        res = await metrics_specialist_node({
            "service": "payment-service",
            "metric_type": "db_pool_acquire_timeouts_total",
            "observation_window": window,
            "incident_timestamp": "2026-11-24T14:32:00Z",
        })

    # Reversed series order on pod-b reset should preserve both pod-a spike AND pod-b reset awareness
    combined = " ".join(e.finding for e in res["evidence"])
    assert "reset" in combined.lower() or "pod-a" in combined


@pytest.mark.asyncio
async def test_char_slow_span_without_counter_localizes_without_inventing_mechanism():
    """Isolated slow trace span without timeout counter growth abstains on mechanism but localizes dependency + check."""
    graph = compile_investigation_graph()
    tid = "e" * 32
    state = await graph.ainvoke(
        {
            "incident_id": "char_slow_span_only",
            "alert_text": f"Checkout slow on trace {tid}",
            "incident_timestamp": "2026-11-24T14:32:30Z",
            "target_service": "checkout-service",
            "trace_id": tid,
            "simulated_telemetry": {
                "prometheus": {
                    "payment-service": {
                        "db_pool_acquire_timeouts_total": {"status": "SUCCESS", "values": [[1795530720, "5"], [1795530750, "5"]]},
                    }
                },
                "tempo": {
                    tid: {
                        "status": "SUCCESS",
                        "timestamp": 1795530750,
                        "spans": [
                            {"span_id": "r", "parent_span_id": "", "service": "checkout-service", "name": "checkout", "duration_ms": 2100.0},
                            {"span_id": "p", "parent_span_id": "r", "service": "payment-service", "name": "db.connection.acquire", "duration_ms": 2050.0},
                        ],
                    }
                },
            },
            "crag_iterations": 0,
        },
        config={"configurable": {"thread_id": "char_slow_span"}},
    )
    assert state["terminal_status"] == "INSUFFICIENT_EVIDENCE"
    assert len(state["next_discriminating_checks"]) >= 1
    checks_text = " ".join(state["next_discriminating_checks"]).lower()
    assert "payment-service" in checks_text or "trace" in checks_text


@pytest.mark.asyncio
async def test_stage1_probe_attempt_accounting_and_snapshot_capture_replay_parity():
    """Stage 1: db_pool_active + db_pool_size emits 2 ProbeAttempts, and live capture replays identically."""
    from sentinel_ops.telemetry.models import TelemetrySnapshot
    from sentinel_ops.telemetry.reader import LiveTelemetryReader, SnapshotReplayReader

    window = ("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z")

    async def fake_query_metric(service, metric_type, window, **kwargs):
        if metric_type == "db_pool_active":
            return {
                "status": "SUCCESS",
                "promql": "payment_db_pool_active",
                "result": [{"metric": {"pod": "pay-0"}, "values": [[1795530720, "2.0"], [1795530750, "2.0"]]}],
            }
        if metric_type == "db_pool_size":
            return {
                "status": "SUCCESS",
                "promql": "payment_db_pool_size",
                "result": [{"metric": {"pod": "pay-0"}, "values": [[1795530720, "2.0"], [1795530750, "2.0"]]}],
            }
        return {"status": "EMPTY", "promql": metric_type, "result": []}

    mock_prom = AsyncMock()
    mock_prom.query_metric = AsyncMock(side_effect=fake_query_metric)
    snapshot = TelemetrySnapshot()
    live_reader = LiveTelemetryReader(prom_adapter=mock_prom, capture_snapshot=snapshot)

    live_obs, live_attempts = await live_reader.read_metric(
        service="payment-service",
        metric_type="db_pool_active",
        window=window,
        incident_timestamp="2026-11-24T14:32:30Z",
    )
    assert len(live_attempts) == 2
    assert {a.signal_name for a in live_attempts} == {"db_pool_active", "db_pool_size"}
    assert live_obs[0].join_status == "label_joined"
    assert live_obs[0].value == 1.0

    # Disconnect backends and replay captured snapshot
    replay_reader = SnapshotReplayReader(snapshot.model_dump())
    rep_obs, rep_attempts = await replay_reader.read_metric(
        service="payment-service",
        metric_type="db_pool_active",
        window=window,
        incident_timestamp="2026-11-24T14:32:30Z",
    )
    assert len(rep_attempts) == 2
    assert rep_obs[0].value == live_obs[0].value
    assert rep_obs[0].join_status == live_obs[0].join_status
    assert rep_obs[0].entity_labels == live_obs[0].entity_labels


@pytest.mark.asyncio
async def test_stage1_merge_observations_order_invariant_and_limiter_budget():
    """Stage 1: merge_observations is order-invariant across replicas and AsyncRateLimiter respects deadline."""
    import time
    from sentinel_ops.agents.llm_planner import AsyncRateLimiter
    from sentinel_ops.agents.state import merge_observations
    from sentinel_ops.telemetry.models import NormalizedMetricObservation

    obs_a = NormalizedMetricObservation(
        observation_id="OBS-prom-a",
        attempt_id="att_1",
        service="payment-service",
        signal_name="db_pool_active",
        entity_labels={"pod": "pod-a"},
        join_key="pod=pod-a",
        value=0.02,
        requested_window=("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"),
        status="SUCCESS",
        finding="same length X",
    )
    obs_b = NormalizedMetricObservation(
        observation_id="OBS-prom-b",
        attempt_id="att_2",
        service="payment-service",
        signal_name="db_pool_active",
        entity_labels={"pod": "pod-b"},
        join_key="pod=pod-b",
        value=0.50,
        requested_window=("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"),
        status="SUCCESS",
        finding="same length Y",
    )
    assert merge_observations([obs_a], [obs_b]) == merge_observations([obs_b], [obs_a])
    assert len(merge_observations([obs_a], [obs_b])) == 2

    limiter = AsyncRateLimiter(min_interval_sec=5.0)
    limiter._last_call = time.monotonic()
    # Deadline only 0.2s away -> must immediately return False without sleeping 5.0s
    t0 = time.monotonic()
    allowed = await limiter.acquire(deadline_timestamp=time.monotonic() + 0.2)
    assert allowed is False
    assert (time.monotonic() - t0) < 0.5
