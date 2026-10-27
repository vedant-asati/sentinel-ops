import pytest
import math
import hashlib
from sentinel_ops.telemetry.models import NormalizedMetricObservation, NormalizedTraceObservation
from sentinel_ops.telemetry.normalize import (
    normalize_prometheus_response,
    normalize_tempo_trace,
    _validate_finite_samples,
    _make_observation_id,
    _analyze_counter_series,
    extract_join_key,
    extract_replica_key,
)


def test_normalization_out_of_order_timestamps_value_inversion():
    """EXPLOIT / DATA INTEGRITY:
    When Prometheus metrics return out-of-order timestamps (e.g. distributed scrapers,
    network jitter, or out-of-order ingestion), `normalize_prometheus_response` does NOT
    sort samples by timestamp.
    Line 321 blindly extracts `parsed[-1][1]` as the current metric value.
    If samples are [(t2=100, val=0.1), (t1=50, val=0.9)], it extracts 0.9 (the older sample),
    inverting time perception and making an active outage look healthy!
    """
    attempt_id = "att_test_ooo"
    resp = {
        "status": "SUCCESS",
        "result": [
            {
                "metric": {"service": "checkout-service"},
                # Timestamps out-of-order: t=1732461060 (newer, 0.95 error rate) followed by t=1732461000 (older, 0.01 error rate)
                "values": [[1732461060, "0.95"], [1732461000, "0.01"]],
            }
        ],
    }

    # Window covering epoch timestamps 1732461000..1732461100
    w_start = "2024-11-24T15:09:00Z"
    w_end = "2024-11-24T15:15:00Z"
    obs_list = normalize_prometheus_response(
        attempt_id=attempt_id,
        service="checkout-service",
        signal_name="error_rate",
        response=resp,
        window=(w_start, w_end),
    )
    assert len(obs_list) == 1
    obs = obs_list[0]
    # Samples sorted chronologically: reports the latest 0.95 (critical spike), not older 0.01
    assert obs.value == 0.95
    assert "0.95" in obs.finding or "95%" in obs.finding


def test_normalization_out_of_order_counter_false_reset_and_zero_delta():
    """Verify out-of-order counter samples are sorted chronologically cleanly."""
    out_of_order_counter = [(1732461060, 70.0), (1732461000, 50.0), (1732461030, 60.0)]
    delta, end_val, reset_detected = _analyze_counter_series(out_of_order_counter)
    assert reset_detected is False
    assert delta == 20.0
    assert end_val == 70.0


def test_normalization_inverted_window_falsely_marks_stale_telemetry():
    """Verify inverted window (start_iso > end_iso) is rejected as TOOL_FAILURE instead of STALE_TELEMETRY."""
    attempt_id = "att_test_inverted"
    resp = {
        "status": "SUCCESS",
        "result": [
            {
                "metric": {"service": "payment-service"},
                "values": [[1732461000, "1.0"]],
            }
        ],
    }
    obs_list = normalize_prometheus_response(
        attempt_id=attempt_id,
        service="payment-service",
        signal_name="error_rate",
        response=resp,
        window=("2026-11-24T15:00:00Z", "2026-11-24T14:00:00Z"),
    )
    assert len(obs_list) == 1
    assert obs_list[0].status == "TOOL_FAILURE"
    assert "Invalid inverted query window" in obs_list[0].finding


def test_observation_id_truncation_hash_collision_vulnerability():
    """Verify SHA-256 24-hex-character (96-bit) observation IDs prevent truncation collisions."""
    ids = set()
    total_samples = 1000
    for i in range(total_samples):
        oid = _make_observation_id("prom", "payment-service", "error_rate", f"pod-{i}", ("w1", "w2"), f"rev_{i}")
        assert oid.startswith("OBS-prom-")
        assert len(oid) == len("OBS-prom-") + 24
        ids.add(oid)

    assert len(ids) == total_samples


def test_series_count_explosion_and_truncation_metadata():
    """SCALE STRESS / BUFFER DEFENSE:
    When Prometheus returns 10,000 series (fleet-wide metric explosion),
    `normalize_prometheus_response` must enforce `max_series` cap (default 5)
    to protect downstream memory and set truncated=True, coverage_status='PARTIAL'.
    """
    attempt_id = "att_explosion"
    # Synthesize 10,000 series
    huge_result = [
        {
            "metric": {"service": "payment-service", "pod": f"pod-{i}"},
            "values": [[1732461000, "0.05"]],
        }
        for i in range(10_000)
    ]
    resp = {
        "status": "SUCCESS",
        "result": huge_result,
        "total_series_count": 10_000,
    }

    obs_list = normalize_prometheus_response(
        attempt_id=attempt_id,
        service="payment-service",
        signal_name="error_rate",
        response=resp,
        window=("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"),
        max_series=5,
    )
    assert len(obs_list) == 5
    for obs in obs_list:
        assert obs.truncated is True
        assert obs.total_series_count == 10_000
        assert obs.retained_series_count == 5
        assert obs.coverage_status == "PARTIAL"


def test_tempo_normalization_unhandled_crash_on_malformed_start_nano():
    """EXPLOIT / RUNTIME CRASH:
    In `normalize_tempo_trace`:
    `nanos = [int(s["start_nano"]) for s in spans if s.get("start_nano")]`
    If a span dictionary contains `{"start_nano": "NOT_AN_INTEGER"}`,
    evaluating `int(s["start_nano"])` raises unhandled ValueError and crashes `normalize_tempo_trace`!
    """
    attempt_id = "att_tempo_crash"
    trace_data = {
        "status": "SUCCESS",
        "spans": [
            {
                "span_id": "s1",
                "name": "checkout_op",
                "service": "checkout-service",
                "start_nano": "CORRUPT_NANOSECONDS_STRING",
            }
        ],
    }

    obs = normalize_tempo_trace(
        attempt_id=attempt_id,
        target_service="checkout-service",
        trace_id="tr_crash",
        trace_data=trace_data,
        window=("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"),
    )
    assert obs.status == "SUCCESS"
    assert obs.trace_timestamp is None
