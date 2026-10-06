from sentinel_ops.analytics.dora import compute_dora_benchmark


def test_compute_dora_benchmark():
    metrics = compute_dora_benchmark()
    assert metrics.mttd_seconds == 5.0
    assert metrics.mttr_seconds <= 2.0
    assert metrics.acceleration_factor > 1000.0
    assert metrics.change_failure_rate == 0.0
    assert metrics.correct_abstention_rate == 1.0
    assert "Elite" in metrics.dora_tier
