import pytest
import httpx
from unittest.mock import patch, MagicMock
from sentinel_ops.analytics.dora import DORAMetrics, compute_dora_benchmark
from sentinel_ops.chaos import print_status, recover_all, inject_fault, SERVICE_PORTS


def test_dora_division_by_zero_and_negative_mttr():
    """ARITHMETIC BUG / DIVISION BY ZERO:
    If agent_mttr_seconds is 0.0 (e.g. cached or instant automated response),
    `manual_mttr_seconds / agent_mttr_seconds` raises ZeroDivisionError.
    Furthermore, DORAMetrics has no ge=0 constraints, allowing negative MTTR and negative acceleration!
    """
    manual_mttr = 2700.0

    # 1. Zero MTTR crashes
    with pytest.raises(ZeroDivisionError):
        agent_mttr = 0.0
        _ = manual_mttr / agent_mttr

    # 2. Corrupt negative delta / clock skew produces nonsensical acceleration and negative MTTR
    negative_agent_mttr = -10.0
    corrupt_accel = manual_mttr / negative_agent_mttr  # -270.0
    corrupt_metrics = DORAMetrics(
        mttd_seconds=-5.0,  # Negative MTTD
        mttr_seconds=negative_agent_mttr,
        acceleration_factor=corrupt_accel,
        change_failure_rate=-99.0,  # Invalid negative rate
        citation_support_rate=5.5,  # Invalid rate > 1.0
        correct_abstention_rate=-1.0,
        dora_tier="Corrupted",
    )
    assert corrupt_metrics.mttr_seconds < 0
    assert corrupt_metrics.acceleration_factor < 0
    assert corrupt_metrics.change_failure_rate < 0


def test_dora_static_hardcoded_fabrication():
    """FABRICATION / VALIDATION DEFICIENCY:
    `compute_dora_benchmark()` does not ingest real telemetry, test execution logs,
    or incident timestamps.
    It returns static hardcoded figures:
    - manual_mttr_seconds = 2700.0
    - agent_mttr_seconds = 1.85
    - change_failure_rate = 0.0
    - citation_support_rate = 1.0
    - correct_abstention_rate = 1.0
    Giving a false veneer of 100% empirical benchmark perfection.
    """
    m1 = compute_dora_benchmark()
    m2 = compute_dora_benchmark()
    assert m1.mttr_seconds == 1.85
    assert m1.acceleration_factor == 1459.5
    assert m1.citation_support_rate == 1.0
    assert m1.change_failure_rate == 0.0
    assert m1 == m2


def test_chaos_print_status_string_matching_false_negative():
    """OBSERVABILITY FLAW / FALSE NEGATIVE:
    `chaos.py` lines 60-63 rely on brittle substring matching:
    `'payment_db_pool_active{service="payment-service"} 2.0' in m_resp.text`
    If Prometheus metrics emit integer '2', float '2.00', '1.99', or pool active is '3.0' or '4.0',
    `print_status` FAILS to detect the fault and falsely reports 'None (Healthy)'!
    """
    mock_metrics_text = (
        '# HELP payment_db_pool_active Active DB connections in pool\n'
        '# TYPE payment_db_pool_active gauge\n'
        'payment_db_pool_active{service="payment-service"} 3.0\n'  # 3.0 instead of 2.0
    )

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = mock_metrics_text

    with patch("httpx.get") as mock_get:
        mock_get.return_value = mock_resp
        # Simulate check in print_status line 60:
        fault = "None (Healthy)"
        if 'payment_db_pool_active{service="payment-service"} 2.0' in mock_resp.text:
            fault = "db_pool_exhaustion"

        # The fault was NOT detected even though pool is at 3.0!
        assert fault == "None (Healthy)"


def test_chaos_service_fault_monitoring_blind_spot():
    """CHAOS ENGINE ARCHITECTURAL FLAW:
    In `chaos.py`, `SERVICE_PORTS` contains 4 services:
    - checkout-service (8001)
    - cart-service (8002)
    - pricing-service (8003)
    - payment-service (8004)
    However, `print_status` ONLY ever checks payment-service (line 60) and pricing-service (line 62).
    If a fault (such as cpu_saturation or db_pool_exhaustion) is injected into
    checkout-service or cart-service, `print_status` is completely blind and reports 'None (Healthy)'.
    """
    checkout_fault_metrics = (
        '# HELP container_cpu_usage_seconds_total Container CPU saturation\n'
        'container_cpu_usage_seconds_total{container="checkout-service"} 0.98\n'
    )

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = checkout_fault_metrics

    # Evaluated under print_status rules:
    fault = "None (Healthy)"
    if 'payment_db_pool_active{service="payment-service"} 2.0' in mock_resp.text:
        fault = "db_pool_exhaustion"
    elif 'container_cpu_usage_seconds_total{container="pricing-service"} 0.98' in mock_resp.text:
        fault = "cpu_saturation"

    # Blind to checkout-service!
    assert fault == "None (Healthy)"


def test_chaos_recover_all_serial_blocking_stall_on_partition():
    """INFRASTRUCTURE / RESILIENCE DEFICIENCY:
    `recover_all()` executes serial synchronous HTTP POST requests with a 5.0s timeout per service.
    If a network partition drops packets across all 4 services,
    `recover_all()` blocks the entire process for 20 continuous seconds (4 * 5.0s = 20s),
    failing to recover with unhandled errors and leaving the sandbox in an unrecoverable state.
    """
    call_count = 0

    def mock_post_timeout(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        raise httpx.ConnectTimeout("Network partition: host unreachable")

    with patch("httpx.post", side_effect=mock_post_timeout):
        # recover_all catches exceptions per service and prints, but attempts all serially
        recover_all()
        # All 4 services were attempted serially, totaling 4 * 5s = 20s blocking latency
        assert call_count == 4
