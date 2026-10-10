import pytest
import httpx
from unittest.mock import AsyncMock, patch, MagicMock
from sentinel_ops.mcp.prometheus_adapter import PrometheusAdapter, ALLOWED_SERVICES, METRIC_QUERY_TEMPLATES
from sentinel_ops.mcp.tempo_adapter import TempoAdapter


@pytest.mark.asyncio
async def test_prom_adapter_window_unpacking_unhandled_crash():
    """SAFETY HARDENING REGRESSION TEST:
    PrometheusAdapter.query_metric must safely validate window parameter,
    returning TOOL_FAILURE gracefully on None, empty tuple, or malformed tuple without crashing.
    """
    adapter = PrometheusAdapter(base_url="http://mock-prom:9090")

    # 1. None window -> TOOL_FAILURE
    res1 = await adapter.query_metric(
        service="payment-service",
        metric_type="db_pool_active",
        window=None,  # type: ignore
    )
    assert res1["status"] == "TOOL_FAILURE"
    assert "Invalid window" in res1["error"]

    # 2. Empty tuple -> TOOL_FAILURE
    res2 = await adapter.query_metric(
        service="payment-service",
        metric_type="db_pool_active",
        window=(),  # type: ignore
    )
    assert res2["status"] == "TOOL_FAILURE"
    assert "Invalid window" in res2["error"]

    # 3. 1-tuple -> TOOL_FAILURE
    res3 = await adapter.query_metric(
        service="payment-service",
        metric_type="db_pool_active",
        window=("2026-11-24T00:00:00Z",),  # type: ignore
    )
    assert res3["status"] == "TOOL_FAILURE"
    assert "Invalid window" in res3["error"]


@pytest.mark.asyncio
async def test_prom_adapter_null_data_json_attribute_error_crash():
    """SAFETY HARDENING REGRESSION TEST:
    PrometheusAdapter must handle {"data": null} responses without raising AttributeError.
    """
    adapter = PrometheusAdapter(base_url="http://mock-prom:9090")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"status": "error", "data": None}
    mock_resp.raise_for_status.return_value = None

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await adapter.query_metric(
            service="payment-service",
            metric_type="db_pool_active",
            window=("2026-11-24T00:00:00Z", "2026-11-24T00:05:00Z"),
        )
        # Safely handled as EMPTY (no data result) without crashing
        assert res["status"] in ("EMPTY", "TOOL_FAILURE")
        assert "'NoneType' object has no attribute 'get'" not in res.get("error", "")


@pytest.mark.asyncio
async def test_prom_adapter_nan_and_inf_metric_values_corruption():
    """TELEMETRY HARDENING REGRESSION TEST:
    Verifies that Prometheus metrics with NaN or Inf are safely formatted and handled.
    """
    adapter = PrometheusAdapter(base_url="http://mock-prom:9090")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "status": "success",
        "data": {
            "result": [
                {
                    "metric": {"service": "payment-service"},
                    "values": [[1732461000, "NaN"], [1732461015, "+Inf"], [1732461030, "-Inf"]],
                }
            ]
        },
    }
    mock_resp.raise_for_status.return_value = None

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await adapter.query_metric(
            service="payment-service",
            metric_type="db_pool_active",
            window=("2026-11-24T00:00:00Z", "2026-11-24T00:05:00Z"),
        )
        assert res["status"] == "SUCCESS"
        assert len(res["result"]) > 0


@pytest.mark.asyncio
async def test_prom_adapter_step_param_unvalidated_injection():
    """SECURITY HARDENING REGRESSION TEST:
    Step parameter must be sanitized against query string injection attacks.
    """
    adapter = PrometheusAdapter(base_url="http://mock-prom:9090")

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"status": "success", "data": {"result": []}}
        mock_get.return_value = mock_resp

        await adapter.query_metric(
            service="payment-service",
            metric_type="db_pool_active",
            window=("2026-11-24T00:00:00Z", "2026-11-24T00:05:00Z"),
            step="15s&extra_param=injected_payload#fragment",
        )
        call_params = mock_get.call_args_list[0][1]["params"]
        # Special characters (&, #, =) stripped
        assert "&" not in call_params["step"]
        assert "#" not in call_params["step"]
        assert "=" not in call_params["step"]


@pytest.mark.asyncio
async def test_tempo_adapter_path_traversal_via_trace_id():
    """SECURITY HARDENING REGRESSION TEST:
    TempoAdapter must reject path traversal sequences (../) in trace_id and return TOOL_FAILURE.
    """
    adapter = TempoAdapter(base_url="http://mock-tempo:53201")

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        malicious_trace_id = "../../metrics"
        res = await adapter.get_trace_waterfall(trace_id=malicious_trace_id)
        assert res["status"] == "TOOL_FAILURE"
        assert "Invalid trace_id" in res["error"]
        # Network request never executed
        mock_get.assert_not_called()


@pytest.mark.asyncio
async def test_tempo_adapter_negative_bottleneck_and_empty_trace_inversion():
    """REPRESENTATION HARDENING REGRESSION TEST:
    Empty traces must report 0.0ms exclusive duration (never -1.00ms).
    """
    adapter = TempoAdapter(base_url="http://mock-tempo:53201")

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"batches": [{"scopeSpans": [{"spans": []}]}]}
        mock_get.return_value = mock_resp

        res = await adapter.get_trace_waterfall(trace_id="trace_empty_01")
        assert res["status"] == "EMPTY"
        assert res["bottleneck_service"] is None
        assert res["bottleneck_duration_ms"] == 0.0
        assert "(-1.00ms" not in res["formatted"]


@pytest.mark.asyncio
async def test_tempo_adapter_index_error_crash_on_empty_attributes():
    """SAFETY HARDENING REGRESSION TEST:
    Batches with empty attributes '[]' must not raise IndexError.
    """
    adapter = TempoAdapter(base_url="http://mock-tempo:53201")

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "batches": [
                {
                    "resource": {"attributes": []},
                    "scopeSpans": [
                        {
                            "spans": [
                                {
                                    "spanId": "s1",
                                    "parentSpanId": "",
                                    "name": "root",
                                    "startTimeUnixNano": 1000000000,
                                    "endTimeUnixNano": 2000000000,
                                }
                            ]
                        }
                    ],
                }
            ]
        }
        mock_get.return_value = mock_resp

        res = await adapter.get_trace_waterfall(trace_id="trace_empty_attrs")
        assert res["status"] == "SUCCESS"
        assert res["spans"][0]["service"] == "unknown"


@pytest.mark.asyncio
async def test_tempo_adapter_null_timestamp_type_error_crash():
    """SAFETY HARDENING REGRESSION TEST:
    Spans with startTimeUnixNano: null must not raise TypeError.
    """
    adapter = TempoAdapter(base_url="http://mock-tempo:53201")

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "batches": [
                {
                    "resource": {"attributes": [{"value": {"stringValue": "payment-service"}}]},
                    "scopeSpans": [
                        {
                            "spans": [
                                {
                                    "spanId": "s1",
                                    "parentSpanId": "",
                                    "name": "null_timestamp_span",
                                    "startTimeUnixNano": None,
                                    "endTimeUnixNano": 2000000000,
                                }
                            ]
                        }
                    ],
                }
            ]
        }
        mock_get.return_value = mock_resp

        res = await adapter.get_trace_waterfall(trace_id="trace_null_time")
        assert res["status"] == "SUCCESS"
        assert res["spans"][0]["service"] == "payment-service"


@pytest.mark.asyncio
async def test_tempo_adapter_parallel_child_exclusive_time_erasure():
    """CAUSAL ATTRIBUTION HARDENING REGRESSION TEST:
    Parent spans with parallel concurrent child calls must compute exclusive time via interval unions,
    preserving genuine parent self-time (10ms) instead of wiping it to 0.0ms.
    """
    adapter = TempoAdapter(base_url="http://mock-tempo:53201")

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "batches": [
                {
                    "resource": {"attributes": [{"value": {"stringValue": "checkout-service"}}]},
                    "scopeSpans": [
                        {
                            "spans": [
                                {
                                    "spanId": "p1",
                                    "parentSpanId": "",
                                    "name": "parent_parallel_call",
                                    "startTimeUnixNano": 0,
                                    "endTimeUnixNano": 110_000_000,  # 110 ms
                                },
                                {
                                    "spanId": "c1",
                                    "parentSpanId": "p1",
                                    "name": "child_rpc_1",
                                    "startTimeUnixNano": 5_000_000,
                                    "endTimeUnixNano": 105_000_000,  # 100 ms
                                },
                                {
                                    "spanId": "c2",
                                    "parentSpanId": "p1",
                                    "name": "child_rpc_2",
                                    "startTimeUnixNano": 5_000_000,
                                    "endTimeUnixNano": 105_000_000,  # 100 ms
                                },
                            ]
                        }
                    ],
                }
            ]
        }
        mock_get.return_value = mock_resp

        res = await adapter.get_trace_waterfall(trace_id="trace_parallel")
        assert res["status"] == "SUCCESS"
        parent_span = [s for s in res["spans"] if s["span_id"] == "p1"][0]
        # Self-time is preserved at 10.0ms!
        assert parent_span["exclusive_duration_ms"] == 10.0
