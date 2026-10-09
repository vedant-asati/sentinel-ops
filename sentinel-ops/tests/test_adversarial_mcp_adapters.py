import pytest
import httpx
from unittest.mock import AsyncMock, patch, MagicMock
from sentinel_ops.mcp.prometheus_adapter import PrometheusAdapter, ALLOWED_SERVICES, METRIC_QUERY_TEMPLATES
from sentinel_ops.mcp.tempo_adapter import TempoAdapter


@pytest.mark.asyncio
async def test_prom_adapter_window_unpacking_unhandled_crash():
    """EXPLOIT / RUNTIME CRASH:
    PrometheusAdapter.query_metric unpacks window (`start_iso, end_iso = window`)
    on line 53 OUTSIDE the try...except block.
    Passing None, an empty tuple (), or a 1-tuple raises an unhandled TypeError/ValueError
    that crashes the calling coroutine instead of returning TOOL_FAILURE.
    """
    adapter = PrometheusAdapter(base_url="http://mock-prom:9090")

    # 1. None window -> TypeError
    with pytest.raises(TypeError):
        await adapter.query_metric(
            service="payment-service",
            metric_type="db_pool_active",
            window=None,  # type: ignore
        )

    # 2. Empty tuple -> ValueError
    with pytest.raises(ValueError):
        await adapter.query_metric(
            service="payment-service",
            metric_type="db_pool_active",
            window=(),  # type: ignore
        )

    # 3. 1-tuple -> ValueError (not enough values to unpack)
    with pytest.raises(ValueError):
        await adapter.query_metric(
            service="payment-service",
            metric_type="db_pool_active",
            window=("2026-11-24T00:00:00Z",),  # type: ignore
        )


@pytest.mark.asyncio
async def test_prom_adapter_null_data_json_attribute_error_crash():
    """EXPLOIT / CRASH:
    If Prometheus returns a response with {"data": null} (standard in error/bad_data responses),
    `resp.json().get("data", {}).get("result")` fails because .get("data", {}) returns None,
    and None.get("result") raises AttributeError: 'NoneType' object has no attribute 'get'.
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
        assert res["status"] == "TOOL_FAILURE"
        assert "'NoneType' object has no attribute 'get'" in res["error"]


@pytest.mark.asyncio
async def test_prom_adapter_nan_and_inf_metric_values_corruption():
    """EXPLOIT / TELEMETRY CORRUPTION:
    Prometheus metrics can legitimately return 'NaN', '+Inf', or '-Inf'.
    The adapter does not validate or sanitize numeric payloads, wrapping raw NaN/Inf strings.
    Downstream triage rules that perform float(val) inherit NaN/Inf, breaking comparison logic.
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
        raw_vals = res["result"][0]["values"]
        # NaN is unhandled string
        assert raw_vals[0][1] == "NaN"
        import math
        assert math.isnan(float(raw_vals[0][1]))
        assert math.isinf(float(raw_vals[1][1]))
        # Float comparisons with NaN silently fail (NaN > 2.0 is False, NaN < 2.0 is False, NaN == NaN is False)
        nan_val = float(raw_vals[0][1])
        assert not (nan_val >= 2.0)
        assert not (nan_val < 2.0)
        assert not (nan_val == nan_val)


@pytest.mark.asyncio
async def test_prom_adapter_step_param_unvalidated_injection():
    """EXPLOIT:
    The `step` parameter is unvalidated and directly passed to httpx query parameters.
    An arbitrary string (or malformed step) is passed directly to the Prometheus backend.
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
        # Verify the raw unescaped injection was passed to the initial query_range call
        call_params = mock_get.call_args_list[0][1]["params"]
        assert call_params["step"] == "15s&extra_param=injected_payload#fragment"


@pytest.mark.asyncio
async def test_tempo_adapter_path_traversal_via_trace_id():
    """EXPLOIT / SECURITY VULNERABILITY:
    TempoAdapter.get_trace_waterfall formats trace_id directly into the URL path:
    `client.get(f"{self.base_url}/api/traces/{trace_id}")`.
    A trace_id containing path traversal sequences `../../` escapes the traces endpoint
    to query arbitrary endpoints on the Tempo server (e.g. `/api/v1/status`, `/metrics`).
    """
    adapter = TempoAdapter(base_url="http://mock-tempo:53201")

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"batches": []}
        mock_get.return_value = mock_resp

        malicious_trace_id = "../../metrics"
        await adapter.get_trace_waterfall(trace_id=malicious_trace_id)

        # Confirm url path traversal
        called_url = mock_get.call_args[0][0]
        assert called_url == "http://mock-tempo:53201/api/traces/../../metrics"


@pytest.mark.asyncio
async def test_tempo_adapter_negative_bottleneck_and_empty_trace_inversion():
    """VULNERABILITY / CORRUPT REPORT:
    When a trace has no spans (empty batches or empty scopeSpans),
    `bottleneck_span` is None and `max_exclusive` remains initialized to -1.0.
    The formatted output reports:
    `Bottleneck Service: None (-1.00ms exclusive)`
    exposing a negative bottleneck duration.
    Furthermore, if all spans have 0.0ms duration, max_exclusive (-1.0) is exceeded by 0.0,
    falsely declaring the first 0ms span as the bottleneck!
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
        assert res["bottleneck_duration_ms"] == -1.0
        assert "(-1.00ms exclusive)" in res["formatted"]


@pytest.mark.asyncio
async def test_tempo_adapter_index_error_crash_on_empty_attributes():
    """EXPLOIT / CRASH:
    Line 49:
    `svc = b.get("resource", {}).get("attributes", [{}])[0].get("value", {}).get("stringValue", "unknown")`
    If a batch has `"attributes": []`, the default `[{}]` is NOT used, and evaluating
    `[][0]` raises IndexError: list index out of range, terminating the adapter with an unhandled exception.
    """
    adapter = TempoAdapter(base_url="http://mock-tempo:53201")

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "batches": [
                {
                    "resource": {"attributes": []},  # Empty attributes list
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
        assert res["status"] == "TOOL_FAILURE"
        assert "list index out of range" in res["error"]


@pytest.mark.asyncio
async def test_tempo_adapter_null_timestamp_type_error_crash():
    """EXPLOIT / CRASH:
    Line 56: `start_nano = int(s.get("startTimeUnixNano", 0))`
    If a span JSON has `"startTimeUnixNano": null`, `.get("startTimeUnixNano", 0)` returns None.
    int(None) raises TypeError: int() argument must be a string, a bytes-like object or a real number, not 'NoneType'.
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
                                    "startTimeUnixNano": None,  # JSON null
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
        assert res["status"] == "TOOL_FAILURE"
        assert "int() argument must be a string" in res["error"]


@pytest.mark.asyncio
async def test_tempo_adapter_parallel_child_exclusive_time_erasure():
    """LOGICAL FLAW / METRIC DISTORTION:
    When a parent span executes concurrent child calls (e.g. 5 parallel RPCs of 100ms each in a 110ms span),
    TempoAdapter naively sums child durations: 5 * 100ms = 500ms.
    exclusive_ms = max(0.0, 110 - 500) = 0.0ms.
    The parent span's 10ms of genuine self-time is completely wiped out,
    making high-concurrency coordinator spans appear to have 0ms latency.
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
        # Self-time wiped out to 0.0 instead of 10.0 ms!
        assert parent_span["exclusive_duration_ms"] == 0.0
