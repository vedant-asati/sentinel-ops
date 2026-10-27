import io
import json
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from sentinel_ops.mcp.server import serve_stdio, handle_jsonrpc_request, MCPToolRegistry
from sentinel_ops.mcp.prometheus_adapter import PrometheusAdapter


@pytest.mark.asyncio
async def test_mcp_stdio_multiline_json_parse_error():
    """PROTOCOL DEFICIENCY / TRANSPORT FRAGILITY:
    `serve_stdio` reads newline-delimited lines: `for raw_line in in_stream: line = raw_line.strip()`.
    If an MCP client sends multi-line formatted JSON-RPC requests (common with human operators,
    debuggers, or standard pretty-printers), `serve_stdio` fails to buffer across lines and
    emits JSON-RPC -32700 Parse errors for each line.
    """
    formatted_request = """{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/list",
  "params": {}
}
"""
    stdin_stream = io.StringIO(formatted_request)
    stdout_stream = io.StringIO()

    await serve_stdio(stdin_stream=stdin_stream, stdout_stream=stdout_stream)
    output_lines = [line for line in stdout_stream.getvalue().strip().split("\n") if line.strip()]

    # Buffers multi-line JSON object cleanly into 1 valid JSON-RPC response
    assert len(output_lines) == 1
    first_resp = json.loads(output_lines[0])
    assert first_resp["id"] == 1
    assert "result" in first_resp
    assert "tools" in first_resp["result"]


@pytest.mark.asyncio
async def test_mcp_tools_call_unhandled_exception_crashes_stdio_server():
    """Verify handle_jsonrpc_request / serve_stdio maps tool validation errors to JSON-RPC errors without crashing."""
    malformed_request = {
        "jsonrpc": "2.0",
        "id": 42,
        "method": "tools/call",
        "params": {
            "name": "tempo_search_traces",
            "arguments": {
                "service": "unauthorized-malicious-service",
                "start_iso": "2026-11-24T14:30:00Z",
                "end_iso": "2026-11-24T14:35:00Z",
            },
        },
    }

    stdin_stream = io.StringIO(json.dumps(malformed_request) + "\n")
    stdout_stream = io.StringIO()

    await serve_stdio(stdin_stream=stdin_stream, stdout_stream=stdout_stream)
    resp = json.loads(stdout_stream.getvalue().strip().splitlines()[0])
    assert resp["id"] == 42
    assert resp["error"]["code"] == -32602
    assert "is not in allowed services list" in resp["error"]["message"]


@pytest.mark.asyncio
async def test_prom_adapter_inverted_window_unvalidated():
    """Verify PrometheusAdapter.query_metric rejects inverted start/end windows locally as TOOL_FAILURE."""
    adapter = PrometheusAdapter(base_url="http://mock-prom:9090")

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        start = "2026-11-24T16:00:00Z"
        end = "2026-11-24T14:00:00Z"  # End is 2 hours before start!

        res = await adapter.query_metric(
            service="payment-service",
            metric_type="db_pool_active",
            window=(start, end),
        )

        assert res["status"] == "TOOL_FAILURE"
        assert "Invalid inverted window" in res["error"]
        assert len(mock_get.call_args_list) == 0


@pytest.mark.asyncio
async def test_prom_adapter_timeout_doubling_during_partition():
    """LATENCY / RESILIENCE DEFICIENCY:
    When Prometheus is partitioned or lagging, if the range query returns an empty result,
    `query_metric` immediately initiates a fallback instant query:
    `client.get(f"{self.base_url}/api/v1/query", params={"query": promql}, timeout=effective_timeout)`.
    During network partitions where queries take the full timeout, this doubles the blocking
    latency (timeout + timeout = 2x timeout) per metric probe!
    """
    adapter = PrometheusAdapter(base_url="http://mock-prom:9090", timeout=5.0)

    call_count = 0
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        # Initial query returns 200 with empty result
        empty_resp = MagicMock(status_code=200, json=lambda: {"status": "success", "data": {"result": []}}, raise_for_status=lambda: None)
        mock_get.return_value = empty_resp

        res = await adapter.query_metric(
            service="payment-service",
            metric_type="db_pool_active",
            window=("2026-11-24T14:30:00Z", "2026-11-24T14:35:00Z"),
        )

        # Confirm TWO GET requests were issued serially
        assert len(mock_get.call_args_list) == 2
        # First query was range
        assert "/api/v1/query_range" in mock_get.call_args_list[0][0][0]
        # Fallback was instant query
        assert "/api/v1/query" in mock_get.call_args_list[1][0][0]
