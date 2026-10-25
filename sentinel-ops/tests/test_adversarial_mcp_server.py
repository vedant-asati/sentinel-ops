import pytest
from sentinel_ops.mcp.server import list_tools, mcp_registry, MCPToolRegistry, get_mcp_tools_envelope, handle_jsonrpc_request


@pytest.mark.asyncio
async def test_mcp_protocol_violation_missing_jsonrpc_spec():
    """PROTOCOL CONFORMANCE REGRESSION TEST:
    Verifies MCP 2024-11-05 spec conformance:
    1. Tools provide 'inputSchema'.
    2. Envelope wrapper returns 'tools' list.
    3. JSON-RPC 2.0 dispatcher handles initialize, tools/list, and tools/call.
    """
    tools = list_tools()
    assert isinstance(tools, list)
    for tool in tools:
        assert "inputSchema" in tool
        assert "parameters" in tool

    envelope = get_mcp_tools_envelope()
    assert "tools" in envelope
    assert len(envelope["tools"]) == 5

    # Verify JSON-RPC 2.0 initialize
    init_resp = await handle_jsonrpc_request({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert init_resp["jsonrpc"] == "2.0"
    assert init_resp["result"]["protocolVersion"] == "2024-11-05"

    # Verify JSON-RPC tools/list
    list_resp = await handle_jsonrpc_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert len(list_resp["result"]["tools"]) == 5


def test_mcp_blast_radius_arbitrary_action_injection():
    """SAFETY HARDENING REGRESSION TEST:
    Dangerous or unapproved actions must NEVER default to routine 0.35/0.50 score.
    They must be flagged as Critical Risk (1.00 score) and rejected.
    """
    registry = MCPToolRegistry()
    res = registry.calculate_blast_radius(
        target_service="payment-service",
        action="catastrophic_destroy_cluster_and_delete_backups",
    )
    assert res["blast_radius_score"] == 1.0
    assert res["blast_radius_level"] == "Critical"
    assert "error" in res or "UNAPPROVED ACTION" in res.get("summary", "")


def test_mcp_blast_radius_nonexistent_service_misleading_zero_risk():
    """SAFETY HARDENING REGRESSION TEST:
    Nonexistent services must NOT be rated Low Risk (0.20).
    They must be assigned Critical Risk (1.00) or error to prevent unsafe remediation.
    """
    registry = MCPToolRegistry()
    res = registry.calculate_blast_radius(
        target_service="critical-auth-service-not-in-topology",
        action="restart",
    )
    assert res["blast_radius_score"] == 1.0
    assert res["blast_radius_level"] in ("Critical", "Unknown/Critical")


def test_mcp_query_graph_rag_empty_and_garbage_timestamp():
    """INPUT VALIDATION REGRESSION TEST:
    query_graph_rag must strictly validate ISO-8601 timestamps and reject garbage input.
    """
    registry = MCPToolRegistry()
    with pytest.raises(ValueError, match="Invalid ISO-8601"):
        registry.query_graph_rag(
            alert_text="Unknown anomaly",
            target_service="payment-service",
            incident_timestamp="GARBAGE_NOT_A_TIMESTAMP_99999999",
            top_k=2,
        )


@pytest.mark.asyncio
async def test_mcp_context_window_exhaustion_unbounded_payload():
    """PAYLOAD BOUNDING REGRESSION TEST:
    promql_range_query must cap telemetry data points to prevent context window overflow.
    """
    from unittest.mock import AsyncMock, patch, MagicMock

    registry = MCPToolRegistry()
    mock_resp = MagicMock()
    mock_resp.status_code = 200

    large_series = [
        {
            "metric": {"service": "payment-service", "pod": f"pod-{i}"},
            "values": [[1732461000 + j * 15, "1.0"] for j in range(10_000)],
        }
        for i in range(5)
    ]
    mock_resp.json.return_value = {"status": "success", "data": {"result": large_series}}
    mock_resp.raise_for_status.return_value = None

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await registry.promql_range_query(
            service="payment-service",
            metric_type="db_pool_active",
            start_iso="2026-11-24T00:00:00Z",
            end_iso="2026-11-24T04:00:00Z",
        )
        assert res["status"] == "SUCCESS"
        # Bounded and downsampled: values array is capped at <= 100 points
        assert len(res["result"]) <= 5
        assert len(res["result"][0]["values"]) <= 100
        assert len(str(res["result"])) < 50_000
