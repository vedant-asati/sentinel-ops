import pytest
from sentinel_ops.mcp.server import list_tools, mcp_registry, MCPToolRegistry


def test_mcp_protocol_violation_missing_jsonrpc_spec():
    """PROTOCOL VIOLATION:
    The MCP specification (Model Context Protocol 2024-11-05) mandates JSON-RPC 2.0 framing
    with standard methods (e.g. `tools/list`, `tools/call`, `initialize`) and strict
    error response formats (code, message, data).
    `sentinel_ops.mcp.server` implements zero JSON-RPC framing, no transport handlers
    (stdio or SSE), and returns bare Python dicts without standard JSON-RPC envelopes.
    """
    tools = list_tools()
    assert isinstance(tools, list)
    # MCP standard tools/list must wrap in {"tools": [...]}
    assert not isinstance(tools, dict) or "tools" not in tools

    # Tool definitions lack required inputSchema field from MCP spec (uses raw "parameters")
    for tool in tools:
        assert "parameters" in tool
        assert "inputSchema" not in tool  # MCP 2024-11-05 spec requires "inputSchema"


def test_mcp_blast_radius_arbitrary_action_injection():
    """MALFORMED TOOL CALL / SAFETY FLAW:
    In list_tools(), action is documented as enum: ['config_reload', 'restart', 'db_pool_resize'].
    However, MCPToolRegistry.calculate_blast_radius performs ZERO parameter validation on `action`.
    Arbitrary dangerous actions ('destroy_cluster', 'drop_all_tables', 'sudo rm -rf /')
    are silently accepted and fall back to a routine 0.5 action weight!
    """
    registry = MCPToolRegistry()
    res = registry.calculate_blast_radius(
        target_service="payment-service",
        action="catastrophic_destroy_cluster_and_delete_backups",
    )
    # The catastrophic action is silently accepted and scored identically to a routine 'restart'
    restart_res = registry.calculate_blast_radius(
        target_service="payment-service",
        action="restart",
    )
    # Destroy cluster receives the exact same score as restart (0.35) due to silent 0.5 fallback
    assert res["target_service"] == "payment-service"
    assert res["blast_radius_score"] == restart_res["blast_radius_score"] == 0.35
    assert res["blast_radius_level"] == "Medium"


def test_mcp_blast_radius_nonexistent_service_misleading_zero_risk():
    """MALFORMED TOOL CALL / SAFETY FLAW:
    Passing a nonexistent or misspelled service (e.g. 'auth-service', 'billing')
    to calculate_blast_radius does not raise an error or return TOOL_FAILURE.
    Instead, it returns Low Risk (0.20) with an empty affected caller set,
    dangerously misleading an automated remediation agent that deleting or restarting
    an unknown service has negligible (Low) risk!
    """
    registry = MCPToolRegistry()
    res = registry.calculate_blast_radius(
        target_service="critical-auth-service-not-in-topology",
        action="restart",
    )
    assert res["blast_radius_score"] == 0.20
    assert res["blast_radius_level"] == "Low"
    assert res["affected_callers"] == []


def test_mcp_query_graph_rag_empty_and_garbage_timestamp():
    """MALFORMED TOOL CALL:
    query_graph_rag accepts malformed or arbitrary strings for incident_timestamp
    without ISO-8601 validation.
    """
    registry = MCPToolRegistry()
    res = registry.query_graph_rag(
        alert_text="Unknown anomaly",
        target_service="payment-service",
        incident_timestamp="GARBAGE_NOT_A_TIMESTAMP_99999999",
        top_k=2,
    )
    # GraphRAG swallows the parsing error and still returns incidents
    assert isinstance(res, list)
    assert len(res) <= 2


@pytest.mark.asyncio
async def test_mcp_context_window_exhaustion_unbounded_payload():
    """BUFFER OVERFLOW / CONTEXT EXHAUSTION:
    While `wrap_telemetry` caps formatted string at 4000 chars, the MCP adapter returns
    the raw Prometheus response in the `'result'` field UNBOUNDED.
    A query with thousands of time series points creates massive memory allocations
    and risks crashing LLM context windows or SSE streams.
    """
    from unittest.mock import AsyncMock, patch, MagicMock

    registry = MCPToolRegistry()
    mock_resp = MagicMock()
    mock_resp.status_code = 200

    # Generate 50,000 data points across 5 series
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
        # The 'result' field holds all 50,000 points without any truncation
        assert len(res["result"]) == 5
        assert len(res["result"][0]["values"]) == 10_000
        # Formatted XML is capped, but the tool return object contains the massive uncompressed payload
        assert len(str(res["result"])) > 1_000_000  # Over 1 Megabyte!
