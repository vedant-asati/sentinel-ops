import pytest
from sentinel_ops.mcp.server import list_tools, mcp_registry


def test_list_mcp_tools():
    tools = list_tools()
    assert len(tools) == 5
    tool_names = {t["name"] for t in tools}
    assert "promql_range_query" in tool_names
    assert "tempo_get_trace" in tool_names
    assert "tempo_search_traces" in tool_names
    assert "calculate_blast_radius" in tool_names
    assert "query_graph_rag" in tool_names


@pytest.mark.asyncio
async def test_mcp_stdio_roundtrip():
    import io
    import json
    from sentinel_ops.mcp.server import serve_stdio

    stdin_buf = io.StringIO(
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}) + "\n"
        + json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}) + "\n"
    )
    stdout_buf = io.StringIO()
    await serve_stdio(stdin_stream=stdin_buf, stdout_stream=stdout_buf)
    lines = [json.loads(line) for line in stdout_buf.getvalue().strip().splitlines()]
    assert len(lines) == 2
    assert lines[0]["result"]["protocolVersion"] == "2024-11-05"
    assert len(lines[1]["result"]["tools"]) == 5


def test_mcp_calculate_blast_radius():
    res = mcp_registry.calculate_blast_radius("payment-service", action="restart")
    assert "checkout-service" in res["affected_callers"]
    assert res["blast_radius_score"] >= 0.35


def test_mcp_query_graph_rag():
    matches = mcp_registry.query_graph_rag(
        alert_text="checkout-service experiencing high latency and payment-service 504 timeout",
        target_service="checkout-service",
        incident_timestamp="2026-11-24T14:32:00Z",
        top_k=2,
    )
    assert len(matches) == 2
    assert matches[0]["incident_id"] == "INC-HIST-01"
