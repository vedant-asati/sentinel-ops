import asyncio
import json
import logging
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from sentinel_ops.agents.blast_radius import calculate_reverse_blast_radius
from sentinel_ops.mcp.prometheus_adapter import PrometheusAdapter
from sentinel_ops.mcp.tempo_adapter import TempoAdapter
from sentinel_ops.memory.graph_rag import TopologyGraphRAG

logger = logging.getLogger(__name__)


ALLOWED_REMEDIATION_ACTIONS = {"config_reload", "restart", "db_pool_resize"}


class MCPToolRegistry:
    """Standard Model Context Protocol (MCP) tool registry exposing bounded telemetry tools."""

    def __init__(self):
        self.prom_adapter = PrometheusAdapter()
        self.tempo_adapter = TempoAdapter()
        self.graph_rag = TopologyGraphRAG()

    async def promql_range_query(
        self,
        service: str,
        metric_type: str,
        start_iso: str,
        end_iso: str,
    ) -> Dict[str, Any]:
        """Queries Prometheus metrics over an anchored time window [start_iso, end_iso]."""
        raw_res = await self.prom_adapter.query_metric(
            service=service,
            metric_type=metric_type,  # type: ignore
            window=(start_iso, end_iso),
        )
        # Cap result array to prevent context window exhaustion
        if raw_res.get("status") == "SUCCESS" and "result" in raw_res:
            series_list = raw_res["result"][:5]
            for s in series_list:
                vals = s.get("values", [])
                if len(vals) > 100:
                    # Keep first 50 and last 50 points
                    s["values"] = vals[:50] + vals[-50:]
            raw_res["result"] = series_list
        return raw_res

    async def tempo_get_trace(self, trace_id: str) -> Dict[str, Any]:
        """Retrieves and analyzes a distributed trace waterfall from Tempo."""
        return await self.tempo_adapter.get_trace_waterfall(trace_id=trace_id)

    def calculate_blast_radius(self, target_service: str, action: str = "restart") -> Dict[str, Any]:
        """Computes upstream caller transitive blast radius and risk score with strict parameter validation."""
        if action not in ALLOWED_REMEDIATION_ACTIONS:
            return {
                "target_service": target_service,
                "error": f"Invalid or unapproved remediation action '{action}'. Approved actions: {list(ALLOWED_REMEDIATION_ACTIONS)}",
                "blast_radius_score": 1.0,
                "blast_radius_level": "Critical",
                "affected_callers": [],
                "summary": f"UNAPPROVED ACTION '{action}' on '{target_service}' blocked by MCP safety policy (Score: 1.00, Critical Risk)",
            }
        return calculate_reverse_blast_radius(target_service=target_service, action=action)

    def query_graph_rag(
        self,
        alert_text: str,
        target_service: str,
        incident_timestamp: str,
        top_k: int = 2,
    ) -> List[Dict[str, Any]]:
        """Retrieves top-k historical incident postmortems using topology-aware GraphRAG with timestamp validation."""
        # Validate ISO-8601 timestamp
        from datetime import datetime
        try:
            datetime.fromisoformat(incident_timestamp.replace("Z", "+00:00"))
        except (ValueError, TypeError, AttributeError):
            raise ValueError(f"Invalid ISO-8601 incident_timestamp: '{incident_timestamp}'")

        matches = self.graph_rag.retrieve(
            alert_text=alert_text,
            target_service=target_service,
            incident_timestamp=incident_timestamp,
            top_k=top_k,
        )
        return [
            {
                "incident_id": m["postmortem"].incident_id,
                "title": m["postmortem"].title,
                "root_cause_service": m["postmortem"].root_cause_service,
                "mechanism": m["postmortem"].mechanism,
                "resolution": m["postmortem"].resolution,
                "composite_score": m["composite_score"],
            }
            for m in matches
        ]


# Singleton tool registry instance
mcp_registry = MCPToolRegistry()


def list_tools() -> List[Dict[str, Any]]:
    """Returns tool schemas in standard MCP format conforming to MCP 2024-11-05 spec."""
    tools = [
        {
            "name": "promql_range_query",
            "description": "Server-enforced time-anchored query for Prometheus metrics.",
            "parameters": {
                "type": "object",
                "properties": {
                    "service": {"type": "string", "enum": ["checkout-service", "cart-service", "pricing-service", "payment-service"]},
                    "metric_type": {
                        "type": "string",
                        "enum": [
                            "error_rate",
                            "latency_p95",
                            "db_pool_active",
                            "db_pool_size",
                            "db_pool_acquire_timeouts_total",
                            "upstream_connect_timeouts_total",
                            "cpu_saturation",
                            "memory_usage",
                            "container_restarts",
                        ],
                    },
                    "start_iso": {"type": "string"},
                    "end_iso": {"type": "string"},
                },
                "required": ["service", "metric_type", "start_iso", "end_iso"],
            },
        },
        {
            "name": "tempo_get_trace",
            "description": "Retrieves and isolates slow spans from Tempo distributed traces.",
            "parameters": {
                "type": "object",
                "properties": {
                    "trace_id": {"type": "string"},
                },
                "required": ["trace_id"],
            },
        },
        {
            "name": "calculate_blast_radius",
            "description": "Calculates upstream dependency blast radius for a service.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target_service": {"type": "string"},
                    "action": {"type": "string", "enum": ["config_reload", "restart", "db_pool_resize"]},
                },
                "required": ["target_service"],
            },
        },
        {
            "name": "query_graph_rag",
            "description": "Retrieves top-k historical incident postmortems using topology-aware GraphRAG.",
            "parameters": {
                "type": "object",
                "properties": {
                    "alert_text": {"type": "string"},
                    "target_service": {"type": "string"},
                    "incident_timestamp": {"type": "string"},
                },
                "required": ["alert_text", "target_service", "incident_timestamp"],
            },
        },
    ]
    # Conform to standard MCP 2024-11-05 inputSchema
    for t in tools:
        t["inputSchema"] = dict(t["parameters"])
    return tools


def get_mcp_tools_envelope() -> Dict[str, Any]:
    """Returns standard MCP JSON-RPC tools/list response structure."""
    return {"tools": list_tools()}


async def handle_jsonrpc_request(request: Dict[str, Any]) -> Dict[str, Any]:
    """JSON-RPC 2.0 dispatcher for Model Context Protocol."""
    req_id = request.get("id")
    method = request.get("method")
    params = request.get("params") or {}

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": "sentinel-ops-mcp", "version": "1.0.0"},
                "capabilities": {"tools": {}},
            },
        }
    elif method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": list_tools()}}
    elif method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if name == "calculate_blast_radius":
            res = mcp_registry.calculate_blast_radius(**arguments)
            return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": json.dumps(res)}]}}
        elif name == "tempo_get_trace":
            res = await mcp_registry.tempo_get_trace(**arguments)
            return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": json.dumps(res)}]}}
        elif name == "promql_range_query":
            res = await mcp_registry.promql_range_query(**arguments)
            return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": json.dumps(res)}]}}
        elif name == "query_graph_rag":
            res = mcp_registry.query_graph_rag(**arguments)
            return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": json.dumps(res)}]}}
        else:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Method not found or unknown tool: {name}"},
            }
    else:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Unknown method: {method}"},
        }


if __name__ == "__main__":
    tools = list_tools()
    print(f"Sentinel-Ops MCP Registry initialized with {len(tools)} tools:")
    for t in tools:
        print(f"  - {t['name']}: {t['description']}")
