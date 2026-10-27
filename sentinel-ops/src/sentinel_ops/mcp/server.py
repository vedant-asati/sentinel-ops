import asyncio
import json
import logging
import sys
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from sentinel_ops.agents.blast_radius import calculate_reverse_blast_radius
from sentinel_ops.core.config import settings
from sentinel_ops.mcp.prometheus_adapter import ALLOWED_SERVICES, PrometheusAdapter
from sentinel_ops.mcp.tempo_adapter import TempoAdapter
from sentinel_ops.memory.graph_rag import TopologyGraphRAG
from sentinel_ops.profiles.registry import get_profile

logger = logging.getLogger(__name__)


ALLOWED_REMEDIATION_ACTIONS = {"config_reload", "restart", "db_pool_resize"}


def _active_profile(profile_id: Optional[str] = None):
    try:
        return get_profile(profile_id or settings.DEFAULT_PROFILE_ID)
    except Exception:
        return None


class MCPToolRegistry:
    """Standard Model Context Protocol (MCP) tool registry exposing profile-driven bounded telemetry tools."""

    def __init__(self):
        self.prom_adapter = PrometheusAdapter()
        self.tempo_adapter = TempoAdapter()
        self.graph_rag = TopologyGraphRAG(profile=_active_profile())

    async def promql_range_query(
        self,
        service: str,
        metric_type: str,
        start_iso: str,
        end_iso: str,
        profile_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Queries Prometheus metrics over an anchored time window [start_iso, end_iso]."""
        prof = _active_profile(profile_id)
        q_kwargs: Dict[str, Any] = {}
        if prof is not None:
            q_kwargs["allowed_services"] = prof.resolve_service_names()
            q_kwargs["promql_templates"] = prof.to_promql_templates()
        raw_res = await self.prom_adapter.query_metric(
            service=service,
            metric_type=metric_type,  # type: ignore
            window=(start_iso, end_iso),
            **q_kwargs,
        )
        # Cap result array to prevent context window exhaustion while preserving truncation metadata
        if raw_res.get("status") == "SUCCESS" and "result" in raw_res:
            series_list = raw_res["result"][:5]
            for s in series_list:
                vals = s.get("values", [])
                if len(vals) > 100:
                    s["values"] = vals[:50] + vals[-50:]
            raw_res["result"] = series_list
        return raw_res

    async def tempo_get_trace(self, trace_id: str) -> Dict[str, Any]:
        """Retrieves and analyzes a distributed trace waterfall from Tempo."""
        return await self.tempo_adapter.get_trace_waterfall(trace_id=trace_id)

    async def tempo_search_traces(
        self,
        service: str,
        start_iso: str,
        end_iso: str,
        limit: int = 5,
        profile_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Discovers the most recent trace ID in Tempo matching service & incident time window."""
        prof = _active_profile(profile_id)
        allowed = prof.resolve_service_names() if prof is not None else ALLOWED_SERVICES
        if service not in allowed:
            raise ValueError(f"Service '{service}' is not in allowed services list: {allowed}.")
        bounded_limit = max(1, min(20, int(limit)))
        trace_id = await self.tempo_adapter.search_traces(
            service=service,
            start_iso=start_iso,
            end_iso=end_iso,
            limit=bounded_limit,
        )
        return {
            "status": "SUCCESS" if trace_id else "EMPTY",
            "service": service,
            "start_iso": start_iso,
            "end_iso": end_iso,
            "trace_id": trace_id,
        }

    def calculate_blast_radius(
        self,
        target_service: str,
        action: str = "restart",
        profile_id: Optional[str] = None,
    ) -> Dict[str, Any]:
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
        prof = _active_profile(profile_id)
        return calculate_reverse_blast_radius(target_service=target_service, action=action, profile=prof)

    def query_graph_rag(
        self,
        alert_text: str,
        target_service: str,
        incident_timestamp: str,
        top_k: int = 2,
        profile_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieves top-k historical incident postmortems using topology-aware GraphRAG with timestamp validation."""
        from datetime import datetime
        try:
            datetime.fromisoformat(incident_timestamp.replace("Z", "+00:00"))
        except (ValueError, TypeError, AttributeError):
            raise ValueError(f"Invalid ISO-8601 incident_timestamp: '{incident_timestamp}'")

        prof = _active_profile(profile_id)
        rag = TopologyGraphRAG(profile=prof) if prof is not None else self.graph_rag
        matches = rag.retrieve(
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


def list_tools(profile_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Returns tool schemas derived from the active SystemProfile in standard MCP 2024-11-05 format."""
    prof = _active_profile(profile_id)
    svcs = list(prof.resolve_service_names()) if prof is not None else list(ALLOWED_SERVICES)
    if prof is not None:
        sigs = sorted({k for k in prof.signals.keys()} | {m.metric_name for m in prof.signals.values()})
    else:
        sigs = [
            "error_rate",
            "latency_p95",
            "db_pool_active",
            "db_pool_size",
            "db_pool_acquire_timeouts_total",
            "upstream_connect_timeouts_total",
            "cpu_saturation",
            "memory_usage",
            "container_restarts",
        ]

    tools = [
        {
            "name": "promql_range_query",
            "description": "Server-enforced time-anchored query for Prometheus metrics.",
            "parameters": {
                "type": "object",
                "properties": {
                    "service": {"type": "string", "enum": svcs},
                    "metric_type": {"type": "string", "enum": sigs},
                    "start_iso": {"type": "string"},
                    "end_iso": {"type": "string"},
                    "profile_id": {"type": "string"},
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
            "name": "tempo_search_traces",
            "description": "Searches Tempo for the latest trace_id matching service and [start_iso, end_iso].",
            "parameters": {
                "type": "object",
                "properties": {
                    "service": {"type": "string", "enum": svcs},
                    "start_iso": {"type": "string"},
                    "end_iso": {"type": "string"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 20},
                    "profile_id": {"type": "string"},
                },
                "required": ["service", "start_iso", "end_iso"],
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
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": list_tools(profile_id=params.get("profile_id"))}}
    elif method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32602, "message": "Invalid params: 'arguments' must be an object"},
            }
        try:
            if name == "calculate_blast_radius":
                res = mcp_registry.calculate_blast_radius(**arguments)
            elif name == "tempo_get_trace":
                res = await mcp_registry.tempo_get_trace(**arguments)
            elif name == "tempo_search_traces":
                res = await mcp_registry.tempo_search_traces(**arguments)
            elif name == "promql_range_query":
                res = await mcp_registry.promql_range_query(**arguments)
            elif name == "query_graph_rag":
                res = mcp_registry.query_graph_rag(**arguments)
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"Method not found or unknown tool: {name}"},
                }
            return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": json.dumps(res)}]}}
        except (ValueError, TypeError) as exc:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32602, "message": f"Invalid tool parameters: {exc}"},
            }
        except Exception as exc:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32603, "message": f"Tool execution error: {exc}"},
            }
    else:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Unknown method: {method}"},
        }


async def serve_stdio(stdin_stream=None, stdout_stream=None) -> None:
    """Runs JSON-RPC 2.0 MCP transport over stdio, supporting single-line and multi-line JSON objects."""
    in_stream = stdin_stream or sys.stdin
    out_stream = stdout_stream or sys.stdout
    decoder = json.JSONDecoder()
    buf = ""
    for chunk in in_stream:
        buf += chunk
        while True:
            stripped = buf.lstrip()
            if not stripped:
                buf = ""
                break
            try:
                req, idx = decoder.raw_decode(stripped)
            except json.JSONDecodeError:
                # If an incomplete multi-line JSON object started with '{' or '[', wait for more input
                if stripped.startswith(("{", "[")):
                    break
                bad_line, _, rest = stripped.partition("\n")
                resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": f"Parse error: invalid JSON '{bad_line[:40]}'"}}
                out_stream.write(json.dumps(resp) + "\n")
                out_stream.flush()
                buf = rest
                continue
            buf = stripped[idx:]
            resp = await handle_jsonrpc_request(req)
            out_stream.write(json.dumps(resp) + "\n")
            out_stream.flush()
    rem = buf.strip()
    if rem:
        try:
            req = json.loads(rem)
            resp = await handle_jsonrpc_request(req)
        except json.JSONDecodeError as exc:
            resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": f"Parse error: {exc}"}}
        out_stream.write(json.dumps(resp) + "\n")
        out_stream.flush()


def main() -> None:
    """CLI entrypoint (`sentinel-ops-mcp`) starting the MCP stdio server."""
    asyncio.run(serve_stdio())


if __name__ == "__main__":
    if "--info" in sys.argv:
        tools = list_tools()
        print(f"Sentinel-Ops MCP Registry initialized with {len(tools)} tools:")
        for t in tools:
            print(f"  - {t['name']}: {t['description']}")
    else:
        main()
