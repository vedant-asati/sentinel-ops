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
        return await self.prom_adapter.query_metric(
            service=service,
            metric_type=metric_type,  # type: ignore
            window=(start_iso, end_iso),
        )

    async def tempo_get_trace(self, trace_id: str) -> Dict[str, Any]:
        """Retrieves and analyzes a distributed trace waterfall from Tempo."""
        return await self.tempo_adapter.get_trace_waterfall(trace_id=trace_id)

    def calculate_blast_radius(self, target_service: str, action: str = "restart") -> Dict[str, Any]:
        """Computes upstream caller transitive blast radius and risk score."""
        return calculate_reverse_blast_radius(target_service=target_service, action=action)

    def query_graph_rag(
        self,
        alert_text: str,
        target_service: str,
        incident_timestamp: str,
        top_k: int = 2,
    ) -> List[Dict[str, Any]]:
        """Retrieves top-k historical incident postmortems using topology-aware GraphRAG."""
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
    """Returns tool schemas in standard MCP format."""
    return [
        {
            "name": "promql_range_query",
            "description": "Server-enforced time-anchored query for Prometheus metrics.",
            "parameters": {
                "type": "object",
                "properties": {
                    "service": {"type": "string", "enum": ["checkout-service", "cart-service", "pricing-service", "payment-service"]},
                    "metric_type": {"type": "string", "enum": ["error_rate", "latency_p95", "db_pool_active", "db_pool_size", "cpu_saturation"]},
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


if __name__ == "__main__":
    tools = list_tools()
    print(f"Sentinel-Ops MCP Registry initialized with {len(tools)} tools:")
    for t in tools:
        print(f"  - {t['name']}: {t['description']}")
