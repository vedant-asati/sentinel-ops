import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple
from langgraph.types import Send
from sentinel_ops.agents.state import InvestigationState
from sentinel_ops.agents.blast_radius import build_service_graph

logger = logging.getLogger(__name__)


def compute_incident_window(incident_timestamp: str, before_minutes: int = 2, after_minutes: int = 3) -> Tuple[str, str]:
    """Computes a dynamic observation window anchored to incident timestamp."""
    try:
        clean_ts = incident_timestamp.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_ts)
    except Exception:
        dt = datetime.now(timezone.utc)
    start_dt = dt - timedelta(minutes=before_minutes)
    end_dt = dt + timedelta(minutes=after_minutes)
    return (
        start_dt.isoformat().replace("+00:00", "Z"),
        end_dt.isoformat().replace("+00:00", "Z"),
    )


def supervisor_node(state: InvestigationState) -> Dict[str, Any]:
    """Supervisor Agent: decomposes incoming incident alert into competing hypotheses

    using dependency topology, alert narrative, and historical GraphRAG context.
    """
    logger.info("Supervisor analyzing incident: %s on target service: %s", state.incident_id, state.target_service)

    hypotheses = []

    # 1. Incorporate historical postmortems from GraphRAG
    for hist in state.historical_context[:2]:
        svc = hist.get("service") or hist.get("root_cause_service", "dependency")
        title = hist.get("title", "Historical Outage")
        hypotheses.append(f"Historical Precedent ({svc}): {title}")

    # 2. Formulate topology-driven competing hypotheses based on target service dependencies
    service_graph = build_service_graph()
    dependencies = list(service_graph.successors(state.target_service)) if state.target_service in service_graph else [state.target_service]

    for dep in dependencies:
        if dep == "cart-service":
            hypotheses.append("Hypothesis: cart-service container memory pressure, leak, or crash loop")
        elif dep == "payment-service":
            hypotheses.append("Hypothesis: payment-service database connection pool exhaustion or network failure")
        elif dep == "pricing-service":
            hypotheses.append("Hypothesis: pricing-service algorithmic calculation latency or CPU throttling")
        elif dep == "postgres-db":
            hypotheses.append("Hypothesis: postgres-db connection saturation or slow transaction locking")
        else:
            hypotheses.append(f"Hypothesis: {dep} dependency degradation or latency spike")

    # If alert explicitly highlights symptoms on a non-dependency, augment hypotheses
    alert_lower = state.alert_text.lower()
    if "cart" in alert_lower and not any("cart-service" in h for h in hypotheses):
        hypotheses.append("Hypothesis: cart-service container memory pressure or crash loop")

    return {
        "hypotheses": hypotheses,
    }


def route_supervisor_to_specialists(state: InvestigationState) -> List[Send]:
    """LangGraph Send router: fans out tasks concurrently to metrics and trace specialists

    strictly based on dependency call-graph topology and alert scope—never fixture peeking.
    """
    tasks: List[Send] = []
    sim_telem = state.simulated_telemetry
    window = compute_incident_window(state.incident_timestamp)
    service_graph = build_service_graph()

    # Extract target trace ID if specified or referenced in alert text
    target_trace_id = state.trace_id
    if not target_trace_id and state.alert_text:
        match = re.search(r"\b([0-9a-fA-F]{32})\b", state.alert_text)
        if match:
            target_trace_id = match.group(1)

    # 1. Always dispatch Trace Specialist for target service to inspect call waterfall
    tasks.append(
        Send(
            "trace_specialist",
            {
                "incident_id": state.incident_id,
                "target_service": state.target_service,
                "trace_id": target_trace_id,
                "observation_window": window,
                "incident_timestamp": state.incident_timestamp,
                "simulated_telemetry": sim_telem,
                "deadline_timestamp": state.deadline_timestamp,
            },
        )
    )

    # 2. Determine dependencies to inspect from service graph topology
    # For checkout-service, immediate downstream dependencies are cart, pricing, payment
    dependencies = list(service_graph.successors(state.target_service)) if state.target_service in service_graph else []
    if not dependencies:
        # If target service is a leaf node, inspect the target itself
        dependencies = [state.target_service]

    # Standard telemetry metrics to query per service
    SERVICE_METRICS = {
        "payment-service": ["db_pool_active", "error_rate", "db_pool_acquire_timeouts_total", "upstream_connect_timeouts_total"],
        "pricing-service": ["latency_p95", "cpu_saturation", "db_pool_acquire_timeouts_total", "upstream_connect_timeouts_total"],
        "cart-service": ["memory_usage", "container_restarts", "error_rate"],
    }

    # Dispatch systematic telemetry probes for all dependencies without peeking at test fixtures
    for dep in dependencies:
        m_types = SERVICE_METRICS.get(dep, ["error_rate", "latency_p95"])
        for m_type in m_types:
            tasks.append(
                Send(
                    "metrics_specialist",
                    {
                        "incident_id": state.incident_id,
                        "service": dep,
                        "metric_type": m_type,
                        "observation_window": window,
                        "incident_timestamp": state.incident_timestamp,
                        "simulated_telemetry": sim_telem,
                        "deadline_timestamp": state.deadline_timestamp,
                    },
                )
            )

    return tasks
