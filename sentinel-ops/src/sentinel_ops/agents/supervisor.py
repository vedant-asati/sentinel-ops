import logging
from typing import Any, Dict, List
from langgraph.types import Send
from sentinel_ops.agents.state import InvestigationState

logger = logging.getLogger(__name__)


def supervisor_node(state: InvestigationState) -> Dict[str, Any]:
    """Supervisor Agent: decomposes incoming incident alert into competing hypotheses

    and prepares parallel query tasks.
    """
    logger.info("Supervisor analyzing incident: %s on target service: %s", state.incident_id, state.target_service)

    hypotheses = [
        "Hypothesis A: payment-service database connection pool exhaustion",
        "Hypothesis B: pricing-service algorithmic calculation latency or CPU throttling",
    ]

    return {
        "hypotheses": hypotheses,
    }


def route_supervisor_to_specialists(state: InvestigationState) -> List[Send]:
    """LangGraph Send router: fans out tasks concurrently to metrics and trace specialists."""
    tasks: List[Send] = []

    sim_telem = state.simulated_telemetry

    # 1. Dispatch Metrics Specialist for payment-service
    tasks.append(
        Send(
            "metrics_specialist",
            {
                "incident_id": state.incident_id,
                "service": "payment-service",
                "metric_type": "db_pool_active",
                "observation_window": (state.incident_timestamp, state.incident_timestamp),
                "incident_timestamp": state.incident_timestamp,
                "simulated_telemetry": sim_telem,
            },
        )
    )

    # 2. Dispatch Metrics Specialist for pricing-service
    tasks.append(
        Send(
            "metrics_specialist",
            {
                "incident_id": state.incident_id,
                "service": "pricing-service",
                "metric_type": "latency_p95",
                "observation_window": (state.incident_timestamp, state.incident_timestamp),
                "incident_timestamp": state.incident_timestamp,
                "simulated_telemetry": sim_telem,
            },
        )
    )

    # 3. Dispatch Trace Specialist for checkout waterfall analysis
    tasks.append(
        Send(
            "trace_specialist",
            {
                "incident_id": state.incident_id,
                "target_service": state.target_service,
                "incident_timestamp": state.incident_timestamp,
                "simulated_telemetry": sim_telem,
            },
        )
    )

    return tasks
