import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple
from langgraph.types import Send
from sentinel_ops.agents.state import InvestigationState

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
    window = compute_incident_window(state.incident_timestamp)

    # 1. Dispatch Metrics Specialist for payment-service
    tasks.append(
        Send(
            "metrics_specialist",
            {
                "incident_id": state.incident_id,
                "service": "payment-service",
                "metric_type": "db_pool_active",
                "observation_window": window,
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
                "observation_window": window,
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
                "observation_window": window,
                "incident_timestamp": state.incident_timestamp,
                "simulated_telemetry": sim_telem,
            },
        )
    )

    # 4. Dispatch Metrics Specialist for cart-service if alert or telemetry present
    has_cart = "cart" in state.alert_text.lower() or (sim_telem and "cart-service" in sim_telem.get("prometheus", {}))
    if has_cart:
        tasks.append(
            Send(
                "metrics_specialist",
                {
                    "incident_id": state.incident_id,
                    "service": "cart-service",
                    "metric_type": "memory_usage",
                    "observation_window": window,
                    "incident_timestamp": state.incident_timestamp,
                    "simulated_telemetry": sim_telem,
                },
            )
        )
        tasks.append(
            Send(
                "metrics_specialist",
                {
                    "incident_id": state.incident_id,
                    "service": "cart-service",
                    "metric_type": "container_restarts",
                    "observation_window": window,
                    "incident_timestamp": state.incident_timestamp,
                    "simulated_telemetry": sim_telem,
                },
            )
        )

    # 5. Dispatch Metrics Specialist for payment-service error_rate if ECONNREFUSED/error mentioned or present
    has_pay_err = "refused" in state.alert_text.lower() or "500" in state.alert_text or (sim_telem and "error_rate" in sim_telem.get("prometheus", {}).get("payment-service", {}))
    if has_pay_err:
        tasks.append(
            Send(
                "metrics_specialist",
                {
                    "incident_id": state.incident_id,
                    "service": "payment-service",
                    "metric_type": "error_rate",
                    "observation_window": window,
                    "incident_timestamp": state.incident_timestamp,
                    "simulated_telemetry": sim_telem,
                },
            )
        )

    return tasks
