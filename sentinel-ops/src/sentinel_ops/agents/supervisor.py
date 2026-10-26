import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple
from langgraph.types import Send
from sentinel_ops.agents.state import InvestigationState
from sentinel_ops.agents.blast_radius import build_service_graph
from sentinel_ops.agents.llm_planner import plan_probes_with_llm

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


async def supervisor_node(state: InvestigationState) -> Dict[str, Any]:
    """Supervisor Agent: decomposes incoming incident alert into competing hypotheses

    using dependency topology, alert narrative, historical GraphRAG context,
    and optional bounded Gemini query planning (--use-llm).
    """
    logger.info("Supervisor analyzing incident: %s on target service: %s", state.incident_id, state.target_service)

    hypotheses = []

    # 1. Incorporate historical postmortems from GraphRAG
    for hist in state.historical_context[:2]:
        svc = hist.get("service") or hist.get("root_cause_service", "dependency")
        title = hist.get("title", "Historical Outage")
        hypotheses.append(f"Historical Precedent ({svc}): {title}")

    # 2. Formulate topology-driven competing hypotheses based on active SystemProfile
    from sentinel_ops.profiles.registry import get_profile

    try:
        profile = get_profile(state.profile_id)
    except Exception:
        profile = None

    service_graph = build_service_graph(profile=profile)
    dependencies = (
        profile.resolve_dependencies(state.target_service)
        if profile is not None
        else (list(service_graph.successors(state.target_service)) if state.target_service in service_graph else [state.target_service])
    )
    if not dependencies:
        dependencies = [state.target_service]

    planned_probes: List[Dict[str, str]] = []
    planner_status = "disabled"
    if state.use_llm:
        allowed_svcs = list(profile.resolve_service_names()) if profile is not None else None
        allowed_sigs = (
            sorted({m.metric_name for m in profile.signals.values()})
            if profile is not None
            else None
        )
        llm_plan = await plan_probes_with_llm(
            alert_text=state.alert_text,
            target_service=state.target_service,
            historical_context=state.historical_context,
            dependencies=dependencies,
            deadline_timestamp=state.deadline_timestamp,
            allowed_services=allowed_svcs,
            allowed_signals=allowed_sigs,
        )
        if llm_plan:
            planner_status = "used"
            for h in llm_plan.hypotheses:
                if h not in hypotheses:
                    hypotheses.append(h)
            planned_probes = [
                {"service": p.service, "metric_type": p.metric_type, "rationale": p.rationale}
                for p in llm_plan.probes
            ]
        else:
            planner_status = "fallback_error"

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
        "llm_planned_probes": planned_probes,
        "planner_status": planner_status,
    }


def route_supervisor_to_specialists(state: InvestigationState) -> List[Send]:
    """LangGraph Send router: fans out tasks concurrently using SystemProfile & dependency graph."""
    from sentinel_ops.profiles.registry import get_profile

    tasks: List[Send] = []
    sim_telem = state.simulated_telemetry
    window = compute_incident_window(
        state.incident_timestamp,
        before_minutes=state.window_before_minutes,
        after_minutes=state.window_after_minutes,
    )
    try:
        profile = get_profile(state.profile_id)
    except Exception:
        profile = None

    service_graph = build_service_graph(profile=profile)

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
                "profile_id": state.profile_id,
                "trace_id": target_trace_id,
                "observation_window": window,
                "incident_timestamp": state.incident_timestamp,
                "simulated_telemetry": sim_telem,
                "deadline_timestamp": state.deadline_timestamp,
            },
        )
    )

    # 2. Determine dependencies to inspect from active SystemProfile / service graph topology
    dependencies = (
        profile.resolve_dependencies(state.target_service)
        if profile is not None
        else (list(service_graph.successors(state.target_service)) if state.target_service in service_graph else [])
    )
    if not dependencies:
        dependencies = [state.target_service]

    DEFAULT_METRICS = {
        "payment-service": ["db_pool_active", "error_rate", "db_pool_acquire_timeouts_total", "upstream_connect_timeouts_total"],
        "pricing-service": ["latency_p95", "cpu_saturation", "db_pool_acquire_timeouts_total", "upstream_connect_timeouts_total"],
        "cart-service": ["memory_usage", "container_restarts", "error_rate"],
    }

    def _service_metrics(dep_name: str) -> List[str]:
        if profile is not None and dep_name in profile.services:
            raw_list = profile.services[dep_name].metrics
            resolved: List[str] = []
            for m_key in raw_list:
                sig = profile.resolve_signal(m_key)
                resolved.append(sig.metric_name if sig else m_key)
            if resolved:
                return resolved
        return DEFAULT_METRICS.get(dep_name, ["error_rate", "latency_p95"])

    # Dispatch surgical LLM-planned probes alone on first pass (use_llm=True, crag_iterations == 0),
    # escalating to the full topology metric matrix on CRAG retry (crag_iterations > 0) or symbolic mode.
    dispatched: set[tuple[str, str]] = set()
    for probe in state.llm_planned_probes:
        svc = probe.get("service", "")
        m_type = probe.get("metric_type", "")
        if svc and m_type and (svc, m_type) not in dispatched:
            dispatched.add((svc, m_type))
            tasks.append(
                Send(
                    "metrics_specialist",
                    {
                        "incident_id": state.incident_id,
                        "profile_id": state.profile_id,
                        "service": svc,
                        "metric_type": m_type,
                        "observation_window": window,
                        "incident_timestamp": state.incident_timestamp,
                        "simulated_telemetry": sim_telem,
                        "deadline_timestamp": state.deadline_timestamp,
                    },
                )
            )

    surgical_budget_active = bool(state.use_llm and state.crag_iterations == 0 and state.llm_planned_probes)
    if not surgical_budget_active:
        for dep in dependencies:
            for m_type in _service_metrics(dep):
                if (dep, m_type) in dispatched:
                    continue
                dispatched.add((dep, m_type))
                tasks.append(
                    Send(
                        "metrics_specialist",
                        {
                            "incident_id": state.incident_id,
                            "profile_id": state.profile_id,
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
