import logging
from typing import Any, Dict
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

from sentinel_ops.agents.adversarial import adversarial_reviewer_node, route_adversarial_review
from sentinel_ops.agents.blast_radius import blast_radius_node
from sentinel_ops.agents.specialists import metrics_specialist_node, trace_specialist_node
from sentinel_ops.agents.state import InvestigationState
from sentinel_ops.agents.sufficiency import crag_sufficiency_node, route_crag_gate
from sentinel_ops.agents.supervisor import route_supervisor_to_specialists, supervisor_node
from sentinel_ops.agents.synthesizer import synthesizer_node

logger = logging.getLogger(__name__)


# Terminal Nodes
def supported_diagnosis_node(state: InvestigationState) -> Dict[str, Any]:
    """Terminal state: Root cause successfully established, grounded, and verified."""
    logger.info("Terminal reached: SUPPORTED_DIAGNOSIS for %s", state.incident_id)
    return {
        "terminal_status": "SUPPORTED_DIAGNOSIS",
        "terminal_reason": "Diagnosis claims verified by adversarial reviewer and backed by telemetry evidence.",
    }


def insufficient_evidence_node(state: InvestigationState) -> Dict[str, Any]:
    """Terminal state: Abstention due to missing, inconclusive, or refuted telemetry with localization checks."""
    logger.warning("Terminal reached: INSUFFICIENT_EVIDENCE (Abstaining) for %s", state.incident_id)
    checks: list[str] = list(state.next_discriminating_checks or [])
    if not checks:
        for obs in state.observations:
            if getattr(obs, "backend_source", None) == "tempo" and obs.status == "SUCCESS":
                bsvc = getattr(obs, "bottleneck_service", None)
                bop = getattr(obs, "bottleneck_operation", None) or "slow_span"
                bdur = getattr(obs, "bottleneck_duration_ms", 0.0)
                if bsvc:
                    checks.append(
                        f"Trace {obs.trace_id} localized bottleneck to {bsvc} ({bop}, {bdur:.1f}ms exclusive); inspect logs, pool waits, and saturation counters on {bsvc}."
                    )
            elif getattr(obs, "join_status", None) in ("unjoinable", "missing_denominator"):
                checks.append(
                    f"Repair metric replica label alignment or missing capacity denominator for {obs.service} {obs.signal_name}."
                )
            elif getattr(obs, "counter_reset_detected", False):
                checks.append(
                    f"Inspect replica counter reset on {obs.service} {obs.signal_name} [{obs.join_key}] within incident window."
                )
        for hint in state.missing_evidence_hints or []:
            if hint not in checks:
                checks.append(hint)
        if not checks:
            checks.append(
                f"Verify telemetry scrape coverage and trace context propagation for {state.target_service}."
            )
    return {
        "terminal_status": "INSUFFICIENT_EVIDENCE",
        "terminal_reason": "Telemetry signals were missing, inconclusive, or failed entailment review. Refusing ungrounded hypothesis.",
        "next_discriminating_checks": checks,
    }


def operational_failure_node(state: InvestigationState) -> Dict[str, Any]:
    """Terminal state: Execution timeout or fatal backend tool error."""
    logger.error("Terminal reached: OPERATIONAL_FAILURE for %s", state.incident_id)
    return {
        "terminal_status": "OPERATIONAL_FAILURE",
        "terminal_reason": "Operational error: run-wide deadline exceeded or unrecoverable telemetry tool crash.",
    }


def build_investigation_graph() -> StateGraph:
    """Builds and wires the complete multi-agent LangGraph workflow."""
    builder = StateGraph(InvestigationState)

    # Core Reasoning & Execution Nodes
    builder.add_node("supervisor", supervisor_node)
    builder.add_node("metrics_specialist", metrics_specialist_node)
    builder.add_node("trace_specialist", trace_specialist_node)
    builder.add_node("crag_sufficiency", crag_sufficiency_node)
    builder.add_node("synthesizer", synthesizer_node)
    builder.add_node("adversarial_reviewer", adversarial_reviewer_node)
    builder.add_node("blast_radius", blast_radius_node)

    # Terminal Outcome Nodes
    builder.add_node("supported_diagnosis", supported_diagnosis_node)
    builder.add_node("insufficient_evidence", insufficient_evidence_node)
    builder.add_node("operational_failure", operational_failure_node)

    # Wiring Edges
    builder.add_edge(START, "supervisor")

    # Supervisor fans out to specialists via Send()
    builder.add_conditional_edges(
        "supervisor",
        route_supervisor_to_specialists,
        ["metrics_specialist", "trace_specialist"],
    )

    # Specialists converge on CRAG sufficiency gate
    builder.add_edge("metrics_specialist", "crag_sufficiency")
    builder.add_edge("trace_specialist", "crag_sufficiency")

    # CRAG Gate conditional routing
    builder.add_conditional_edges(
        "crag_sufficiency",
        route_crag_gate,
        {
            "synthesizer": "synthesizer",
            "supervisor": "supervisor",
            "insufficient_evidence": "insufficient_evidence",
            "operational_failure": "operational_failure",
        },
    )

    # Synthesizer to Adversarial Reviewer
    builder.add_edge("synthesizer", "adversarial_reviewer")

    # Adversarial Reviewer conditional routing
    builder.add_conditional_edges(
        "adversarial_reviewer",
        route_adversarial_review,
        {
            "blast_radius": "blast_radius",
            "synthesizer": "synthesizer",
            "insufficient_evidence": "insufficient_evidence",
            "operational_failure": "operational_failure",
        },
    )

    # Blast radius leads to supported terminal outcome
    builder.add_edge("blast_radius", "supported_diagnosis")

    # Terminals exit
    builder.add_edge("supported_diagnosis", END)
    builder.add_edge("insufficient_evidence", END)
    builder.add_edge("operational_failure", END)

    return builder


def compile_investigation_graph(checkpointer: Any = None):
    """Compiles the investigation graph with an optional checkpoint saver."""
    builder = build_investigation_graph()
    saver = checkpointer or MemorySaver()
    return builder.compile(checkpointer=saver)
