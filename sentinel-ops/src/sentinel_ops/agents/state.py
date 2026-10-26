from __future__ import annotations
from typing import Annotated, Any, Dict, List, Literal, Optional, Tuple
from pydantic import BaseModel, ConfigDict, Field

from sentinel_ops.telemetry.models import (
    NormalizedMetricObservation,
    NormalizedTraceObservation,
    ProbeAttempt,
)


class EvidenceItem(BaseModel):
    """Immutable factual observation collected by a telemetry adapter."""
    model_config = ConfigDict(frozen=True)

    id: str = Field(description="Deterministic observation ID, e.g., EV-001")
    backend_source: Literal["prometheus", "tempo"] = Field(description="Telemetry source")
    query_string: str = Field(description="Exact PromQL or trace ID queried")
    query_params: Dict[str, Any] = Field(description="Service, window, metric parameters")
    observation_window: Tuple[str, str] = Field(description="(start_iso, end_iso) anchored to T_incident")
    sample_or_span_ref: str = Field(description="Target metric series key or span ID")
    finding: str = Field(description="Factual summary of observed telemetry")
    raw_payload: str = Field(description="Sanitized and defanged raw telemetry snippet")
    status: Literal["SUCCESS", "EMPTY", "TOOL_FAILURE"] = Field(
        description="Distinguishes valid proof-of-absence (EMPTY) from execution errors (TOOL_FAILURE)"
    )


STATUS_PRIORITY = {
    "SUCCESS": 3,
    "TOOL_FAILURE": 2,
    "EMPTY": 1,
}


def _evidence_sort_key(item: EvidenceItem):
    """Deterministic, symmetric sort key for commutativity and tie-breaking."""
    prio = STATUS_PRIORITY.get(item.status, 0)
    return (prio, len(item.finding or ""), item.finding or "", item.raw_payload or "")


def merge_evidence_items(
    existing: List[EvidenceItem], incoming: List[EvidenceItem]
) -> List[EvidenceItem]:
    """LangGraph reducer: merges and deduplicates concurrent evidence by stable ID.
    Strictly commutative and associative: merge(A, B) == merge(B, A).
    Priority order: SUCCESS > TOOL_FAILURE > EMPTY.
    """
    items_by_id: Dict[str, EvidenceItem] = {}
    for item in list(existing) + list(incoming):
        if item.id not in items_by_id:
            items_by_id[item.id] = item
        else:
            prev = items_by_id[item.id]
            if _evidence_sort_key(item) > _evidence_sort_key(prev):
                items_by_id[item.id] = item

    return sorted(items_by_id.values(), key=lambda x: x.id)


_OBS_STATUS_RANK = {
    "SUCCESS": 5,
    "STALE_TELEMETRY": 4,
    "UNSUPPORTED": 3,
    "TOOL_FAILURE": 2,
    "EMPTY": 1,
}


def merge_probe_attempts(
    existing: List[ProbeAttempt], incoming: List[ProbeAttempt]
) -> List[ProbeAttempt]:
    """Deterministic append/deduplicate reducer for backend ProbeAttempt records (keyed by attempt_id)."""
    by_id: Dict[str, ProbeAttempt] = {}
    for att in list(existing) + list(incoming):
        by_id[att.attempt_id] = att
    return sorted(by_id.values(), key=lambda a: (a.acquired_at, a.attempt_id))


def merge_observations(
    existing: List[Any], incoming: List[Any]
) -> List[Any]:
    """Deterministic reducer for typed observations keyed by identity, never selecting truth via message length."""
    by_id: Dict[str, Any] = {}
    for obs in list(existing) + list(incoming):
        oid = getattr(obs, "observation_id", None)
        if not oid:
            continue
        if oid not in by_id:
            by_id[oid] = obs
        else:
            prev = by_id[oid]
            new_key = (_OBS_STATUS_RANK.get(obs.status, 0), obs.attempt_id)
            old_key = (_OBS_STATUS_RANK.get(prev.status, 0), prev.attempt_id)
            if new_key > old_key:
                by_id[oid] = obs
    return sorted(by_id.values(), key=lambda o: o.observation_id)


class AtomicClaim(BaseModel):
    """Atomic claim with explicit evidence citation mapping."""
    model_config = ConfigDict(frozen=True)

    claim_id: str = Field(description="e.g., CL-001")
    statement: str = Field(description="Single factual assertion")
    claim_type: Literal["symptom", "root_cause", "mechanism", "competing_hypothesis_falsified"]
    cited_evidence_ids: List[str] = Field(
        description="List of EV-xxx identifiers directly proving this statement"
    )
    supported_by_evidence: Optional[bool] = None


class AdversarialVerdict(BaseModel):
    """Evaluation verdict produced by the fresh-context red-team reviewer."""
    all_claims_supported: bool
    confidence: float = Field(ge=0.0, le=1.0)
    claim_evaluations: List[Dict[str, Any]] = Field(
        description="Per-claim entailment verdict: [{claim_id: 'CL-001', supported: true, reason: '...'}]"
    )
    critique_hint: Optional[str] = None


class InvestigationState(BaseModel):
    """Core state object passed across LangGraph nodes."""
    incident_id: str
    alert_text: str
    incident_timestamp: str = Field(description="ISO-8601 anchor timestamp T_incident")
    target_service: str = Field(description="Primary reporting service (e.g. checkout-service)")
    profile_id: str = Field(default="checkout-demo", description="Versioned SystemProfile ID governing topology & rules")
    environment: str = Field(default="default", description="Scoped deployment environment identifier")
    window_before_minutes: int = Field(default=2, ge=1, le=60)
    window_after_minutes: int = Field(default=3, ge=1, le=60)
    trace_id: Optional[str] = Field(default=None, description="Specific target trace ID if alerted")
    hypotheses: List[str] = Field(default_factory=list)
    historical_context: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Top-k matching postmortems retrieved by GraphRAG"
    )
    
    # Concurrent evidence & typed observation ledgers with deterministic reducers
    evidence: Annotated[List[EvidenceItem], merge_evidence_items] = Field(default_factory=list)
    observations: Annotated[List[NormalizedMetricObservation | NormalizedTraceObservation], merge_observations] = Field(default_factory=list)
    probe_attempts: Annotated[List[ProbeAttempt], merge_probe_attempts] = Field(default_factory=list)

    # Query dispatch & budgets
    use_llm: bool = Field(default=False, description="Enable bounded Neuro-Symbolic LLM planning")
    planner_status: Literal["used", "disabled", "fallback_error", "budget_skipped"] = "disabled"
    llm_planned_probes: List[Dict[str, str]] = Field(default_factory=list)
    crag_iterations: int = 0
    crag_sufficient: bool = False
    missing_evidence_hints: List[str] = Field(default_factory=list)
    simulated_telemetry: Optional[Dict[str, Any]] = None
    deadline_timestamp: Optional[float] = Field(
        default=None,
        description="Monotonic timestamp after which the run must abort as OPERATIONAL_FAILURE"
    )
    
    # Diagnosis & Claims
    structured_claims: List[AtomicClaim] = Field(default_factory=list)
    root_cause_summary: Optional[str] = None
    incident_brief_narrative: Optional[str] = None
    mechanism: Optional[str] = Field(default=None, description="Validated root-cause mechanism identifier")
    localized_dependency: Optional[Dict[str, Any]] = Field(default=None, description="Localized bottleneck span even when sub-mechanism is uncorroborated")
    rule_evaluation: Optional[Dict[str, Any]] = Field(default=None, description="Serialized RuleEvaluationResult shared across CRAG/synthesizer/adversarial")
    adversarial_verdict: Optional[AdversarialVerdict] = None
    adversarial_iterations: int = 0
    
    # Blast radius & remediation
    affected_callers: List[str] = Field(default_factory=list)
    blast_radius_score: Optional[float] = None
    remediation_proposal: Optional[str] = None
    next_discriminating_checks: List[str] = Field(
        default_factory=list,
        description="Actionable next telemetry checks for operator when evidence is inconclusive or missing"
    )
    recommended_runbook_action: Optional[str] = Field(
        default=None,
        description="Read-only advisory command for operator (e.g., kubectl or helm)"
    )
    
    # Terminal State
    terminal_status: Optional[Literal[
        "SUPPORTED_DIAGNOSIS",
        "INSUFFICIENT_EVIDENCE",
        "OPERATIONAL_FAILURE"
    ]] = None
    terminal_reason: Optional[str] = None
