from __future__ import annotations
from typing import Annotated, Any, Dict, List, Literal, Optional, Tuple
from pydantic import BaseModel, Field


class EvidenceItem(BaseModel):
    """Immutable factual observation collected by a telemetry adapter."""
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


def merge_evidence_items(
    existing: List[EvidenceItem], incoming: List[EvidenceItem]
) -> List[EvidenceItem]:
    """LangGraph reducer: merges and deduplicates concurrent evidence by stable ID."""
    seen_ids = {item.id for item in existing}
    merged = list(existing)
    for item in incoming:
        if item.id not in seen_ids:
            merged.append(item)
            seen_ids.add(item.id)
    return merged


class AtomicClaim(BaseModel):
    """Atomic claim with explicit evidence citation mapping."""
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
    hypotheses: List[str] = Field(default_factory=list)
    
    # Concurrent evidence ledger with deterministic reducer
    evidence: Annotated[List[EvidenceItem], merge_evidence_items] = Field(default_factory=list)
    
    # Query dispatch & budgets
    crag_iterations: int = 0
    crag_sufficient: bool = False
    missing_evidence_hints: List[str] = Field(default_factory=list)
    simulated_telemetry: Optional[Dict[str, Any]] = None
    
    # Diagnosis & Claims
    structured_claims: List[AtomicClaim] = Field(default_factory=list)
    root_cause_summary: Optional[str] = None
    adversarial_verdict: Optional[AdversarialVerdict] = None
    adversarial_iterations: int = 0
    
    # Blast radius & remediation
    affected_callers: List[str] = Field(default_factory=list)
    blast_radius_score: Optional[float] = None
    remediation_proposal: Optional[str] = None
    
    # Terminal State
    terminal_status: Optional[Literal[
        "SUPPORTED_DIAGNOSIS",
        "INSUFFICIENT_EVIDENCE",
        "OPERATIONAL_FAILURE"
    ]] = None
    terminal_reason: Optional[str] = None
