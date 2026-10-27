import json
import logging
import re
from typing import Any, Dict, List, Optional
from sentinel_ops.agents.llm_planner import refine_brief_with_llm
from sentinel_ops.agents.state import AtomicClaim, EvidenceItem, InvestigationState
from sentinel_ops.security.redact import scrub_attributes, scrub_credentials

logger = logging.getLogger(__name__)


def _scrub_brief_payload(obj: Any) -> Any:
    """Recursively redacts sensitive keys, tokens, DB URIs, and credentials across brief exports."""
    if isinstance(obj, str):
        return scrub_credentials(obj)
    if isinstance(obj, dict):
        return {
            k: ("[REDACTED]" if isinstance(scrub_attributes({k: ""}).get(k), str) and scrub_attributes({k: ""})[k] == "[REDACTED]" else _scrub_brief_payload(v))
            for k, v in obj.items()
        }
    if isinstance(obj, (list, tuple)):
        return [_scrub_brief_payload(v) for v in obj]
    return obj


def validate_brief_narrative(
    narrative: Optional[str],
    claims: List[Any],
    evidence: List[Any],
) -> Optional[str]:
    """Ensures any free-text LLM narrative cites only verified [EV-xxx] IDs and avoids invented mechanisms."""
    if not narrative or not isinstance(narrative, str) or not narrative.strip():
        return None
    if not claims:
        return None

    def _get(obj, attr, default=None):
        return obj.get(attr, default) if isinstance(obj, dict) else getattr(obj, attr, default)

    verified_ids = {
        cid
        for c in claims
        for cid in (_get(c, "cited_evidence_ids", []) or [])
    }
    successful_ids = {
        _get(e, "id") for e in evidence if _get(e, "status") == "SUCCESS"
    }
    allowed_ids = verified_ids & successful_ids
    cited_in_text = re.findall(r"\[?(EV-[A-Za-z0-9_\-]+)\]?", narrative)
    if any(eid not in allowed_ids for eid in cited_in_text):
        return None

    # Ensure narrative does not assert a contradictory root-cause service against claims
    root_text = " ".join(
        str(_get(c, "statement", "")).lower()
        for c in claims
        if _get(c, "claim_type") == "root_cause"
    )
    claim_all_text = " ".join(str(_get(c, "statement", "")).lower() for c in claims)
    narr_lower = narrative.lower()
    for svc in ("payment-service", "pricing-service", "cart-service", "checkout-service"):
        if svc in narr_lower and svc not in claim_all_text:
            return None

    # Require root-cause service from CL-001 to appear cleanly and reject invented generic fault domains
    forbidden_invented = ("storage device", "disk failure", "dns hijacking", "bgp route")
    if any(term in narr_lower for term in forbidden_invented):
        return None
    if root_text:
        for svc in ("payment-service", "pricing-service", "cart-service"):
            if svc in root_text and svc not in narr_lower:
                return None
    return narrative.strip()


def format_incident_brief(state: Dict[str, Any] | InvestigationState, fmt: str = "markdown") -> str:
    """Renders a strict read-only on-call Incident Brief from terminal investigation state."""
    data = state.model_dump() if isinstance(state, InvestigationState) else dict(state)
    incident_id = data.get("incident_id", "unknown")
    target_service = data.get("target_service", "checkout-service")
    status = data.get("terminal_status", "OPERATIONAL_FAILURE")
    reason = data.get("terminal_reason", "")
    summary = data.get("root_cause_summary") or "No causal mechanism substantiated."
    raw_narrative = data.get("incident_brief_narrative")
    mechanism = data.get("mechanism") or "undetermined"
    claims = data.get("structured_claims") or []
    evidence = data.get("evidence") or []
    next_checks = data.get("next_discriminating_checks") or []
    callers = data.get("affected_callers") or []
    blast_score = data.get("blast_radius_score")
    runbook_action = data.get("recommended_runbook_action")
    if isinstance(runbook_action, str):
        runbook_action = scrub_credentials(runbook_action)

    def _ev_dict(ev):
        raw = ev.model_dump() if hasattr(ev, "model_dump") else dict(ev)
        return _scrub_brief_payload(raw)

    def _cl_dict(cl):
        raw = cl.model_dump() if hasattr(cl, "model_dump") else dict(cl)
        return _scrub_brief_payload(raw)

    ev_list = [_ev_dict(e) for e in evidence]
    cl_list = [_cl_dict(c) for c in claims]
    summary = scrub_credentials(summary) if isinstance(summary, str) else summary
    reason = scrub_credentials(reason) if isinstance(reason, str) else reason
    next_checks = [scrub_credentials(str(chk)) for chk in next_checks]
    brief_narrative = validate_brief_narrative(raw_narrative, cl_list, ev_list)
    if brief_narrative:
        brief_narrative = scrub_credentials(brief_narrative)

    rule_eval = data.get("rule_evaluation") or {}
    cov_status = rule_eval.get("coverage_status") or "UNKNOWN"
    trunc_series = rule_eval.get("truncated_series") or []
    claim_scope = rule_eval.get("claim_scope")
    claim_subject = rule_eval.get("claim_subject")

    if fmt == "json":
        probe_attempts = data.get("probe_attempts") or []
        return json.dumps(
            {
                "schema_version": "3.0",
                "incident_id": incident_id,
                "profile_id": data.get("profile_id", "checkout-demo"),
                "environment": data.get("environment", "default"),
                "target_service": target_service,
                "incident_timestamp": data.get("incident_timestamp"),
                "trace_id": data.get("trace_id"),
                "terminal_status": status,
                "root_cause_summary": brief_narrative if (brief_narrative and status == "SUPPORTED_DIAGNOSIS") else summary,
                "mechanism": mechanism,
                "claim_scope": claim_scope,
                "claim_subject": claim_subject,
                "coverage_status": cov_status,
                "truncated_series": trunc_series,
                "planner_status": data.get("planner_status", "disabled"),
                "localized_dependency": data.get("localized_dependency"),
                "queries_executed": len(probe_attempts) if probe_attempts else len(ev_list),
                "raw_payload_retention": data.get("raw_payload_retention", "sanitized"),
                "claims": cl_list,
                "evidence": ev_list,
                "evidence_count": len(ev_list),
                "affected_callers": callers,
                "blast_radius_score": blast_score,
                "next_discriminating_checks": next_checks,
                "advisory_runbook_action": runbook_action,
            },
            indent=2,
        )

    lines = [
        f"# On-Call Incident Brief: `{incident_id}`",
        "",
        f"- **Target Service:** `{target_service}`",
        f"- **Terminal Status:** `{status}`",
        f"- **Timestamp Anchor:** `{data.get('incident_timestamp', 'N/A')}`",
        f"- **Coverage Status:** `{cov_status}`" + (f" (truncated: {', '.join(trunc_series)})" if trunc_series else ""),
    ]
    if claim_scope:
        lines.append(f"- **Claim Scope:** `{claim_scope}`" + (f" (`{claim_subject}`)" if claim_subject else ""))
    lines.extend([
        "",
        "## Assessment Summary",
        brief_narrative if (brief_narrative and status == "SUPPORTED_DIAGNOSIS") else (summary if status == "SUPPORTED_DIAGNOSIS" else (reason or summary)),
        "",
    ])
    loc = data.get("localized_dependency")
    if loc and loc.get("bottleneck_service"):
        lines.append(
            f"- **Localized Bottleneck:** `{loc.get('bottleneck_service')}`"
            + (f" (`{loc.get('bottleneck_operation')}`)" if loc.get("bottleneck_operation") else "")
            + f" ({loc.get('exclusive_duration_ms', 0.0):.1f}ms exclusive)"
        )
        lines.append("")

    if cl_list:
        lines.append("## Grounded Claims & Telemetry Citations")
        for c in cl_list:
            cites = ", ".join(f"`[{cid}]`" for cid in c.get("cited_evidence_ids", []))
            sc_tag = f", scope={c.get('claim_scope')}" if c.get("claim_scope") else ""
            lines.append(f"- **{c.get('claim_id')} (`{c.get('claim_type')}{sc_tag}`)**: {c.get('statement')} (Cites: {cites})")
        lines.append("")

    if ev_list:
        lines.append("## Evidence Ledger")
        for e in ev_list:
            lines.append(f"- **`[{e.get('id')}]` ({e.get('status')}, {e.get('backend_source')})**: {e.get('finding')}")
        lines.append("")

    if callers or blast_score is not None:
        lines.append("## Advisory Blast Radius")
        lines.append(f"- **Upstream Affected Callers:** {', '.join(callers) if callers else 'None'}")
        lines.append(f"- **Risk Score:** {blast_score if blast_score is not None else 'N/A'}")
        if runbook_action:
            lines.append(f"- **Advisory Inspection / Runbook Command (Read-Only Suggestion):** `{runbook_action}`")
        lines.append("")

    lines.append("## Next Discriminating Checks")
    if next_checks:
        for chk in next_checks:
            lines.append(f"- {chk}")
    else:
        lines.append("- Verify downstream dependency metrics and trace spans in target window.")
    return "\n".join(lines) + "\n"


async def synthesizer_node(state: InvestigationState) -> Dict[str, Any]:
    """RCA Synthesizer: builds structured atomic claims strictly from verified rule evaluation."""
    logger.info("Synthesizer formulating grounded root-cause diagnosis...")

    evidence_list = state.evidence
    successful_items = {e.id: e for e in evidence_list if e.status == "SUCCESS"}

    rule_eval = getattr(state, "rule_evaluation", None)
    if not (rule_eval and rule_eval.get("is_sufficient")):
        # Fail closed: never synthesize or restore a rejected conclusion via legacy string matching
        return {
            "structured_claims": [],
            "root_cause_summary": "Inconclusive telemetry signals observed.",
            "incident_brief_narrative": None,
            "mechanism": None,
            "next_discriminating_checks": list(state.next_discriminating_checks or [
                "Verify Prometheus exporter scrape status and distributed trace propagation before mitigating."
            ]),
            "recommended_runbook_action": None,
        }

    svc = rule_eval.get("root_cause_service") or state.target_service
    mech = rule_eval.get("mechanism") or rule_eval.get("winning_rule") or "pool_acquisition_timeout"
    claim_scope = rule_eval.get("claim_scope")
    claim_subject = rule_eval.get("claim_subject") or svc
    obs_to_ev = {
        e.query_params.get("observation_id"): e
        for e in successful_items.values()
        if e.query_params.get("observation_id")
    }
    cited_evs = [obs_to_ev[oid] for oid in rule_eval.get("supporting_observation_ids", []) if oid in obs_to_ev]
    cited_ids = [e.id for e in cited_evs]
    if not cited_ids:
        return {
            "structured_claims": [],
            "root_cause_summary": "Inconclusive telemetry signals observed (no verified citation mapping).",
            "incident_brief_narrative": None,
            "mechanism": None,
            "next_discriminating_checks": list(state.next_discriminating_checks or []),
            "recommended_runbook_action": None,
        }

    claims = [
        AtomicClaim(
            claim_id="CL-001",
            statement=f"{claim_subject} {mech} is the root cause of {state.target_service} degradation.",
            claim_type="root_cause",
            claim_subject=claim_subject,
            claim_scope=claim_scope,
            cited_evidence_ids=cited_ids,
        ),
        AtomicClaim(
            claim_id="CL-002",
            statement="; ".join(e.finding for e in cited_evs),
            claim_type="mechanism",
            claim_subject=claim_subject,
            claim_scope=claim_scope,
            cited_evidence_ids=cited_ids,
        ),
    ]
    for f_oid in rule_eval.get("healthy_observation_ids", []):
        h_ev = obs_to_ev.get(f_oid)
        if h_ev is not None:
            h_svc = h_ev.query_params.get("service") or "dependency"
            claims.append(
                AtomicClaim(
                    claim_id=f"CL-00{len(claims) + 1}",
                    statement=f"Falsified competing hypothesis: {h_ev.finding}",
                    claim_type="competing_hypothesis_falsified",
                    claim_subject=h_svc,
                    claim_scope="service_fleet",
                    cited_evidence_ids=[h_ev.id],
                )
            )
    if mech == "cpu_contention":
        summary = f"Root cause identified as {svc} CPU saturation contributing to latency spikes."
    else:
        summary = f"Root cause identified as {claim_subject} {mech}."
    next_checks = list(rule_eval.get("next_discriminating_checks") or [])
    runbook_action = rule_eval.get("recommended_runbook_action")
    brief_narrative = None
    if state.use_llm and claims:
        refined = await refine_brief_with_llm(
            alert_text=state.alert_text,
            target_service=state.target_service,
            verified_claims=[c.model_dump() for c in claims],
            evidence=[e.model_dump() for e in evidence_list],
            next_checks=next_checks,
            deadline_timestamp=state.deadline_timestamp,
        )
        if refined:
            brief_narrative = validate_brief_narrative(
                refined.executive_summary,
                [c.model_dump() for c in claims],
                [e.model_dump() for e in evidence_list],
            )
            if refined.prioritized_next_check and refined.prioritized_next_check not in next_checks:
                next_checks = [refined.prioritized_next_check] + next_checks
    return {
        "structured_claims": claims,
        "root_cause_summary": summary,
        "incident_brief_narrative": brief_narrative,
        "mechanism": mech,
        "next_discriminating_checks": next_checks,
        "recommended_runbook_action": runbook_action,
    }
