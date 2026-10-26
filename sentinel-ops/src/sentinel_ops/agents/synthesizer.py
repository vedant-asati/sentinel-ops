import json
import logging
import re
from typing import Any, Dict, List, Optional
from sentinel_ops.agents.llm_planner import refine_brief_with_llm
from sentinel_ops.agents.state import AtomicClaim, EvidenceItem, InvestigationState

logger = logging.getLogger(__name__)


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

    def _ev_dict(ev):
        return ev.model_dump() if hasattr(ev, "model_dump") else dict(ev)

    def _cl_dict(cl):
        return cl.model_dump() if hasattr(cl, "model_dump") else dict(cl)

    ev_list = [_ev_dict(e) for e in evidence]
    cl_list = [_cl_dict(c) for c in claims]
    brief_narrative = validate_brief_narrative(raw_narrative, cl_list, ev_list)

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
        "",
        "## Assessment Summary",
        brief_narrative if (brief_narrative and status == "SUPPORTED_DIAGNOSIS") else (summary if status == "SUPPORTED_DIAGNOSIS" else (reason or summary)),
        "",
    ]

    if cl_list:
        lines.append("## Grounded Claims & Telemetry Citations")
        for c in cl_list:
            cites = ", ".join(f"`[{cid}]`" for cid in c.get("cited_evidence_ids", []))
            lines.append(f"- **{c.get('claim_id')} (`{c.get('claim_type')}`)**: {c.get('statement')} (Cites: {cites})")
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
    """RCA Synthesizer: builds structured atomic claims with explicit evidence citations

    and provides actionable next discriminating checks and runbook actions.
    When state.use_llm=True, refines narrative summary strictly from verified evidence.
    """
    logger.info("Synthesizer formulating grounded root-cause diagnosis...")

    evidence_list = state.evidence
    successful_items = {e.id: e for e in evidence_list if e.status == "SUCCESS"}

    # Shared Stage 2/3 typed rule synthesis path (profile-agnostic across all migrated rules)
    rule_eval = getattr(state, "rule_evaluation", None)
    if rule_eval and rule_eval.get("is_sufficient"):
        svc = rule_eval.get("root_cause_service") or state.target_service
        mech = rule_eval.get("mechanism") or rule_eval.get("winning_rule") or "pool_acquisition_timeout"
        obs_to_ev = {
            e.query_params.get("observation_id"): e
            for e in successful_items.values()
            if e.query_params.get("observation_id")
        }
        cited_evs = [obs_to_ev[oid] for oid in rule_eval.get("supporting_observation_ids", []) if oid in obs_to_ev]
        cited_ids = [e.id for e in cited_evs]
        if cited_ids:
            claims = [
                AtomicClaim(
                    claim_id="CL-001",
                    statement=f"{svc} {mech} is the root cause of {state.target_service} degradation.",
                    claim_type="root_cause",
                    cited_evidence_ids=cited_ids,
                ),
                AtomicClaim(
                    claim_id="CL-002",
                    statement="; ".join(e.finding for e in cited_evs),
                    claim_type="mechanism",
                    cited_evidence_ids=cited_ids,
                ),
            ]
            for f_oid in rule_eval.get("healthy_observation_ids", []):
                h_ev = obs_to_ev.get(f_oid)
                if h_ev is not None:
                    claims.append(
                        AtomicClaim(
                            claim_id=f"CL-00{len(claims) + 1}",
                            statement=f"Falsified competing hypothesis: {h_ev.finding}",
                            claim_type="competing_hypothesis_falsified",
                            cited_evidence_ids=[h_ev.id],
                        )
                    )
            if mech == "cpu_contention":
                summary = f"Root cause identified as {svc} CPU saturation contributing to latency spikes."
            else:
                summary = f"Root cause identified as {svc} {mech}."
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

    def is_payment(e):
        return e.query_params.get("service") == "payment-service" or "payment" in e.query_string or "payment" in e.id or "paym" in e.id

    def is_pricing(e):
        return e.query_params.get("service") == "pricing-service" or "pricing" in e.query_string or "pricing" in e.id or "pric" in e.id

    # Find identifying evidence
    payment_evidence = next((e for e in successful_items.values() if is_payment(e) and "saturated" in e.finding and e.sample_or_span_ref == "db_pool_active"), None)
    payment_wait_ev = next(
        (
            e for e in successful_items.values()
            if (is_payment(e) and e.sample_or_span_ref == "db_pool_acquire_timeouts_total" and "spiked" in e.finding)
            or (e.backend_source == "tempo" and "payment-service" in e.finding and "TimeoutError" in e.finding)
        ),
        None,
    )
    pricing_metric_ev = next((e for e in successful_items.values() if is_pricing(e) and "latency_p95 spiked" in e.finding), None)
    pricing_cpu_ev = next((e for e in successful_items.values() if is_pricing(e) and e.sample_or_span_ref == "cpu_saturation" and "saturated" in e.finding), None)
    pricing_trace_ev = next((e for e in successful_items.values() if e.backend_source == "tempo" and "pricing-service" in e.finding and "bottleneck" in e.finding), None)
    pricing_normal_ev = next((e for e in successful_items.values() if is_pricing(e) and ("normal" in e.finding or "healthy" in e.finding) and "nan" not in e.finding.lower()), None)
    
    # Cart evidence: memory + restart/trace
    cart_mem_ev = next((e for e in successful_items.values() if "cart" in e.id and "memory" in e.query_string and "exhausted" in e.finding), None)
    cart_restart_ev = next((e for e in successful_items.values() if "cart" in e.id and "restarts" in e.query_string and "elevated" in e.finding), None)
    cart_trace_ev = next((e for e in successful_items.values() if e.backend_source == "tempo" and "cart" in e.finding and "bottleneck" in e.finding), None)
    
    # Payment error evidence
    payment_error_ev = next((e for e in successful_items.values() if is_payment(e) and "error_rate" in e.query_string and "spiked" in e.finding), None)
    payment_trace_ev = next((e for e in successful_items.values() if e.backend_source == "tempo" and "payment" in e.finding and "bottleneck" in e.finding), None)

    claims: List[AtomicClaim] = []
    next_checks: List[str] = []
    runbook_action = None
    mechanism = None

    # Check for corroborated timeout mechanisms
    timeout_trace = next((e for e in successful_items.values() if e.backend_source == "tempo" and "TimeoutError" in e.finding), None)
    if timeout_trace:
        op = timeout_trace.query_params.get("operation", "")
        svc = timeout_trace.query_params.get("service") or ("payment-service" if "payment" in timeout_trace.finding else "pricing-service")

        if "db.connection.acquire" in timeout_trace.finding or op == "db.connection.acquire":
            counter_ev = next((
                e for e in successful_items.values()
                if (e.query_params.get("service") == svc or svc in e.id)
                and e.query_params.get("metric_type") == "db_pool_acquire_timeouts_total"
                and "spiked" in e.finding
            ), None)
            if counter_ev:
                claims.append(
                    AtomicClaim(
                        claim_id="CL-001",
                        statement=f"{svc} pool_acquisition_timeout is the root cause of checkout timeouts.",
                        claim_type="root_cause",
                        cited_evidence_ids=[counter_ev.id, timeout_trace.id],
                    )
                )
                claims.append(
                    AtomicClaim(
                        claim_id="CL-002",
                        statement=f"{counter_ev.finding}; {timeout_trace.finding}",
                        claim_type="mechanism",
                        cited_evidence_ids=[counter_ev.id, timeout_trace.id],
                    )
                )
                return {
                    "structured_claims": claims,
                    "root_cause_summary": f"Root cause identified as {svc} pool_acquisition_timeout.",
                    "mechanism": "pool_acquisition_timeout",
                    "next_discriminating_checks": [
                        f"Inspect database pool configuration on {svc}",
                        "Check PostgreSQL connection locks and wait queues",
                    ],
                    "recommended_runbook_action": f"helm upgrade --set db.pool.max_connections=100 {svc} ./charts/{svc}",
                }
        elif "rpc.connect" in timeout_trace.finding or op == "rpc.connect":
            counter_ev = next((
                e for e in successful_items.values()
                if (e.query_params.get("service") == svc or svc in e.id)
                and e.query_params.get("metric_type") == "upstream_connect_timeouts_total"
                and "spiked" in e.finding
            ), None)
            if counter_ev:
                claims.append(
                    AtomicClaim(
                        claim_id="CL-001",
                        statement=f"{svc} upstream_connect_timeout is the root cause of checkout timeouts.",
                        claim_type="root_cause",
                        cited_evidence_ids=[counter_ev.id, timeout_trace.id],
                    )
                )
                claims.append(
                    AtomicClaim(
                        claim_id="CL-002",
                        statement=f"{counter_ev.finding}; {timeout_trace.finding}",
                        claim_type="mechanism",
                        cited_evidence_ids=[counter_ev.id, timeout_trace.id],
                    )
                )
                return {
                    "structured_claims": claims,
                    "root_cause_summary": f"Root cause identified as {svc} upstream_connect_timeout.",
                    "mechanism": "upstream_connect_timeout",
                    "next_discriminating_checks": [
                        f"Verify TCP network routing and gateway timeout headers on {svc}",
                        "Inspect ingress envoy proxy access logs",
                    ],
                    "recommended_runbook_action": f"kubectl rollout restart deployment/{svc}",
                }

    if payment_evidence and payment_wait_ev:
        cited_ids = [payment_evidence.id, payment_wait_ev.id]
        if payment_trace_ev and payment_trace_ev.id not in cited_ids:
            cited_ids.append(payment_trace_ev.id)
        claims.append(
            AtomicClaim(
                claim_id="CL-001",
                statement="payment-service database connection pool exhaustion is the root cause of transaction delays.",
                claim_type="root_cause",
                cited_evidence_ids=cited_ids,
            )
        )
        claims.append(
            AtomicClaim(
                claim_id="CL-002",
                statement=f"{payment_evidence.finding}; {payment_wait_ev.finding}",
                claim_type="mechanism",
                cited_evidence_ids=cited_ids,
            )
        )
        if pricing_normal_ev:
            claims.append(
                AtomicClaim(
                    claim_id="CL-003",
                    statement=f"Falsified pricing hypothesis: {pricing_normal_ev.finding}",
                    claim_type="competing_hypothesis_falsified",
                    cited_evidence_ids=[pricing_normal_ev.id],
                )
            )
        summary = "Root cause identified as payment-service database connection pool exhaustion."
        mechanism = "db_pool_exhaustion"
        next_checks = [
            "Verify active PostgreSQL connections: SELECT count(*) FROM pg_stat_activity;",
            "Inspect payment-service hikari connection timeout configuration.",
        ]
        runbook_action = "helm upgrade --set db.pool.max_connections=100 payment-service ./charts/payment-service"

    elif cart_mem_ev and cart_restart_ev:
        cited_ids = [cart_mem_ev.id, cart_restart_ev.id]
        mech_parts = [cart_mem_ev.finding, cart_restart_ev.finding]
        if cart_trace_ev:
            cited_ids.append(cart_trace_ev.id)
            mech_parts.append(cart_trace_ev.finding)

        claims.append(
            AtomicClaim(
                claim_id="CL-001",
                statement="cart-service memory exhaustion and container restarts (OOMKill) is the root cause of cart validation errors.",
                claim_type="root_cause",
                cited_evidence_ids=cited_ids,
            )
        )
        claims.append(
            AtomicClaim(
                claim_id="CL-002",
                statement="; ".join(mech_parts),
                claim_type="mechanism",
                cited_evidence_ids=cited_ids,
            )
        )
        summary = "Root cause identified as cart-service session cache memory leak and container OOMKill."
        mechanism = "memory_leak_oomkill"
        next_checks = [
            "Inspect kernel dmesg logs for OOM killer invocations: dmesg -T | grep -i oom-killer",
            "Collect heap profile from cart-service: curl -s http://cart-service:8002/debug/pprof/heap > heap.pb.gz",
        ]
        runbook_action = "kubectl rollout restart deployment/cart-service && kubectl set resources deployment/cart-service --limits=memory=1Gi"

    elif payment_error_ev and (payment_trace_ev or any(is_payment(e) and "refused" in e.finding.lower() for e in successful_items.values())):
        cited_ids = [payment_error_ev.id]
        if payment_trace_ev:
            cited_ids.append(payment_trace_ev.id)
        claims.append(
            AtomicClaim(
                claim_id="CL-001",
                statement="payment-service endpoint connection failure and elevated error rate is the root cause of order placement failures.",
                claim_type="root_cause",
                cited_evidence_ids=cited_ids,
            )
        )
        claims.append(
            AtomicClaim(
                claim_id="CL-002",
                statement=payment_error_ev.finding,
                claim_type="mechanism",
                cited_evidence_ids=cited_ids,
            )
        )
        summary = "Root cause identified as payment-service connection failure and endpoint refusal."
        mechanism = "config_drift_connection_refused"
        next_checks = [
            "Verify payment-service endpoint HTTP port configuration (e.g. 8004 vs 8443)",
            "Inspect recent deployment rollout diffs: kubectl rollout history deployment/payment-service",
        ]
        runbook_action = "kubectl rollout undo deployment/payment-service"

    elif pricing_cpu_ev and (pricing_trace_ev or pricing_metric_ev):
        primary_ev = pricing_trace_ev or pricing_metric_ev
        assert primary_ev is not None
        cited_pricing = [primary_ev.id, pricing_cpu_ev.id]
        if pricing_trace_ev and pricing_trace_ev.id not in cited_pricing:
            cited_pricing.append(pricing_trace_ev.id)
        if pricing_metric_ev and pricing_metric_ev.id not in cited_pricing:
            cited_pricing.append(pricing_metric_ev.id)

        claims.append(
            AtomicClaim(
                claim_id="CL-001",
                statement="pricing-service algorithmic CPU calculation delay is the root cause of checkout timeouts.",
                claim_type="root_cause",
                cited_evidence_ids=cited_pricing,
            )
        )
        claims.append(
            AtomicClaim(
                claim_id="CL-002",
                statement=f"{primary_ev.finding}; {pricing_cpu_ev.finding}",
                claim_type="mechanism",
                cited_evidence_ids=cited_pricing,
            )
        )
        healthy_payment = next((e for e in successful_items.values() if is_payment(e) and ("normal" in e.finding or "healthy" in e.finding) and "nan" not in e.finding.lower()), None)
        if healthy_payment:
            claims.append(
                AtomicClaim(
                    claim_id="CL-003",
                    statement=f"Falsified payment hypothesis: {healthy_payment.finding}",
                    claim_type="competing_hypothesis_falsified",
                    cited_evidence_ids=[healthy_payment.id],
                )
            )
        summary = "Root cause identified as pricing-service algorithmic calculation latency."
        mechanism = "cpu_algorithmic_latency"
        next_checks = [
            "Inspect container CPU throttling: container_cpu_cfs_throttled_seconds_total for pricing-service",
            "Trace cryptographic validation loop execution count per checkout transaction",
        ]
        runbook_action = "kubectl scale deployment/pricing-service --replicas=4"

    else:
        summary = "Inconclusive telemetry signals observed."
        next_checks = [
            "Verify Prometheus exporter scrape status across microservices (/metrics endpoint)",
            "Check OpenTelemetry distributed trace collector connectivity on port 53201",
        ]
        runbook_action = "Perform manual telemetry inspection before executing automated remediation."

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
        "mechanism": mechanism,
        "next_discriminating_checks": next_checks,
        "recommended_runbook_action": runbook_action,
    }
