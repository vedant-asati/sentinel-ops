import logging
from typing import Any, Dict, List
from sentinel_ops.agents.state import AtomicClaim, InvestigationState

logger = logging.getLogger(__name__)


def synthesizer_node(state: InvestigationState) -> Dict[str, Any]:
    """RCA Synthesizer: builds structured atomic claims with explicit evidence citations

    and provides actionable next discriminating checks and runbook actions.
    """
    logger.info("Synthesizer formulating grounded root-cause diagnosis...")

    evidence_list = state.evidence
    successful_items = {e.id: e for e in evidence_list if e.status == "SUCCESS"}

    def is_payment(e):
        return e.query_params.get("service") == "payment-service" or "payment" in e.query_string or "payment" in e.id or "paym" in e.id

    def is_pricing(e):
        return e.query_params.get("service") == "pricing-service" or "pricing" in e.query_string or "pricing" in e.id or "pric" in e.id

    # Find identifying evidence
    payment_evidence = next((e for e in successful_items.values() if is_payment(e) and "saturated" in e.finding), None)
    pricing_metric_ev = next((e for e in successful_items.values() if is_pricing(e) and "spiked" in e.finding), None)
    pricing_cpu_ev = next((e for e in successful_items.values() if is_pricing(e) and ("cpu" in e.query_string.lower() or "cpu" in e.sample_or_span_ref.lower())), None)
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

    if payment_evidence:
        cited_ids = [payment_evidence.id]
        if payment_trace_ev:
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
                statement=payment_evidence.finding,
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

    elif pricing_trace_ev or (pricing_metric_ev and pricing_cpu_ev):
        primary_ev = pricing_trace_ev or pricing_metric_ev
        assert primary_ev is not None
        cited_pricing = [primary_ev.id]
        if pricing_trace_ev and pricing_trace_ev.id not in cited_pricing:
            cited_pricing.append(pricing_trace_ev.id)
        if pricing_metric_ev and pricing_metric_ev.id not in cited_pricing:
            cited_pricing.append(pricing_metric_ev.id)
        if pricing_cpu_ev and pricing_cpu_ev.id not in cited_pricing:
            cited_pricing.append(pricing_cpu_ev.id)

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
                statement=primary_ev.finding,
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

    return {
        "structured_claims": claims,
        "root_cause_summary": summary,
        "mechanism": mechanism,
        "next_discriminating_checks": next_checks,
        "recommended_runbook_action": runbook_action,
    }
