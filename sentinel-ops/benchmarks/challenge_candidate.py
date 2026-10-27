"""Bridge the current replay entry point to the challenge's JSON decision protocol."""

import json
import sys

from benchmarks.runner import SentinelOpsLangGraphAgent


def decision_for(incident):
    result = SentinelOpsLangGraphAgent().diagnose(incident)
    roots = [claim for claim in result["claims"] if claim.claim_type == "root_cause"]
    causal_claims = [claim for claim in result["claims"] if claim.claim_type in ("mechanism", "root_cause")]
    cited_ids = {eid for claim in causal_claims for eid in claim.cited_evidence_ids}
    ledger = {entry.id: entry for entry in result["evidence"]}
    refs = set()
    for eid in cited_ids:
        entry = ledger.get(eid)
        if entry is None or entry.status != "SUCCESS":
            refs.add(f"unresolved/{eid}")
        elif entry.backend_source == "tempo":
            sp = entry.sample_or_span_ref
            if sp and sp != "span_waterfall":
                refs.add(f"tempo/{entry.query_string}/{sp}")
            else:
                refs.add(f"tempo/{entry.query_string}")
        else:
            params = entry.query_params
            rkey = params.get("replica_key")
            if rkey:
                refs.add(f"prom/{params.get('service')}/{params.get('metric_type')}/{rkey}")
            else:
                refs.add(f"prom/{params.get('service')}/{params.get('metric_type')}")

    mechanism = result.get("mechanism")
    if mechanism is None and causal_claims:
        mechanism = " ".join(claim.statement for claim in (roots or causal_claims))
    service = result["diagnosed_root_cause"]
    loc = result.get("localized_dependency") or {}
    loc_svc = loc.get("bottleneck_service")
    loc_op = loc.get("bottleneck_operation")
    rule_eval = result.get("rule_evaluation") or {}
    cov = rule_eval.get("coverage_status") or ("PARTIAL" if any(e.query_params.get("truncated") for e in result["evidence"]) else "COMPLETE")
    scope = (roots[0].claim_scope if roots else None) or rule_eval.get("claim_scope")
    checks = result.get("next_checks") or rule_eval.get("next_discriminating_checks") or []
    next_check = checks[0] if checks else None

    if result["terminal_status"] != "SUPPORTED_DIAGNOSIS":
        return {
            "status": result["terminal_status"],
            "service": None,
            "mechanism": None,
            "scope": None,
            "citations": [],
            "localized_service": loc_svc,
            "localized_operation": loc_op,
            "coverage": cov,
            "next_check": next_check,
        }

    return {
        "status": result["terminal_status"],
        "service": None if service == "unknown" else service,
        "mechanism": mechanism,
        "scope": scope,
        "citations": sorted(refs),
        "localized_service": loc_svc,
        "localized_operation": loc_op,
        "coverage": cov,
        "next_check": next_check,
    }


if __name__ == "__main__":
    print(json.dumps(decision_for(json.load(sys.stdin))))
