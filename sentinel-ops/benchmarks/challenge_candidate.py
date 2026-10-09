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
            refs.add(f"tempo/{entry.query_string}")
        else:
            params = entry.query_params
            refs.add(f"prom/{params.get('service')}/{params.get('metric_type')}")
    # Preserve legacy free text verbatim. Guessing a mechanism from keywords here
    # would let the evaluator silently strengthen the production diagnosis.
    mechanism = result.get("mechanism")
    if mechanism is None and causal_claims:
        mechanism = " ".join(claim.statement for claim in (roots or causal_claims))
    service = result["diagnosed_root_cause"]
    if result["terminal_status"] != "SUPPORTED_DIAGNOSIS":
        return {
            "status": result["terminal_status"],
            "service": None,
            "mechanism": None,
            "citations": [],
        }

    return {"status": result["terminal_status"], "service": None if service == "unknown" else service,
            "mechanism": mechanism, "citations": sorted(refs)}


if __name__ == "__main__":
    print(json.dumps(decision_for(json.load(sys.stdin))))
