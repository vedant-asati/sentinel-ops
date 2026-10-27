from collections import Counter
from copy import deepcopy
from datetime import datetime
import json
import math
import sys

import pytest

from benchmarks.challenge_gate import evaluate, grade, load_holdout, main, summarize
from benchmarks.challenges import FAILURE, INSUFFICIENT, SUPPORTED, generate


def reference(incident):
    """Positive control derived only from observable inputs, independent of case labels."""
    snapshot = incident["mock_telemetry"]
    trace_id = incident["trace_id"]
    trace = snapshot["tempo"].get(trace_id)

    def _iter_series(rec):
        if "result" in rec:
            return rec["result"]
        return [{"metric": rec.get("metric") or {}, "values": rec.get("values") or []}]

    all_prom = [r for svc in snapshot["prometheus"].values() for r in svc.values()]
    coverage = "COMPLETE"
    for r in all_prom:
        if r.get("status") == "SUCCESS" and len(_iter_series(r)) > 5:
            coverage = "PARTIAL"
            break

    result = {
        "status": INSUFFICIENT,
        "service": None,
        "mechanism": None,
        "scope": None,
        "citations": [],
        "localized_service": None,
        "localized_operation": None,
        "coverage": coverage,
        "next_check": None,
    }
    if all(r.get("status") == "TOOL_FAILURE" for r in [*all_prom, *snapshot["tempo"].values()]):
        return dict(result, status=FAILURE, coverage="UNKNOWN")

    end = datetime.fromisoformat(incident["incident_timestamp"]).timestamp()
    if not trace or trace["status"] != "SUCCESS" or not end - 120 <= trace["timestamp"] <= end + 180:
        result["next_check"] = f"Verify Tempo trace availability for {trace_id}."
        return result

    spans = trace.get("spans") or []
    timeout_markers = {"TimeoutError", "DEADLINE_EXCEEDED"}
    # Extract bottleneck (timeout span or max duration child)
    bspan = next((s for s in spans if s.get("error") in timeout_markers), None)
    if bspan is None:
        children = [s for s in spans if s.get("parent_span_id")]
        bspan = max(children or spans, key=lambda s: float(s.get("duration_ms", 0.0)), default=None)
    if bspan:
        result["localized_service"] = bspan.get("service")
        result["localized_operation"] = bspan.get("name")

    operations = {
        "db.connection.acquire": ("pool_acquisition_timeout", "db_pool_acquire_timeouts_total"),
        "rpc.connect": ("upstream_connect_timeout", "upstream_connect_timeouts_total"),
    }
    for span in spans:
        if span.get("error") not in timeout_markers or span["name"] not in operations:
            continue
        service = span["service"]
        mechanism, metric = operations[span["name"]]
        record = snapshot["prometheus"].get(service, {}).get(metric)
        if not record or record["status"] != "SUCCESS":
            continue
        series_list = _iter_series(record)[:5]
        # Reject conflicting revisions on same key
        seen_keys = set()
        conflict = False
        valid_entry = None
        for entry in series_list:
            lbls = entry.get("metric") or {}
            rep = "|".join(f"{k}={lbls[k]}" for k in sorted(("pod", "instance", "container")) if k in lbls)
            if rep in seen_keys:
                conflict = True
                break
            seen_keys.add(rep)
            samples = [(ts, float(v)) for ts, v in entry.get("values", []) if end - 120 <= ts <= end + 180]
            if len(samples) >= 2 and all(math.isfinite(v) for _, v in samples) and samples[-1][1] > samples[0][1]:
                valid_entry = (rep, samples)
        if conflict or not valid_entry:
            continue
        rep_key, _ = valid_entry
        # Also verify pool replica compatibility if replica-labeled pool exists
        pool_rec = snapshot["prometheus"].get(service, {}).get("db_pool_active")
        size_rec = snapshot["prometheus"].get(service, {}).get("db_pool_size")
        if rep_key and pool_rec and pool_rec.get("status") == "SUCCESS" and size_rec and size_rec.get("status") == "SUCCESS":
            p_entries = _iter_series(pool_rec)[:5]
            s_entries = _iter_series(size_rec)[:5]
            p_reps = {
                "|".join(f"{k}={(e.get('metric') or {})[k]}" for k in sorted(("pod", "instance", "container")) if k in (e.get("metric") or {})): e.get("values", [])[-1][1]
                for e in p_entries
            }
            s_reps = {
                "|".join(f"{k}={(e.get('metric') or {})[k]}" for k in sorted(("pod", "instance", "container")) if k in (e.get("metric") or {})): e.get("values", [])[-1][1]
                for e in s_entries
            }
            if any(k for k in p_reps):
                if rep_key not in p_reps or rep_key not in s_reps or float(p_reps[rep_key]) / float(s_reps[rep_key]) < 0.95:
                    continue
        prom_ref = f"prom/{service}/{metric}/{rep_key}" if rep_key else f"prom/{service}/{metric}"
        span_ref = f"tempo/{trace_id}/{span['span_id']}"
        return {
            "status": SUPPORTED,
            "service": service,
            "mechanism": mechanism,
            "scope": "affected_request",
            "citations": sorted([prom_ref, span_ref]),
            "localized_service": service,
            "localized_operation": span["name"],
            "coverage": coverage,
            "next_check": f"Inspect {service} {mechanism} settings.",
        }

    # Build discriminating next_check for abstentions
    if result["localized_service"] and result["localized_operation"]:
        contenders = [
            svc_name
            for svc_name, svc_metrics in snapshot["prometheus"].items()
            for m_name, m_rec in svc_metrics.items()
            if m_name.endswith("_timeouts_total")
            and m_rec.get("status") == "SUCCESS"
            and any(
                len(e.get("values", [])) >= 2 and isinstance(e["values"][-1][1], (int, float)) and float(e["values"][-1][1]) > float(e["values"][0][1])
                for e in _iter_series(m_rec)
            )
        ]
        other_str = f" vs contention on {', '.join(contenders)}" if contenders else ""
        result["next_check"] = f"Compare {result['localized_operation']} on {result['localized_service']}{other_str}."
    return result


@pytest.mark.parametrize("seed", [1, 9274, 20261124])
def test_generated_protocol_is_solvable_without_labels(seed):
    cases = generate(seed)
    assert generate(seed) == cases
    assert generate(seed + 1) != cases
    assert len({case.incident["id"] for case in cases}) == len(cases)
    assert Counter(case.status for case in cases) == {SUPPORTED: 16, INSUFFICIENT: 64, FAILURE: 4}
    for case in cases:
        assert set(case.incident) == {"id", "target_service", "alert_text", "incident_timestamp",
                                      "trace_id", "mock_telemetry"}
        assert grade(case, reference(case.incident)) == [], case.family


@pytest.mark.parametrize(("shortcut", "witness", "error"), [
    ("always-abstain", "corroborated", "wrong terminal status"),
    ("fixture-id-lookup", "corroborated", "wrong service"),
    ("ignore-time", "stale-counter", "wrong terminal status"),
    ("ignore-time", "stale-trace", "wrong terminal status"),
    ("ignore-counter", "flat-counter", "wrong terminal status"),
    ("ignore-counter", "counter-reset", "wrong terminal status"),
    ("ignore-counter", "nonfinite", "wrong terminal status"),
    ("ignore-counter", "wrong-service", "wrong terminal status"),
    ("first-trace", "renamed-reordered", "wrong terminal status"),
    ("wrong-mechanism", "corroborated", "wrong mechanism"),
    ("unrelated-citation", "corroborated", "incorrect causal citations"),
    ("wrong-span-citation", "wrong-span-in-correct-trace", "incorrect causal citations"),
    ("ignore-pod-label", "service-label-collapse", "wrong terminal status"),
    ("trust-inrange-cumulative-cpu", "in-range-cumulative-cpu", "wrong terminal status"),
    ("slow-span-as-timeout", "slow-span-without-timeout", "wrong terminal status"),
    ("generic-next-check", "slow-span-without-timeout", "missing discriminating next check"),
    ("hide-partial-coverage", "six-pod-truncated-series", "incorrect coverage disclosure"),
    ("outage-as-abstention", "collector-outage", "wrong terminal status"),
])
def test_gate_kills_shortcuts(shortcut, witness, error):
    cases = [case for case in generate(447) if case.family == witness]
    assert cases, witness
    caught = 0
    for case in cases:
        incident = deepcopy(case.incident)
        snapshot = incident["mock_telemetry"]
        if shortcut == "ignore-time":
            anchor = int(datetime.fromisoformat(incident["incident_timestamp"]).timestamp())
            for metrics in snapshot["prometheus"].values():
                for metric in metrics.values():
                    for i, sample in enumerate(metric.get("values", [])):
                        sample[0] = anchor - 30 + 30 * i
            for trace in snapshot["tempo"].values():
                trace["timestamp"] = anchor
        if shortcut == "ignore-counter":
            for metrics in snapshot["prometheus"].values():
                for key, metric in metrics.items():
                    if key.endswith("_timeouts_total") and "values" in metric:
                        metric["values"][-1][1] = metric["values"][0][1] + 1
        if shortcut == "first-trace":
            incident["trace_id"] = next(iter(snapshot["tempo"]))
        decision = reference(incident)
        if shortcut in {"always-abstain", "outage-as-abstention"}:
            decision = {**decision, "status": INSUFFICIENT, "service": None, "mechanism": None, "scope": None, "citations": []}
        if shortcut == "fixture-id-lookup":
            decision["service"] = {"case_01": "payment-service"}.get(incident["id"])
        if shortcut == "wrong-mechanism":
            decision["mechanism"] = "config_drift"
        if shortcut == "unrelated-citation":
            decision["citations"] = [f"prom/{decision['service']}/latency_p95"]
        if shortcut == "wrong-span-citation":
            spans = snapshot["tempo"][incident["trace_id"]]["spans"]
            sib = next(s["span_id"] for s in spans if not s.get("error") and s.get("parent_span_id"))
            decision["citations"] = [f"tempo/{incident['trace_id']}/{sib}", decision["citations"][0]]
        if shortcut in {"ignore-pod-label", "trust-inrange-cumulative-cpu", "slow-span-as-timeout"}:
            decision["status"] = SUPPORTED
        if shortcut == "generic-next-check":
            decision["next_check"] = "Verify metrics in dashboard."
        if shortcut == "hide-partial-coverage":
            decision["coverage"] = "COMPLETE"
        caught += error in grade(case, decision)
    if shortcut == "first-trace":
        assert caught > 0
    else:
        assert caught == len(cases)


@pytest.mark.parametrize("script,expected", [
    ("print('oops')", "candidate error"),
    ("print('{}')", "invalid decision schema"),
    ("raise SystemExit(3)", "candidate exit 3"),
    ("import time; time.sleep(2)", "candidate timeout"),
])
def test_candidate_errors_are_scored(script, expected):
    rows = evaluate(generate(5)[:1], [sys.executable, "-c", script], 0.5)
    assert rows[0]["errors"][0].startswith(expected)
    assert summarize(rows)["passed"] == 0


def test_cli_reports_and_fails_on_bad_candidate(tmp_path):
    path = tmp_path / "report.json"
    assert main(["--seed", "7", "--report", str(path), "--", sys.executable, "-c", "print('{}')"]) == 1
    report = json.loads(path.read_text())
    assert report["seed"] == 7
    assert report["summary"]["total"] == len(report["cases"]) == 84
    assert all(row["incident"]["id"] == row["id"] for row in report["cases"])


def test_holdout_boundary(tmp_path):
    case = next(c for c in generate(13) if c.status == SUPPORTED)
    path = tmp_path / "reserved.json"
    records = [{"family": "independent", "incident": case.incident, "expected": reference(case.incident)}]
    path.write_text(json.dumps(records))
    held, = load_holdout(path)
    assert held.family == "holdout/independent"
    assert grade(held, reference(held.incident)) == []
    records[0]["incident"]["ground_truth"] = "answer leak"
    path.write_text(json.dumps(records))
    with pytest.raises(ValueError, match="public snapshot fields"):
        load_holdout(path)


if __name__ == "__main__":
    print(json.dumps(reference(json.load(sys.stdin))))
