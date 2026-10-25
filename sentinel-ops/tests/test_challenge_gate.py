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
    result = {"status": INSUFFICIENT, "service": None, "mechanism": None, "citations": []}
    records = [r for svc in snapshot["prometheus"].values() for r in svc.values()]
    if all(r["status"] == "TOOL_FAILURE" for r in [*records, *snapshot["tempo"].values()]):
        return dict(result, status=FAILURE)
    end = datetime.fromisoformat(incident["incident_timestamp"]).timestamp()
    if not trace or trace["status"] != "SUCCESS" or not end - 60 <= trace["timestamp"] <= end:
        return result
    operations = {
        "db.connection.acquire": ("pool_acquisition_timeout", "db_pool_acquire_timeouts_total"),
        "rpc.connect": ("upstream_connect_timeout", "upstream_connect_timeouts_total"),
    }
    for span in trace["spans"]:
        if span.get("error") != "TimeoutError" or span["name"] not in operations:
            continue
        service = span["service"]
        mechanism, metric = operations[span["name"]]
        record = snapshot["prometheus"][service][metric]
        samples = [(ts, float(v)) for ts, v in record.get("values", []) if end - 60 <= ts <= end]
        if record["status"] != "SUCCESS" or len(samples) < 2:
            continue
        if all(math.isfinite(v) for _, v in samples) and samples[-1][1] > samples[0][1]:
            return {"status": SUPPORTED, "service": service, "mechanism": mechanism,
                    "citations": [f"tempo/{trace_id}", f"prom/{service}/{metric}"]}
    return result


@pytest.mark.parametrize("seed", [1, 9274, 20261124])
def test_generated_protocol_is_solvable_without_labels(seed):
    cases = generate(seed)
    assert generate(seed) == cases
    assert generate(seed + 1) != cases
    assert len({case.incident["id"] for case in cases}) == len(cases)
    assert Counter(case.status for case in cases) == {SUPPORTED: 8, INSUFFICIENT: 36, FAILURE: 4}
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
                    for i, sample in enumerate(metric["values"]):
                        sample[0] = anchor - 30 + 30 * i
            for trace in snapshot["tempo"].values():
                trace["timestamp"] = anchor
        if shortcut == "ignore-counter":
            for metrics in snapshot["prometheus"].values():
                for key, metric in metrics.items():
                    if key.endswith("_timeouts_total"):
                        metric["values"][-1][1] = metric["values"][0][1] + 1
        if shortcut == "first-trace":
            incident["trace_id"] = next(iter(snapshot["tempo"]))
        decision = reference(incident)
        if shortcut in {"always-abstain", "outage-as-abstention"}:
            decision = {"status": INSUFFICIENT, "service": None, "mechanism": None, "citations": []}
        if shortcut == "fixture-id-lookup":
            decision["service"] = {"case_01": "payment-service"}.get(incident["id"])
        if shortcut == "wrong-mechanism":
            decision["mechanism"] = "config_drift"
        if shortcut == "unrelated-citation":
            decision["citations"] = [f"prom/{decision['service']}/latency_p95"]
        caught += error in grade(case, decision)
    if shortcut == "first-trace":
        # A serialization shortcut sometimes guesses correctly by chance.
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
    assert report["summary"]["total"] == len(report["cases"]) == 48
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
