"""Run independent candidates over the same blind incident protocol."""

import argparse
from collections import Counter
import json
from pathlib import Path
import secrets
import subprocess
import sys
from time import monotonic

from benchmarks.challenges import Case, FAILURE, INSUFFICIENT, SUPPORTED, generate


def load_holdout(path):
    """Load human-adjudicated incidents kept outside the development suite."""
    records = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(records, list) or not records:
        raise ValueError("holdout must contain a nonempty JSON array")
    cases = []
    ids = set()
    public_fields = {"id", "target_service", "alert_text", "trace_id", "incident_timestamp", "mock_telemetry"}
    for record in records:
        incident, expected = record["incident"], record["expected"]
        if set(incident) != public_fields or not isinstance(incident["mock_telemetry"], dict):
            raise ValueError("holdout incident must contain only the public snapshot fields")
        if not isinstance(incident["id"], str) or incident["id"] in ids:
            raise ValueError("holdout requires unique string IDs")
        ids.add(incident["id"])
        status = expected["status"]
        refs = expected["citations"]
        if status not in (SUPPORTED, INSUFFICIENT, FAILURE) or not isinstance(refs, list):
            raise ValueError("invalid holdout status or citations")
        if not all(isinstance(ref, str) and ref for ref in refs) or len(refs) != len(set(refs)):
            raise ValueError("holdout citations must be unique source locators")
        service, mechanism = expected["service"], expected["mechanism"]
        if status == SUPPORTED:
            if not all(isinstance(v, str) and v for v in (service, mechanism)) or not refs:
                raise ValueError("supported holdout cases require service, mechanism and citations")
        elif (service, mechanism, refs) != (None, None, []):
            raise ValueError("non-diagnostic holdout cases cannot have a causal answer")
        cases.append(Case("holdout/" + record["family"], incident, status, service, mechanism, tuple(refs)))
    return cases


def grade(case: Case, decision: dict) -> list[str]:
    fields = {"status", "service", "mechanism", "citations"}
    if not isinstance(decision, dict) or set(decision) != fields:
        return ["invalid decision schema"]
    refs = decision["citations"]
    if not isinstance(refs, list) or not all(isinstance(ref, str) for ref in refs):
        return ["invalid citations"]
    problems = []
    if decision["status"] != case.status:
        problems.append("wrong terminal status")
    if decision["service"] != case.service:
        problems.append("wrong service")
    if decision["mechanism"] != case.mechanism:
        problems.append("wrong mechanism")
    if set(refs) != set(case.required_refs) or len(set(refs)) != len(refs):
        problems.append("incorrect causal citations")
    return problems


def evaluate(cases, command, timeout):
    rows = []
    for case in cases:
        started = monotonic()
        decision = None
        try:
            proc = subprocess.run(command, input=json.dumps(case.incident), capture_output=True,
                                  text=True, timeout=timeout, check=False)
            if proc.returncode:
                problems = [f"candidate exit {proc.returncode}: {proc.stderr[-500:].strip()}"]
            else:
                decision = json.loads(proc.stdout)
                problems = grade(case, decision)
        except subprocess.TimeoutExpired:
            problems = ["candidate timeout"]
        except (OSError, UnicodeError, ValueError) as exc:
            problems = [f"candidate error: {exc}"]
        rows.append({
            "family": case.family, "id": case.incident["id"], "errors": problems,
            "elapsed_ms": round(1000 * (monotonic() - started)),
            "expected": {"status": case.status, "service": case.service,
                         "mechanism": case.mechanism, "citations": list(case.required_refs)},
            "decision": decision,
        })
    return rows


def summarize(rows):
    failed = [r for r in rows if r["errors"]]
    supported = [r for r in rows if isinstance(r["decision"], dict)
                 and r["decision"].get("status") == SUPPORTED]
    positives = [r for r in rows if r["expected"]["status"] == SUPPORTED]
    return {
        "total": len(rows), "passed": len(rows) - len(failed),
        "diagnosable_cases": len(positives),
        "fully_grounded_correct_diagnoses": sum(not r["errors"] for r in positives),
        "supported_decisions": len(supported),
        "false_support_on_nondiagnostic_cases": sum(r["expected"]["status"] != SUPPORTED for r in supported),
        "incorrect_supported_decisions": sum(bool(r["errors"]) for r in supported),
        "failures_by_family": dict(sorted(Counter(r["family"] for r in failed).items())),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, help="default: fresh random seed, printed before execution")
    parser.add_argument("--timeout", type=float, default=10.0, help="seconds per candidate process")
    parser.add_argument("--report", type=Path, help="write full per-case JSON results and failing inputs")
    parser.add_argument("--holdout", type=Path, help="also grade separately authored, labeled JSON incidents")
    parser.add_argument("candidate", nargs=argparse.REMAINDER, help="-- executable [args...]")
    args = parser.parse_args(argv)
    if not 0 < args.timeout < float("inf"):
        parser.error("--timeout must be positive and finite")
    seed = args.seed if args.seed is not None else secrets.randbits(63)
    command = args.candidate
    if command[:1] == ["--"]:
        command = command[1:]
    command = command or [sys.executable, "-m", "benchmarks.challenge_candidate"]
    print(f"Seed {seed}", flush=True)
    cases = generate(seed)
    if args.holdout:
        try:
            cases.extend(load_holdout(args.holdout))
        except (OSError, ValueError, KeyError, TypeError) as exc:
            parser.error(f"invalid holdout: {exc}")
    rows = evaluate(cases, command, args.timeout)
    summary = summarize(rows)
    print(json.dumps(summary, indent=2))
    failures = [row for row in rows if row["errors"]]
    if failures:
        print("First failure:", json.dumps(failures[0]))
    if args.report:
        for case, row in zip(cases, rows, strict=True):
            if row["errors"]:
                row["incident"] = case.incident
        args.report.write_text(json.dumps({"seed": seed, "summary": summary, "cases": rows},
                                          indent=2) + "\n", encoding="utf-8")
    return int(bool(failures))


if __name__ == "__main__":
    sys.exit(main())
