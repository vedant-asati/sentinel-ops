"""Adversarial exploit test suite for Benchmark Challenges and Challenge Gate Round 2

(sentinel_ops.benchmarks.challenges, sentinel_ops.benchmarks.challenge_gate).

Proves:
1. Uncorroborated spans & slow receipt rendering delay exploit:
   slow-span-without-timeout incident where render_receipt (2350ms) has no TimeoutError,
   tricking candidates into false certification on unrelated growing timeout counters.
2. Challenge Gate grading projection bypass:
   When case.localized_service is None (true for all stale-trace, missing-trace, unrelated-trace cases),
   grade() fails to validate localized_service, localized_operation, or scope,
   allowing candidates to smuggle arbitrary hallucinations into accepted decisions.
3. Score inflation exploit:
   Zero-reasoning candidates that abstain pass cases with zero false support flags.
4. Deterministic structural shortcut:
   Supported cases can be 100% solved with a 15-line heuristic on fixed span names
   ('child', 'db.connection.acquire', 'rpc.connect') bypassing all agent multi-hop reasoning.
5. Seed invariance and non-diagnostic perturbations:
   Validates case distributions across multiple seeds and exposes boundary conditions.
"""

from collections import Counter
from copy import deepcopy
import json
import pytest

from benchmarks.challenges import (
    Case,
    FAILURE,
    INSUFFICIENT,
    SUPPORTED,
    generate,
)
from benchmarks.challenge_gate import grade, summarize


class TestUncorroboratedSpansAndRenderingDelays:
    def test_slow_span_without_timeout_tricks_naive_candidate(self):
        """Vulnerability: In family 'slow-span-without-timeout', payment-service has growing

        db_pool_acquire_timeouts_total (2 -> 15), but the trace latency bottleneck is
        pricing-service render_receipt (2350ms, no error).
        A candidate relying on metric growth certifies payment-service and FAILS the gate.
        """
        cases = [c for c in generate(42) if c.family == "slow-span-without-timeout"]
        assert len(cases) > 0
        case = cases[0]

        # Case ground truth requires INSUFFICIENT with next_check comparing render_receipt vs contention
        assert case.status == INSUFFICIENT
        assert case.localized_service == "pricing-service"
        assert case.localized_operation == "render_receipt"

        # Naive candidate tricked by Prometheus counter growth:
        tricked_decision = {
            "status": SUPPORTED,
            "service": "payment-service",
            "mechanism": "pool_acquisition_timeout",
            "scope": "affected_request",
            "citations": [f"prom/payment-service/db_pool_acquire_timeouts_total"],
            "localized_service": "payment-service",
            "localized_operation": "db.connection.acquire",
            "coverage": "COMPLETE",
            "next_check": "Inspect payment-service pool",
        }
        problems = grade(case, tricked_decision)
        # Gate flags false certification
        assert "wrong terminal status" in problems
        assert "wrong service" in problems
        assert "wrong mechanism" in problems


class TestChallengeGateGradingBypasses:
    def test_grading_projection_bypass_on_nondiagnostic_cases(self):
        """Vulnerability: When case.localized_service is None (e.g. stale-trace, missing-trace,

        unrelated-trace), grade() NEVER checks decision['localized_service'],
        decision['localized_operation'], or decision['scope'].
        A candidate can inject completely fabricated strings without triggering any errors!
        """
        # Pick non-diagnostic cases without localized_service
        cases = [c for c in generate(42) if c.localized_service is None]
        assert len(cases) >= 16
        case = cases[0]

        # Decision contains fabricated hallucinated fields
        smuggled_decision = {
            "status": case.status,
            "service": None,
            "mechanism": None,
            "scope": "FABRICATED_SCOPE_GLOBAL_FAILURE",
            "citations": [],
            "localized_service": "HALLUCINATED_SERVICE_NAME",
            "localized_operation": "FABRICATED_OPERATION_NAME",
            "coverage": "COMPLETE",
            "next_check": None,
        }
        # Grade MUST reject all three hallucinated projection fields
        problems = grade(case, smuggled_decision)
        assert "wrong claim scope" in problems
        assert "wrong localized service" in problems
        assert "wrong localized operation" in problems

    def test_score_inflation_via_uncalibrated_abstention(self):
        """Vulnerability: On the 20 unlocalizable cases where localized_service is None,

        a zero-reasoning candidate that always outputs static INSUFFICIENT passes 100% of them
        with 0 false support and 0 errors, inflating the score without performing any diagnosis.
        """
        cases = [c for c in generate(42) if c.localized_service is None and c.status == INSUFFICIENT]
        assert len(cases) == 12

        constant_decision = {
            "status": INSUFFICIENT,
            "service": None,
            "mechanism": None,
            "scope": None,
            "citations": [],
            "localized_service": None,
            "localized_operation": None,
            "coverage": "COMPLETE",
            "next_check": None,
        }
        rows = []
        for c in cases:
            probs = grade(c, constant_decision)
            rows.append({
                "family": c.family,
                "errors": probs,
                "expected": {"status": c.status},
                "decision": constant_decision,
            })

        summary = summarize(rows)
        # Passes all unlocalizable cases with 0 errors!
        assert summary["passed"] == len(cases)
        assert summary["false_support_on_nondiagnostic_cases"] == 0


class TestDeterministicStructuralShortcut:
    def test_hardcoded_child_and_timeout_shortcut_blocked(self):
        """Regression guard: randomized causal span IDs and mixed error markers reject hardcoded shortcuts."""
        cases = [c for c in generate(42) if c.status == SUPPORTED]
        assert len(cases) == 16

        def brittle_shortcut(incident):
            snap = incident["mock_telemetry"]
            trace = snap["tempo"].get(incident["trace_id"])
            if not trace:
                return None
            for span in trace.get("spans", []):
                if span.get("error") == "TimeoutError":
                    svc = span["service"]
                    op = span["name"]
                    mech = "pool_acquisition_timeout" if "acquire" in op else "upstream_connect_timeout"
                    counter = "db_pool_acquire_timeouts_total" if "acquire" in op else "upstream_connect_timeouts_total"
                    cov = "PARTIAL" if any(len(r.get("result", [])) > 5 for s in snap["prometheus"].values() for r in s.values()) else "COMPLETE"
                    rec = snap["prometheus"].get(svc, {}).get(counter, {})
                    res_list = rec.get("result", [])
                    rep_key = ""
                    if res_list:
                        m = res_list[0].get("metric", {})
                        parts = [f"{k}={m[k]}" for k in sorted(("pod", "instance", "container")) if k in m]
                        if parts:
                            rep_key = "/" + "|".join(parts)
                    prom_ref = f"prom/{svc}/{counter}{rep_key}"
                    return {
                        "status": SUPPORTED,
                        "service": svc,
                        "mechanism": mech,
                        "scope": "affected_request",
                        "citations": sorted([prom_ref, f"tempo/{incident['trace_id']}/child"]),
                        "localized_service": svc,
                        "localized_operation": op,
                        "coverage": cov,
                        "next_check": f"Inspect {svc} {mech} settings.",
                    }
            return None

        failures = 0
        for case in cases:
            decision = brittle_shortcut(case.incident)
            if decision is None or grade(case, decision):
                failures += 1
        assert failures == len(cases)


class TestChallengeGenerationSeedInvariance:
    @pytest.mark.parametrize("seed", [0, 42, 12345, 99999])
    def test_challenge_generation_across_seeds(self, seed):
        """Validates that challenge generator produces exact same 84-case shape across seeds."""
        cases = generate(seed)
        assert len(cases) == 84
        counts = Counter(c.status for c in cases)
        assert counts[SUPPORTED] == 16
        assert counts[INSUFFICIENT] == 64
        assert counts[FAILURE] == 4
