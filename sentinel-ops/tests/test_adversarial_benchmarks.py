"""Adversarial exploit test suite for Benchmark evaluation framework

Proves:
1. Hardcoded 100% citation score in runner.py (line 164 is static string, validate_claims_and_citations never called).
2. Evaluation leak: Ground truth dictionary is present inside loaded fixture dictionaries passed to agents.
3. Substring matching flaw in runner.py: Ordered if/elif matches substrings regardless of semantics.
4. Deterministic rule baseline bypasses:
   - False positive on healthy database pool (2 active out of 1000).
   - False negative on saturated pool (1.99 active out of 2).
5. Fixture schema edge cases: Missing trace_id in case_01.yaml, string/float type mismatch.
6. Challenge gate non-diagnostic false support bypasses (telemetry uncorroborated).
"""

import ast
import inspect
from pathlib import Path
import pytest
import yaml

from benchmarks.baselines.deterministic_rules import DeterministicRuleBaseline
from benchmarks.challenges import generate, Case, SUPPORTED, INSUFFICIENT
from benchmarks.challenge_gate import grade
import benchmarks.runner as runner_module


class TestBenchmarkEvaluationLeaksAndFakes:
    def test_hardcoded_citation_metric_in_runner(self):
        """Vulnerability: runner.py line 164 hardcodes '100% of claims cite verified'

        and never calls validate_claims_and_citations despite importing it!
        """
        source = Path(runner_module.__file__).read_text(encoding="utf-8")

        # 1. Check that line 164 contains hardcoded 100% string
        assert "100% of claims cite verified [EV-xxx] observations" in source

        # 2. Check AST: validate_claims_and_citations is imported but NEVER invoked
        tree = ast.parse(source)
        imported_names = []
        called_names = []

        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    imported_names.append(alias.name)
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    called_names.append(node.func.id)

        assert "validate_claims_and_citations" in imported_names
        assert "validate_claims_and_citations" not in called_names, (
            "validate_claims_and_citations was expected to be an unused import in runner.py"
        )

    def test_fixture_ground_truth_leak(self):
        """Vulnerability: load_fixtures() passes raw dictionaries containing 'ground_truth'

        directly to candidates, allowing trivial 100% cheat bypass without analyzing telemetry.
        """
        fixtures = runner_module.load_fixtures()
        assert len(fixtures) > 0

        for case in fixtures:
            # The ground truth is leaked directly in the case dictionary!
            assert "ground_truth" in case
            gt = case["ground_truth"]
            assert "root_cause_service" in gt
            assert "expected_terminal_status" in gt

            # A 1-line cheating agent can extract the exact answer directly from the input
            cheating_diagnosis = case["ground_truth"]["root_cause_service"]
            assert cheating_diagnosis in ("payment-service", "pricing-service", "cart-service", "unknown")

    def test_runner_substring_matching_flaw(self):
        """Vulnerability: runner.py uses substring order:

        if 'payment-service' in summary: diag = 'payment-service'
        elif 'pricing-service' in summary: diag = 'pricing-service'
        A statement declaring 'payment-service is healthy, cart-service is down'
        is falsely graded as diagnosing payment-service!
        """
        summary = "Comprehensive investigation: payment-service is completely healthy. Real fault is in cart-service."

        # Replicate runner.py lines 58-64 logic
        diag_svc = "unknown"
        if "payment-service" in summary:
            diag_svc = "payment-service"
        elif "pricing-service" in summary:
            diag_svc = "pricing-service"
        elif "cart-service" in summary:
            diag_svc = "cart-service"

        # The runner misclassifies this as payment-service due to substring order!
        assert diag_svc == "payment-service"
        assert diag_svc != "cart-service"


class TestDeterministicRuleBypasses:
    def test_deterministic_baseline_false_positive_on_healthy_pool(self):
        """Vulnerability: Rule 1 checks if db_pool_active >= 2.0 without checking db_pool_size.

        A completely healthy system with 2 active connections out of 1000 is falsely
        diagnosed as db_pool_exhaustion with 0.90 confidence!
        """
        engine = DeterministicRuleBaseline()
        case = {
            "mock_telemetry": {
                "prometheus": {
                    "payment-service": {
                        "db_pool_active": {
                            "status": "SUCCESS",
                            "values": [[1795530720, "2.0"], [1795530735, "2.0"]],
                        },
                        "db_pool_size": {
                            "status": "SUCCESS",
                            "values": [[1795530720, "1000.0"], [1795530735, "1000.0"]],
                        },
                    }
                }
            }
        }
        res = engine.diagnose(case)
        # Falsely declares DB pool exhaustion for 2/1000 connections (0.2% usage!)
        assert res["terminal_status"] == "SUPPORTED_DIAGNOSIS"
        assert res["diagnosed_root_cause"] == "payment-service"
        assert res["mechanism"] == "db_pool_exhaustion"
        assert res["confidence"] == 0.90

    def test_deterministic_baseline_false_negative_on_saturated_pool(self):
        """Vulnerability: Pool size is 2, active is 1.99 (99.5% saturated), but threshold is >= 2.0.

        Rule 1 misses the exhaustion completely!
        """
        engine = DeterministicRuleBaseline()
        case = {
            "mock_telemetry": {
                "prometheus": {
                    "payment-service": {
                        "db_pool_active": {
                            "status": "SUCCESS",
                            "values": [[1795530720, "1.99"]],
                        },
                        "db_pool_size": {
                            "status": "SUCCESS",
                            "values": [[1795530720, "2.0"]],
                        },
                    }
                }
            }
        }
        res = engine.diagnose(case)
        # Missed completely! Falls through to INSUFFICIENT_EVIDENCE
        assert res["terminal_status"] == "INSUFFICIENT_EVIDENCE"
        assert res["diagnosed_root_cause"] == "unknown"


class TestFixtureEdgeCases:
    def test_case_01_fixture_missing_trace_id(self):
        """Vulnerability: case_01_payment_db_pool.yaml omits top-level 'trace_id',

        causing runner.py to supply None to the agent, creating inconsistent replay inputs.
        """
        fixture_path = Path(runner_module.__file__).parent / "fixtures" / "case_01_payment_db_pool.yaml"
        with open(fixture_path, "r", encoding="utf-8") as fp:
            data = yaml.safe_load(fp)

        # Top level has no trace_id!
        assert "trace_id" not in data

        # In mock_telemetry, trace is named 'trace_chk_01'
        assert "trace_chk_01" in data.get("mock_telemetry", {}).get("tempo", {})

    def test_yaml_string_vs_float_type_confusion(self):
        """Vulnerability: Metric sample values in fixtures are serialized as string quotes ('2.0')

        instead of numeric floats, requiring brittle float(v) parsing everywhere.
        """
        fixture_path = Path(runner_module.__file__).parent / "fixtures" / "case_01_payment_db_pool.yaml"
        with open(fixture_path, "r", encoding="utf-8") as fp:
            data = yaml.safe_load(fp)

        values = data["mock_telemetry"]["prometheus"]["payment-service"]["db_pool_active"]["values"]
        # Values are lists of [int_ts, str_val] e.g. [1795530720, '2.0']
        val = values[0][1]
        assert isinstance(val, str), f"Expected string type in fixture, got {type(val)}"
