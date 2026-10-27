"""Adversarial exploit test suite for SystemProfile architecture

(sentinel_ops.profiles.schema, sentinel_ops.profiles.registry).

Proves:
1. Circular dependencies in ServiceSpec pass Pydantic validation, creating cyclic graphs that crash
   DAG algorithms (nx.topological_sort raises NetworkXUnfeasible).
2. Dangling/phantom service references in depends_on inject unmapped nodes into DiGraph,
   causing KeyError when indexing profile.services[node].
3. Corrupted PromQL query templates with unescaped single braces crash string formatting with KeyError/ValueError.
4. Unmapped time units (milliseconds vs seconds vs nanoseconds) cause massive threshold misinterpretations
   without normalization.
5. Boundary and malicious parameters evading Pydantic:
   - saturation_threshold = -1.0 (triggers on 0 connections)
   - saturation_threshold = NaN (never triggers; comparisons always evaluate False)
   - saturation_threshold = 9999.0 (> 1.0 for a ratio)
6. Cumulative counter misclassifications:
   - Unrated counters without standard suffix ('packet_drops', 'db_pool_timeouts') treated as gauges.
   - Gauge metrics ending in '_count' ('active_worker_count') falsely classified as cumulative counters.
7. Registry path traversal: get_profile accepts arbitrary relative paths.
8. Registry silent exception swallowing: Malformed YAML profiles are dropped with zero error logging.
"""

import math
from pathlib import Path
import networkx as nx
import pytest
from pydantic import ValidationError

from sentinel_ops.profiles.schema import (
    ServiceSpec,
    SignalMapping,
    SystemProfile,
    is_cumulative_counter_metric,
    normalize_duration_to_seconds,
)
from sentinel_ops.profiles.registry import (
    get_profile,
    load_profile_file,
    _PROFILE_CACHE,
)


class TestProfileTopologicalAndDependencyExploits:
    def test_circular_service_dependencies_pass_validation_but_crash_dag(self):
        """Vulnerability: Pydantic accepts circular service dependencies (A -> B -> A).

        build_service_graph() constructs a cyclic graph, crashing topological sort.
        """
        data = {
            "profile_id": "cyclic-profile",
            "services": {
                "svc-a": {"name": "svc-a", "depends_on": ["svc-b"]},
                "svc-b": {"name": "svc-b", "depends_on": ["svc-a"]},
            },
            "signals": {},
        }
        # Rejected by SystemProfile DAG validator!
        with pytest.raises(ValidationError, match="dependency cycle"):
            SystemProfile(**data)

    def test_dangling_service_dependency_creates_phantom_nodes(self):
        """Verify dangling depends_on entries are rejected by SystemProfile validation."""
        data = {
            "profile_id": "dangling-profile",
            "services": {
                "checkout-service": {
                    "name": "checkout-service",
                    "depends_on": ["phantom-service-does-not-exist"],
                }
            },
            "signals": {},
        }
        with pytest.raises(ValidationError, match="undefined service"):
            SystemProfile(**data)


class TestPromQLAndUnitVulnerabilities:
    def test_unescaped_single_brace_promql_crashes_formatting(self):
        """Verify malformed single-brace PromQL templates are rejected at profile load time."""
        malformed_template = 'rate(http_requests_total{status="500", service="{service}"}[1m])'
        with pytest.raises(ValidationError, match="invalid promql_template"):
            SignalMapping(
                logical_signal="error_rate",
                metric_name="http_requests_total",
                promql_template=malformed_template,
            )

    def test_unmapped_time_units_cause_magnitude_confusion(self):
        """Verify normalize_duration_to_seconds converts ms/s uniformly."""
        mapping_ms = SignalMapping(
            logical_signal="latency_p95",
            metric_name="app_latency_ms",
            promql_template="app_latency_ms",
            unit="milliseconds",
        )
        mapping_sec = SignalMapping(
            logical_signal="latency_p95",
            metric_name="app_latency_sec",
            promql_template="app_latency_sec",
            unit="seconds",
        )
        assert normalize_duration_to_seconds(500.0, mapping_ms.unit) == pytest.approx(0.5)
        assert normalize_duration_to_seconds(2500.0, mapping_ms.unit) == pytest.approx(2.5)
        assert normalize_duration_to_seconds(0.025, mapping_sec.unit) == pytest.approx(0.025)


class TestBoundaryParametersEvadingPydantic:
    def test_malicious_and_boundary_saturation_thresholds(self):
        """Verify negative, NaN, and >1.0 ratio saturation thresholds are rejected cleanly."""
        with pytest.raises(ValidationError, match="finite and non-negative"):
            SignalMapping(
                logical_signal="pool_active",
                metric_name="db_pool",
                promql_template="db_pool",
                saturation_threshold=-1.0,
            )

        with pytest.raises(ValidationError, match="finite and non-negative"):
            SignalMapping(
                logical_signal="pool_active",
                metric_name="db_pool",
                promql_template="db_pool",
                saturation_threshold=float("nan"),
            )

        with pytest.raises(ValidationError, match="<= 1.0"):
            SignalMapping(
                logical_signal="pool_active",
                metric_name="db_pool",
                promql_template="db_pool",
                saturation_threshold=9999.0,
            )


class TestCumulativeCounterClassificationFlaws:
    def test_unrated_counter_without_suffix_misclassified_as_gauge(self):
        """Verify known unrated cumulative counters without _total suffix are detected cleanly."""
        assert is_cumulative_counter_metric(
            promql='db_pool_timeouts{service="payment"}',
            signal_name="db_pool_timeouts",
        )
        assert is_cumulative_counter_metric(
            promql='packet_drops{service="ingress"}',
            signal_name="packet_drops",
        )

    def test_gauge_ending_with_count_falsely_classified_as_counter(self):
        """Verify gauge metrics ending in '_count' are NOT misclassified as cumulative counters."""
        is_counter = is_cumulative_counter_metric(
            promql='active_worker_count{service="render"}',
            signal_name="active_worker_count",
        )
        assert is_counter is False


class TestRegistryVulnerabilities:
    def test_registry_arbitrary_path_traversal(self, tmp_path):
        """Vulnerability: get_profile accepts arbitrary relative file paths, loading profiles

        outside designated repository directories.
        """
        outside_profile = tmp_path / "outside_profile.yaml"
        outside_profile.write_text(
            """
profile_id: untrusted-outside-profile
services: {}
signals: {}
""",
            encoding="utf-8",
        )
        # get_profile resolves and loads outside_profile directly
        loaded = get_profile(str(outside_profile))
        assert loaded.profile_id == "untrusted-outside-profile"

    def test_registry_silent_swallowing_of_corrupted_profiles(self, tmp_path, monkeypatch):
        """Vulnerability: _ensure_builtin_profiles_loaded silently swallows all Exceptions,

        leaving production operators blind if a YAML profile has invalid syntax.
        """
        import sentinel_ops.profiles.registry as reg
        monkeypatch.setattr(reg, "PROFILES_DIR", tmp_path)
        monkeypatch.setattr(reg, "BUNDLED_PROFILES_DIR", tmp_path)

        corrupted = tmp_path / "corrupted_profile.yaml"
        corrupted.write_text("invalid_yaml: [: malformed", encoding="utf-8")

        # Does not raise any exception, silently drops it
        reg._ensure_builtin_profiles_loaded()
        assert "corrupted_profile" not in reg._PROFILE_CACHE
