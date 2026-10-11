"""Adversarial exploit test suite for multi-hop causal reasoning and blast radius engine

(sentinel_ops.agents.blast_radius).

Proves:
1. Score explosion (> 1.0) due to hardcoded /4.0 denominator on larger topologies.
2. Inverted blast radius: Core user-facing edge gateway (checkout-service) classified as
   minimal Low Risk (0.04) because it has 0 upstream callers, while internal leaves get High Risk.
3. Cascading downstream failure blindness: Reverse blast radius completely ignores downstream
   descendants and cascading failure propagation.
4. Circular dependency symmetry deadlock: In cycles, all services produce identical blast scores.
5. Unsafe action weight fallback: Dangerous actions ('drop_database', 'purge_state') default to 0.5.
"""

import networkx as nx
import pytest
from sentinel_ops.agents.blast_radius import (
    build_service_graph,
    calculate_reverse_blast_radius,
)


class TestBlastRadiusVulnerabilities:
    def test_score_explosion_past_one_due_to_hardcoded_denominator(self, monkeypatch):
        """HARDENING REGRESSION TEST:
        Blast radius score must remain strictly bounded in [0.0, 1.0],
        even on large topologies with many callers.
        """
        large_graph = nx.DiGraph()
        for i in range(8):
            large_graph.add_edge(f"service-{i}", "shared-db")

        import sentinel_ops.agents.blast_radius as br
        monkeypatch.setattr(br, "build_service_graph", lambda: large_graph)

        res = br.calculate_reverse_blast_radius("shared-db", action="db_pool_resize")
        # Blast radius score is strictly bounded <= 1.0
        assert res["blast_radius_score"] <= 1.0
        assert res["blast_radius_score"] == 0.92

    def test_inverted_blast_radius_edge_gateway_low_risk(self):
        """Vulnerability: Customer-facing gateway (checkout-service) has 0 upstream callers,

        so restarting it is evaluated as 'Low Risk' (0.04 score), despite 100% customer downtime!
        Meanwhile, restarting an internal leaf dependency (postgres-db) is evaluated as High Risk (0.62).
        """
        res_gateway = calculate_reverse_blast_radius("checkout-service", action="config_reload")
        res_postgres = calculate_reverse_blast_radius("postgres-db", action="db_pool_resize")

        # Public gateway has 0 callers in reverse traversal -> 0.04 score, Low Risk!
        assert res_gateway["blast_radius_score"] == 0.04
        assert res_gateway["blast_radius_level"] == "Low"
        assert len(res_gateway["affected_callers"]) == 0

        # Internal leaf has 2 callers -> 0.62 score, Medium/High Risk
        assert res_postgres["blast_radius_score"] >= 0.50
        assert res_postgres["blast_radius_level"] in ("Medium", "High")

        # INVERSION EXPLOIT: Disrupting the entire user entrance has 15x LESS risk score
        # than modifying an internal leaf database!
        assert res_gateway["blast_radius_score"] < res_postgres["blast_radius_score"]

    def test_cascading_downstream_failure_blindness(self):
        """INVARIANT: Ingress restart accounts for downstream reachability while separating upstream callers."""
        graph = build_service_graph()
        descendants = nx.descendants(graph, "checkout-service")
        assert len(descendants) == 4

        res = calculate_reverse_blast_radius("checkout-service", action="restart")
        assert len(res["affected_callers"]) == 0
        assert len(res["downstream_dependencies"]) == 4
        assert res["blast_radius_score"] >= 0.45
        assert res["blast_radius_level"] in ("Medium", "High")

    def test_circular_dependency_symmetry_deadlock(self, monkeypatch):
        """Vulnerability: In a circular dependency A -> B -> C -> A,

        every node has the exact same ancestors and receives the exact same blast radius score,
        blinding the multi-hop reasoning engine from detecting the causal origin.
        """
        cycle_graph = nx.DiGraph()
        cycle_graph.add_edge("svc-a", "svc-b")
        cycle_graph.add_edge("svc-b", "svc-c")
        cycle_graph.add_edge("svc-c", "svc-a")

        import sentinel_ops.agents.blast_radius as br
        monkeypatch.setattr(br, "build_service_graph", lambda: cycle_graph)

        res_a = br.calculate_reverse_blast_radius("svc-a", action="restart")
        res_b = br.calculate_reverse_blast_radius("svc-b", action="restart")
        res_c = br.calculate_reverse_blast_radius("svc-c", action="restart")

        # In cyclic topology, all 3 services produce identical affected caller counts and scores
        assert len(res_a["affected_callers"]) == len(res_b["affected_callers"]) == len(res_c["affected_callers"]) == 2
        assert res_a["blast_radius_score"] == res_b["blast_radius_score"] == res_c["blast_radius_score"]

    def test_unsafe_fallback_for_catastrophic_actions(self):
        """HARDENING REGRESSION TEST:
        Dangerous unmapped actions (e.g. 'drop_all_tables') must be flagged
        as Critical Risk (1.00) and never treated with routine restart weight.
        """
        res_routine = calculate_reverse_blast_radius("payment-service", action="restart")
        res_catastrophic = calculate_reverse_blast_radius("payment-service", action="drop_all_tables")

        assert res_catastrophic["blast_radius_score"] == 1.0
        assert res_catastrophic["blast_radius_level"] == "Critical"
        assert res_catastrophic["blast_radius_score"] > res_routine["blast_radius_score"]
