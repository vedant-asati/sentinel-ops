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
        """Vulnerability: caller_ratio = len(affected_callers) / 4.0 hardcodes 4.0.

        In a 10-service topology, a shared dependency with 8 callers results in
        caller_ratio = 2.0 and blast_radius_score = 1.52 (> 1.0), breaking score invariants!
        """
        # Create a topology with 10 microservices all calling shared-db
        large_graph = nx.DiGraph()
        for i in range(8):
            large_graph.add_edge(f"service-{i}", "shared-db")

        # Monkeypatch build_service_graph to return large_graph
        import sentinel_ops.agents.blast_radius as br
        monkeypatch.setattr(br, "build_service_graph", lambda: large_graph)

        res = br.calculate_reverse_blast_radius("shared-db", action="db_pool_resize")
        # Blast radius score explodes past 1.0!
        assert res["blast_radius_score"] > 1.0, f"Expected score > 1.0, got {res['blast_radius_score']}"
        assert res["blast_radius_score"] == 1.52  # (0.6 * 8/4) + (0.4 * 0.8) = 1.2 + 0.32

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
        """Vulnerability: calculate_reverse_blast_radius only inspects ancestors (callers),

        ignoring downstream descendants (callees). If checkout-service fails and cascades down
        to cart, pricing, payment, none of these affected systems are accounted for.
        """
        graph = build_service_graph()
        # checkout-service has 3 direct downstream dependents and 1 transitive (postgres-db)
        descendants = nx.descendants(graph, "checkout-service")
        assert len(descendants) == 4

        # But reverse blast radius reports ZERO affected systems for checkout-service!
        res = calculate_reverse_blast_radius("checkout-service", action="restart")
        assert len(res["affected_callers"]) == 0
        assert not set(res["affected_callers"]).intersection(descendants)

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
        """Vulnerability: Dangerous unmapped actions (e.g. 'drop_all_tables', 'kernel_panic')

        fall back to action_weights.get(action, 0.5), treating a catastrophic wipe with the same
        weight as a routine restart (0.5).
        """
        res_routine = calculate_reverse_blast_radius("payment-service", action="restart")
        res_catastrophic = calculate_reverse_blast_radius("payment-service", action="drop_all_tables")

        # Catastrophic table drop has the exact same score as a safe service restart!
        assert res_routine["blast_radius_score"] == res_catastrophic["blast_radius_score"]
