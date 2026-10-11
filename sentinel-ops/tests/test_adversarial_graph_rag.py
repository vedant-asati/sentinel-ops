"""Adversarial exploit test suite for GraphRAG memory system (sentinel_ops.memory.graph_rag).

Proves:
1. Disconnected subgraph & topological distance inversion:
   Disconnected service (no path) is scored higher/closer than deep connected service (>= 6 hops).
2. Undirected graph direction blindness:
   Reverses caller -> callee causality, treating downstream victims as upstream causes.
3. Circular dependencies:
   Cycles collapse into bidirectional cliques, shortcutting causal hop distance.
4. Vector distance degeneracy:
   Zero semantic similarity alerts still yield high-confidence postmortem recommendations.
   Non-alphanumeric and single-character tokens silently dropped by regex.
5. Edge weight corruption:
   Graph weights (latency, failure rate, bandwidth) completely ignored by shortest path.
6. Temporal decay vulnerabilities:
   Timezone mismatch silently swallowed, future postmortems scored with max recency (1.0),
   and zero/negative tau crashes swallowed.
"""

import math
import networkx as nx
import pytest
from datetime import datetime, timezone

from sentinel_ops.memory.graph_rag import (
    TopologyGraphRAG,
    PostmortemIncident,
    compute_text_cosine_similarity,
    tokenize,
)


class TestGraphRAGPathologicalTopologies:
    def test_disconnected_subgraph_distance_inversion(self):
        """HARDENING REGRESSION TEST:
        Disconnected subgraphs must return infinite distance (0.0 proximity),
        ranking connected deep dependencies strictly HIGHER than unreachable services.
        """
        g = nx.DiGraph()
        chain = ["A", "B", "C", "D", "E", "F", "G"]
        for i in range(len(chain) - 1):
            g.add_edge(chain[i], chain[i + 1])

        # Add completely isolated/disconnected node Z
        g.add_node("Z")

        rag = TopologyGraphRAG(graph=g)

        dist_connected = rag.calculate_graph_distance("A", "G")
        dist_disconnected = rag.calculate_graph_distance("A", "Z")

        assert dist_connected == 6.0
        assert math.isinf(dist_disconnected)

        topo_score_connected = 1.0 / (1.0 + dist_connected)
        topo_score_disconnected = 0.0

        # Connected service is ranked HIGHER than disconnected service
        assert topo_score_connected > topo_score_disconnected

    def test_circular_dependency_collapses_causal_distance(self):
        """HARDENING REGRESSION TEST:
        In a directed circular dependency A -> B -> C -> A,
        directional causal distance from A to C is 2 hops (A -> B -> C)
        and must not be shortcutted to 1 hop.
        """
        g = nx.DiGraph()
        g.add_edge("checkout-service", "cart-service")
        g.add_edge("cart-service", "auth-service")
        g.add_edge("auth-service", "checkout-service")  # circular dependency

        rag = TopologyGraphRAG(graph=g)
        dist = rag.calculate_graph_distance("checkout-service", "auth-service")
        assert dist == 2.0

    def test_direction_blindness_confuses_cause_and_effect(self):
        """Vulnerability: DiGraph is converted to undirected, making callee -> caller

        distance identical to caller -> callee, destroying causal ordering.
        """
        g = nx.DiGraph()
        # checkout calls payment, payment calls postgres. Postgres NEVER calls checkout.
        g.add_edge("checkout-service", "payment-service")
        g.add_edge("payment-service", "postgres-db")

        rag = TopologyGraphRAG(graph=g)

        # In undirected graph, postgres-db -> checkout is 2.0
        dist_reverse = rag.calculate_graph_distance("postgres-db", "checkout-service")
        dist_forward = rag.calculate_graph_distance("checkout-service", "postgres-db")

        assert dist_reverse == dist_forward == 2.0

        # But in directed graph, postgres cannot reach checkout at all!
        with pytest.raises(nx.NetworkXNoPath):
            nx.shortest_path_length(g, "postgres-db", "checkout-service")


class TestVectorDistanceDegeneracy:
    def test_zero_similarity_forces_confident_retrieval(self):
        """HARDENING REGRESSION TEST:
        An alert with zero semantic similarity to any postmortem must be penalized
        (composite_score < 0.25) so irrelevant postmortems are not falsely promoted.
        """
        postmortems = [
            PostmortemIncident(
                incident_id="INC-HIST-01",
                target_service="checkout-service",
                title="Payment DB Connection Pool Exhaustion",
                root_cause_service="checkout-service",
                mechanism="db_pool_exhaustion",
                resolution="Increase pool size",
                timestamp="2026-11-24T10:00:00Z",
                summary="Payment DB pool saturated.",
            )
        ]

        rag = TopologyGraphRAG(postmortems=postmortems)

        alert_text = "Frontend navbar button purple color misaligned on safari browser"
        results = rag.retrieve(
            alert_text=alert_text,
            target_service="checkout-service",
            incident_timestamp="2026-11-24T10:00:00Z",
            top_k=1,
        )

        assert len(results) == 1
        res = results[0]
        assert res["sim_score"] == 0.0
        # Composite score is penalized below 0.25 threshold
        assert res["composite_score"] < 0.25

    def test_token_inflation_degeneracy(self):
        """Vulnerability: Repeated tokens artificially inflate term frequency without IDF weighting."""
        text1 = "timeout " * 100
        text2 = "timeout error in payment database pool"
        sim = compute_text_cosine_similarity(text1, text2)
        # Cosine similarity is non-zero solely from repetitive token flooding
        assert sim > 0.0

    def test_special_characters_and_single_char_token_stripping(self):
        """INVARIANT: Single-character tokens are preserved so 'service A' != 'service B'."""
        assert tokenize("a b c d") == ["a", "b", "c", "d"]
        assert compute_text_cosine_similarity("service A", "service A") == pytest.approx(1.0)
        assert compute_text_cosine_similarity("service A", "service B") < 1.0


class TestEdgeWeightCorruption:
    def test_edge_weights_are_completely_ignored(self):
        """Vulnerability: TopologyGraphRAG does not accept or evaluate edge weights (latency, failure rate)."""
        g = nx.DiGraph()
        # High-latency path with weight 1000.0 vs low-latency path with weight 1.0
        g.add_edge("A", "B", weight=1000.0)
        g.add_edge("A", "C", weight=1.0)
        g.add_edge("C", "B", weight=1.0)

        rag = TopologyGraphRAG(graph=g)
        # Undirected shortest path length ignores weights: A -> B is 1 hop!
        unweighted_dist = rag.calculate_graph_distance("A", "B")
        assert unweighted_dist == 1.0

        # Weighted shortest path would take A -> C -> B (weight 2.0 < 1000.0)
        weighted_dist = nx.shortest_path_length(g.to_undirected(), "A", "B", weight="weight")
        assert weighted_dist == 2.0
        assert unweighted_dist != weighted_dist


class TestTemporalDecayVulnerabilities:
    def test_offset_naive_vs_aware_silent_exception(self):
        """INVARIANT: Naive and UTC-aware ISO timestamps normalize cleanly instead of falling back to 0.5."""
        rag = TopologyGraphRAG()
        decay_naive = rag.calculate_recency_decay("2026-11-24T14:32:00", "2026-10-15T10:00:00Z")
        decay_aware = rag.calculate_recency_decay("2026-11-24T14:32:00Z", "2026-10-15T10:00:00Z")
        assert decay_naive == pytest.approx(decay_aware)
        assert decay_naive != 0.5

    def test_future_postmortem_yields_maximum_recency(self):
        """INVARIANT: Future-dated postmortems relative to incident time receive 0.0 recency score."""
        rag = TopologyGraphRAG()
        decay = rag.calculate_recency_decay("2026-11-24T14:32:00Z", "2027-11-24T14:32:00Z")
        assert decay == 0.0

    def test_zero_and_negative_tau_crashes_swallowed(self):
        """INVARIANT: Non-positive tau_days raises explicit ValueError rather than swallowing division errors."""
        rag_zero_tau = TopologyGraphRAG(tau_days=0.0)
        with pytest.raises(ValueError, match="tau_days must be positive"):
            rag_zero_tau.calculate_recency_decay("2026-11-24T14:32:00Z", "2026-10-15T10:00:00Z")
