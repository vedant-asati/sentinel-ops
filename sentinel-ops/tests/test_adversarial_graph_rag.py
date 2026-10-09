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
        """Vulnerability: Disconnected subgraphs return fallback distance 5.0,

        ranking an isolated/unreachable service CLOSER than a connected service 6 hops away!
        """
        g = nx.DiGraph()
        # Build 6-hop connected chain: A -> B -> C -> D -> E -> F -> G (distance 6)
        chain = ["A", "B", "C", "D", "E", "F", "G"]
        for i in range(len(chain) - 1):
            g.add_edge(chain[i], chain[i + 1])

        # Add completely isolated/disconnected node Z (separate cluster/zone)
        g.add_node("Z")

        rag = TopologyGraphRAG(graph=g)

        dist_connected = rag.calculate_graph_distance("A", "G")
        dist_disconnected = rag.calculate_graph_distance("A", "Z")

        # Distance to connected service is 6.0
        assert dist_connected == 6.0
        # Distance to completely disconnected service falls back to 5.0!
        assert dist_disconnected == 5.0

        # Topological score: 1 / (1 + dist)
        topo_score_connected = 1.0 / (1.0 + dist_connected)       # 1/7 = 0.1429
        topo_score_disconnected = 1.0 / (1.0 + dist_disconnected) # 1/6 = 0.1667

        # EXPLOIT: Disconnected service receives a HIGHER proximity score than connected service!
        assert topo_score_disconnected > topo_score_connected, (
            f"Expected disconnected node score ({topo_score_disconnected:.4f}) "
            f"to invert and exceed connected node score ({topo_score_connected:.4f})"
        )

    def test_circular_dependency_collapses_causal_distance(self):
        """Vulnerability: In a directed circular dependency A -> B -> C -> A,

        converting to undirected collapses directional causal distance from 2 hops (A->B->C) to 1 hop.
        """
        g = nx.DiGraph()
        g.add_edge("checkout-service", "cart-service")
        g.add_edge("cart-service", "auth-service")
        g.add_edge("auth-service", "checkout-service")  # circular dependency

        rag = TopologyGraphRAG(graph=g)
        # Undirected distance between checkout and auth is 1.0 (via reverse edge)
        dist = rag.calculate_graph_distance("checkout-service", "auth-service")
        assert dist == 1.0

        # Causal directed distance from checkout to auth is actually 2 hops (checkout -> cart -> auth)
        causal_directed_dist = nx.shortest_path_length(g, "checkout-service", "auth-service")
        assert causal_directed_dist == 2.0
        assert dist < causal_directed_dist  # Undirected shortcuts causal direction

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
        """Vulnerability: An alert with zero semantic similarity to any postmortem

        still receives composite score >= 0.50 if target_service matches root_cause_service,
        forcing irrelevant postmortem recommendations into agent state.
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

        # Alert has completely zero semantic relevance (UI/CSS issue)
        alert_text = "Frontend navbar button purple color misaligned on safari browser"
        results = rag.retrieve(
            alert_text=alert_text,
            target_service="checkout-service",
            incident_timestamp="2026-11-24T10:00:00Z",
            top_k=1,
        )

        assert len(results) == 1
        res = results[0]
        # Text similarity is 0.0
        assert res["sim_score"] == 0.0
        # But composite score is 0.50 (w_graph * 1.0 + w_decay * 1.0)
        assert res["composite_score"] >= 0.50
        # Agent receives a false hypothesis recommendation for a CSS bug!
        assert "Investigate checkout-service for db_pool_exhaustion" in res["recommended_hypothesis"]

    def test_token_inflation_degeneracy(self):
        """Vulnerability: Repeated tokens artificially inflate term frequency without IDF weighting."""
        text1 = "timeout " * 100
        text2 = "timeout error in payment database pool"
        sim = compute_text_cosine_similarity(text1, text2)
        # Cosine similarity is non-zero solely from repetitive token flooding
        assert sim > 0.0

    def test_special_characters_and_single_char_token_stripping(self):
        """Vulnerability: Regex [a-zA-Z0-9_-]{2,} silently drops single-character tokens and symbols.

        Identical texts consisting of symbols or single-letter names return 0.0 similarity.
        """
        assert tokenize("a b c d") == []
        assert tokenize("$$$ ### @@@") == []
        assert compute_text_cosine_similarity("service A", "service A") == 1.0  # only 'service' matched
        assert compute_text_cosine_similarity("service A", "service B") == 1.0  # A and B dropped, gives false 1.0!


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
        """Vulnerability: Naive timestamp vs aware timestamp raises TypeError in datetime,

        silently swallowed by broad except Exception, falling back to static 0.5.
        """
        rag = TopologyGraphRAG()
        # incident_time has no timezone (naive), postmortem has Z (aware)
        decay = rag.calculate_recency_decay("2026-11-24T14:32:00", "2026-10-15T10:00:00Z")
        assert decay == 0.5  # Silent fallback due to caught TypeError

    def test_future_postmortem_yields_maximum_recency(self):
        """Vulnerability: If postmortem timestamp is in the future relative to incident (clock skew),

        delta_days is clamped to max(0.0, negative) = 0.0, returning max decay score 1.0.
        """
        rag = TopologyGraphRAG()
        # Postmortem is in the future (year 2027) relative to incident (2026)
        decay = rag.calculate_recency_decay("2026-11-24T14:32:00Z", "2027-11-24T14:32:00Z")
        assert decay == 1.0

    def test_zero_and_negative_tau_crashes_swallowed(self):
        """Vulnerability: tau_days <= 0 causes ZeroDivisionError, silently swallowed and returns 0.5."""
        rag_zero_tau = TopologyGraphRAG(tau_days=0.0)
        decay = rag_zero_tau.calculate_recency_decay("2026-11-24T14:32:00Z", "2026-10-15T10:00:00Z")
        assert decay == 0.5
