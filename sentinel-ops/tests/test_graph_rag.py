import pytest
from sentinel_ops.memory.graph_rag import (
    TopologyGraphRAG,
    compute_text_cosine_similarity,
)


def test_cosine_similarity():
    sim = compute_text_cosine_similarity("payment database connection pool timeout", "payment database pool saturated")
    assert sim > 0.4
    sim_zero = compute_text_cosine_similarity("apple banana", "zebra giraffe")
    assert sim_zero == 0.0


def test_graph_distance_and_decay():
    rag = TopologyGraphRAG()
    # Direct edge: checkout-service -> payment-service (distance 1.0)
    dist = rag.calculate_graph_distance("checkout-service", "payment-service")
    assert dist == 1.0

    # Self distance is 0.0
    assert rag.calculate_graph_distance("checkout-service", "checkout-service") == 0.0

    # Recency decay for same time is 1.0
    decay = rag.calculate_recency_decay("2026-10-15T10:00:00Z", "2026-10-15T10:00:00Z")
    assert pytest.approx(decay, 0.01) == 1.0


def test_graph_rag_retrieval_payment():
    rag = TopologyGraphRAG()
    results = rag.retrieve(
        alert_text="checkout-service experiencing high latency and payment-service 504 gateway timeout",
        target_service="checkout-service",
        incident_timestamp="2026-11-24T14:32:00Z",
        top_k=2,
    )
    assert len(results) == 2
    top = results[0]
    # Top match should be INC-HIST-01 (Payment DB connection pool)
    assert top["postmortem"].incident_id == "INC-HIST-01"
    assert top["composite_score"] > 0.25
