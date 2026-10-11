import math
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
import networkx as nx
from pydantic import BaseModel, Field

from sentinel_ops.agents.blast_radius import build_service_graph


class PostmortemIncident(BaseModel):
    """Historical postmortem incident record."""
    incident_id: str
    target_service: str
    title: str
    root_cause_service: str
    mechanism: str
    resolution: str
    timestamp: str  # ISO-8601
    summary: str


# Pre-seeded historical postmortems
PRESEEDED_POSTMORTEMS: List[PostmortemIncident] = [
    PostmortemIncident(
        incident_id="INC-HIST-01",
        target_service="checkout-service",
        title="Checkout Latency Spikes Caused by Payment DB Connection Pool Saturation",
        root_cause_service="payment-service",
        mechanism="db_pool_exhaustion",
        resolution="Increased payment-service HikariCP connection pool size from 2 to 50.",
        timestamp="2026-10-15T10:00:00Z",
        summary="Checkout timeouts accompanied by payment 504s. Root cause was max connection pool exhaustion on Postgres.",
    ),
    PostmortemIncident(
        incident_id="INC-HIST-02",
        target_service="checkout-service",
        title="Pricing Algorithm Inefficiency Causing Checkout Span Delays",
        root_cause_service="pricing-service",
        mechanism="cpu_algorithmic_latency",
        resolution="Optimized discount calculation algorithm and added Redis cache layer.",
        timestamp="2026-09-01T14:30:00Z",
        summary="Checkout latency increased to 4s due to cryptographic discount validation loop consuming 98% CPU in pricing-service.",
    ),
    PostmortemIncident(
        incident_id="INC-HIST-03",
        target_service="cart-service",
        title="Cart Service Memory Exhaustion from Session Leaks",
        root_cause_service="cart-service",
        mechanism="memory_leak",
        resolution="Cleared unbounded session array and added TTL eviction.",
        timestamp="2026-08-20T08:15:00Z",
        summary="Cart service container OOMKilled (Exit 137) due to memory leak in session tracking cache.",
    ),
]


def tokenize(text: str) -> List[str]:
    """Extract lowercase alphanumeric tokens (including single-character IDs) from text."""
    return re.findall(r"\b[a-zA-Z0-9_\-]+\b", text.lower())


def compute_text_cosine_similarity(text1: str, text2: str) -> float:
    """Computes cosine similarity between two text strings using term frequencies."""
    tokens1 = tokenize(text1)
    tokens2 = tokenize(text2)
    if not tokens1 or not tokens2:
        return 0.0

    c1 = Counter(tokens1)
    c2 = Counter(tokens2)
    intersection = set(c1.keys()) & set(c2.keys())
    numerator = sum(c1[t] * c2[t] for t in intersection)

    norm1 = math.sqrt(sum(v * v for v in c1.values()))
    norm2 = math.sqrt(sum(v * v for v in c2.values()))
    if norm1 == 0 or norm2 == 0:
        return 0.0
    return numerator / (norm1 * norm2)


class TopologyGraphRAG:
    """Topology-Aware GraphRAG memory engine.

    Combines:
      1. Text Semantic Similarity (CosineSim)
      2. Service Graph Topological Distance: 1 / (1 + GraphDistance(S_alert, S_p))
      3. Recency Decay: exp(-delta_t / tau)
    """

    def __init__(
        self,
        postmortems: Optional[List[PostmortemIncident]] = None,
        graph: Optional[nx.DiGraph] = None,
        w_sim: float = 0.5,
        w_graph: float = 0.3,
        w_decay: float = 0.2,
        tau_days: float = 90.0,
    ):
        self.postmortems = postmortems or list(PRESEEDED_POSTMORTEMS)
        self.graph = graph or build_service_graph()
        self.w_sim = w_sim
        self.w_graph = w_graph
        self.w_decay = w_decay
        self.tau_days = tau_days

    def calculate_graph_distance(self, svc_alert: str, svc_postmortem: str) -> float:
        """Calculates causal directed distance between alert origin and postmortem service."""
        if svc_alert == svc_postmortem:
            return 0.0
        if svc_alert in self.graph and svc_postmortem in self.graph:
            if nx.has_path(self.graph, svc_alert, svc_postmortem):
                return float(nx.shortest_path_length(self.graph, svc_alert, svc_postmortem))
            elif nx.has_path(self.graph, svc_postmortem, svc_alert):
                return float(nx.shortest_path_length(self.graph, svc_postmortem, svc_alert))
        return float("inf")

    def calculate_recency_decay(self, incident_time_iso: str, postmortem_time_iso: str) -> float:
        """Calculates exponential decay factor exp(-delta_days / tau_days) with UTC normalization."""
        if self.tau_days <= 0:
            raise ValueError(f"tau_days must be positive, got {self.tau_days}")
        try:
            t_now = datetime.fromisoformat(incident_time_iso.replace("Z", "+00:00"))
            t_pm = datetime.fromisoformat(postmortem_time_iso.replace("Z", "+00:00"))
            if t_now.tzinfo is None:
                t_now = t_now.replace(tzinfo=timezone.utc)
            if t_pm.tzinfo is None:
                t_pm = t_pm.replace(tzinfo=timezone.utc)
            diff_seconds = (t_now - t_pm).total_seconds()
            if diff_seconds < 0:
                # Penalize postmortem dated in the future relative to incident (clock skew / invalid)
                return 0.0
            delta_days = diff_seconds / 86400.0
            return math.exp(-delta_days / self.tau_days)
        except Exception:
            return 0.5

    def retrieve(
        self,
        alert_text: str,
        target_service: str,
        incident_timestamp: str,
        top_k: int = 2,
    ) -> List[Dict[str, Any]]:
        """Retrieves and ranks the top-k most relevant historical postmortems."""
        scored_records = []

        for pm in self.postmortems:
            sim_score = compute_text_cosine_similarity(alert_text, f"{pm.title} {pm.summary}")
            graph_dist = self.calculate_graph_distance(target_service, pm.root_cause_service)
            if math.isinf(graph_dist):
                topo_score = 0.0
            else:
                topo_score = 1.0 / (1.0 + graph_dist)
            decay_score = self.calculate_recency_decay(incident_timestamp, pm.timestamp)

            composite_score = (
                (self.w_sim * sim_score)
                + (self.w_graph * topo_score)
                + (self.w_decay * decay_score)
            )
            # If text similarity is zero (completely irrelevant incident text), penalize composite score
            if sim_score == 0.0:
                composite_score = composite_score * 0.2

            scored_records.append({
                "postmortem": pm,
                "composite_score": round(composite_score, 3),
                "sim_score": round(sim_score, 3),
                "topo_score": round(topo_score, 3),
                "decay_score": round(decay_score, 3),
                "recommended_hypothesis": f"Investigate {pm.root_cause_service} for {pm.mechanism}",
            })

        scored_records.sort(key=lambda x: x["composite_score"], reverse=True)
        return scored_records[:top_k]
