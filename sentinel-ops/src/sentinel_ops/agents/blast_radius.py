import networkx as nx
from typing import Any, Dict, List


def build_service_graph() -> nx.DiGraph:
    """Builds microservices dependency directed graph: caller -> dependency."""
    g = nx.DiGraph()
    g.add_edge("checkout-service", "cart-service")
    g.add_edge("checkout-service", "pricing-service")
    g.add_edge("checkout-service", "payment-service")
    g.add_edge("payment-service", "postgres-db")
    return g


def calculate_reverse_blast_radius(target_service: str, action: str = "restart") -> Dict[str, Any]:
    """Traverses UPSTREAM callers (ancestors) to calculate impact of modifying target_service."""
    graph = build_service_graph()
    
    if target_service in graph:
        # Ancestors of target_service are all upstream nodes that reach target_service
        affected_callers = sorted(list(nx.ancestors(graph, target_service)))
    else:
        affected_callers = []
        
    action_weights = {"config_reload": 0.1, "restart": 0.5, "db_pool_resize": 0.8}
    w_action = action_weights.get(action, 0.5)
    
    caller_ratio = len(affected_callers) / 4.0
    score = (0.6 * caller_ratio) + (0.4 * w_action)
    level = "Low" if score < 0.35 else ("Medium" if score < 0.65 else "High")
    
    return {
        "target_service": target_service,
        "affected_callers": affected_callers,
        "blast_radius_score": round(score, 2),
        "blast_radius_level": level,
        "summary": f"Modifying '{target_service}' potentially impacts {len(affected_callers)} caller(s): {affected_callers} (Score: {score:.2f}, {level} Risk)"
    }
