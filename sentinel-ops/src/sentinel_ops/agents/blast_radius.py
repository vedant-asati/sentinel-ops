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


def blast_radius_node(state: Any) -> Dict[str, Any]:
    """Calculates upstream blast radius for the diagnosed root cause service."""
    # Find diagnosed root cause service from claims
    root_cause_service = "checkout-service"
    for claim in state.structured_claims:
        if claim.claim_type == "root_cause":
            if "payment-service" in claim.statement:
                root_cause_service = "payment-service"
            elif "pricing-service" in claim.statement:
                root_cause_service = "pricing-service"
            elif "cart-service" in claim.statement:
                root_cause_service = "cart-service"
            break

    res = calculate_reverse_blast_radius(root_cause_service, action="db_pool_resize" if root_cause_service == "payment-service" else "restart")
    proposal = f"Apply targeted mitigation on '{root_cause_service}': {res['summary']}"
    return {
        "affected_callers": res["affected_callers"],
        "blast_radius_score": res["blast_radius_score"],
        "remediation_proposal": proposal,
    }

