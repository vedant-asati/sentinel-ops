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
    root_cause_service = "checkout-service"
    action = "restart"

    for claim in state.structured_claims:
        if claim.claim_type == "root_cause":
            stmt = claim.statement.lower()
            if "payment-service" in stmt:
                root_cause_service = "payment-service"
            elif "pricing-service" in stmt:
                root_cause_service = "pricing-service"
            elif "cart-service" in stmt:
                root_cause_service = "cart-service"

            # Derive action from mechanism
            if "database connection pool" in stmt or "db_pool" in stmt:
                action = "db_pool_resize"
            elif "config" in stmt or "drift" in stmt:
                action = "config_reload"
            elif "connection failure" in stmt or "refusal" in stmt:
                action = "restart"
            elif "memory" in stmt or "oom" in stmt or "cpu" in stmt:
                action = "restart"
            break

    res = calculate_reverse_blast_radius(root_cause_service, action=action)
    proposal = f"Apply targeted mitigation on '{root_cause_service}' ({action}): {res['summary']}"
    return {
        "affected_callers": res["affected_callers"],
        "blast_radius_score": res["blast_radius_score"],
        "remediation_proposal": proposal,
    }
