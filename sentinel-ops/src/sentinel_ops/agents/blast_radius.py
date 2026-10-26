import networkx as nx
from typing import Any, Dict, List


def build_service_graph(profile: Any = None) -> nx.DiGraph:
    """Builds microservices dependency directed graph from a SystemProfile or default checkout graph."""
    if profile is not None and hasattr(profile, "build_service_graph"):
        return profile.build_service_graph()
    g = nx.DiGraph()
    g.add_edge("checkout-service", "cart-service")
    g.add_edge("checkout-service", "pricing-service")
    g.add_edge("checkout-service", "payment-service")
    g.add_edge("payment-service", "postgres-db")
    return g


def calculate_reverse_blast_radius(
    target_service: str,
    action: str = "restart",
    profile: Any = None,
) -> Dict[str, Any]:
    """Traverses UPSTREAM callers (ancestors) to calculate impact of modifying target_service."""
    graph = profile.build_service_graph() if profile is not None else build_service_graph()
    
    if target_service not in graph:
        return {
            "target_service": target_service,
            "affected_callers": [],
            "blast_radius_score": 1.0,
            "blast_radius_level": "Critical",
            "summary": f"Target service '{target_service}' unknown in topology graph: flagged as Critical Risk (1.00)",
        }

    action_weights = {"config_reload": 0.1, "restart": 0.5, "db_pool_resize": 0.8}
    w_action = action_weights.get(action)
    if w_action is None:
        return {
            "target_service": target_service,
            "affected_callers": [],
            "blast_radius_score": 1.0,
            "blast_radius_level": "Critical",
            "error": f"Invalid or unapproved remediation action '{action}'. Approved actions: {list(action_weights.keys())}",
            "summary": f"UNAPPROVED ACTION '{action}' on '{target_service}' blocked by safety policy (Score: 1.00, Critical Risk)",
        }
        
    affected_callers = sorted(list(nx.ancestors(graph, target_service)))
    downstream_dependencies = sorted(list(nx.descendants(graph, target_service)))
    denom = max(1, len(graph.nodes) - 1) if profile is not None else 4.0
    caller_ratio = min(1.0, len(affected_callers) / denom)
    # Public ingress services with zero upstream callers still carry downstream customer exposure on disruptive actions
    is_public_ingress = len(affected_callers) == 0 and len(downstream_dependencies) > 0 and action != "config_reload"
    ingress_exposure = min(0.5, len(downstream_dependencies) * 0.12) if is_public_ingress else 0.0
    score = min(1.0, max(0.0, (0.6 * caller_ratio) + (0.4 * w_action) + ingress_exposure))
    level = "Low" if score < 0.35 else ("Medium" if score < 0.65 else "High")
    if score >= 0.90:
        level = "Critical"
    
    return {
        "target_service": target_service,
        "affected_callers": affected_callers,
        "downstream_dependencies": downstream_dependencies,
        "blast_radius_score": round(score, 2),
        "blast_radius_level": level,
        "summary": (
            f"Modifying '{target_service}' potentially impacts {len(affected_callers)} upstream caller(s): "
            f"{affected_callers} and {len(downstream_dependencies)} downstream dependency(s): "
            f"{downstream_dependencies} (Score: {score:.2f}, {level} Risk)"
        ),
    }


MECHANISM_TO_ACTION: Dict[str, str] = {
    "pool_acquisition_timeout": "db_pool_resize",
    "db_pool_exhaustion": "db_pool_resize",
    "upstream_connect_timeout": "config_reload",
    "config_drift_connection_refused": "config_reload",
    "memory_leak_oomkill": "restart",
    "cpu_algorithmic_latency": "restart",
    "cpu_contention": "restart",
}


def blast_radius_node(state: Any) -> Dict[str, Any]:
    """Calculates upstream blast radius for the diagnosed root cause service."""
    from sentinel_ops.profiles.registry import get_profile

    profile_id = getattr(state, "profile_id", "checkout-demo")
    try:
        profile = get_profile(profile_id)
        known_services = profile.resolve_service_names()
    except Exception:
        profile = None
        known_services = ("payment-service", "pricing-service", "cart-service")

    rule_eval = getattr(state, "rule_evaluation", None) or {}
    root_cause_service = rule_eval.get("root_cause_service") or getattr(state, "target_service", "checkout-service")
    mechanism = getattr(state, "mechanism", None)
    action = MECHANISM_TO_ACTION.get(mechanism, "restart") if mechanism else "restart"

    if not rule_eval.get("root_cause_service"):
        for claim in state.structured_claims:
            if claim.claim_type == "root_cause":
                stmt = claim.statement.lower()
                for svc in known_services:
                    if svc.lower() in stmt:
                        root_cause_service = svc
                        break

                if not mechanism:
                    if "database connection pool" in stmt or "db_pool" in stmt or "pool_acquisition_timeout" in stmt:
                        action = "db_pool_resize"
                    elif "config" in stmt or "drift" in stmt or "connection failure" in stmt or "refused" in stmt or "upstream_connect_timeout" in stmt:
                        action = "config_reload"
                    elif "memory" in stmt or "oom" in stmt or "cpu" in stmt:
                        action = "restart"
                break

    res = calculate_reverse_blast_radius(root_cause_service, action=action, profile=profile)
    proposal = f"Advisory check on '{root_cause_service}' ({action}): {res['summary']}"
    return {
        "affected_callers": res["affected_callers"],
        "blast_radius_score": res["blast_radius_score"],
        "remediation_proposal": proposal,
    }
