import networkx as nx
from sentinel_ops.agents.blast_radius import build_service_graph, calculate_reverse_blast_radius


def test_reverse_blast_radius_ancestor_traversal():
    """Verifies that dependency traversal follows UPSTREAM callers (ancestors), not descendants."""
    # checkout -> cart, pricing, payment; payment -> postgres-db
    res_postgres = calculate_reverse_blast_radius("postgres-db", "restart")
    
    # Modifying postgres-db impacts both payment-service and checkout-service!
    assert "payment-service" in res_postgres["affected_callers"]
    assert "checkout-service" in res_postgres["affected_callers"]
    assert res_postgres["blast_radius_score"] >= 0.50
    assert res_postgres["blast_radius_level"] in ("Medium", "High")

    # Modifying checkout-service (upstream root) has 0 upstream callers
    res_checkout = calculate_reverse_blast_radius("checkout-service", "config_reload")
    assert len(res_checkout["affected_callers"]) == 0
    assert res_checkout["blast_radius_level"] == "Low"
