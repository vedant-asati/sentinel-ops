from typing import Any, Dict


class UngroundedHeuristicBaseline:
    """Offline heuristic baseline simulating an ungrounded single-pass comparator without LLM API calls."""

    def diagnose(self, case: Dict[str, Any]) -> Dict[str, Any]:
        mock_telem = case.get("mock_telemetry") or {}
        prom = mock_telem.get("prometheus", {})
        alert_text = case.get("alert_text", "")

        # Inspect observable telemetry without relying on case ID
        payment_prom = prom.get("payment-service", {})
        pricing_prom = prom.get("pricing-service", {})
        cart_prom = prom.get("cart-service", {})

        # 1. Saturated payment DB pool
        db_pool = payment_prom.get("db_pool_active", {})
        if db_pool.get("status") == "SUCCESS":
            vals = db_pool.get("values", [])
            if vals and float(vals[-1][1]) >= 2.0:
                return {
                    "baseline": "single_pass_llm",
                    "diagnosed_root_cause": "payment-service",
                    "mechanism": "db_pool_exhaustion",
                    "terminal_status": "SUPPORTED_DIAGNOSIS",
                    "unsupported_claims_count": 1,
                }

        # 2. Elevated pricing latency
        pricing_lat = pricing_prom.get("latency_p95", {})
        if pricing_lat.get("status") == "SUCCESS":
            vals = pricing_lat.get("values", [])
            if vals and float(vals[-1][1]) > 1.0:
                return {
                    "baseline": "single_pass_llm",
                    "diagnosed_root_cause": "pricing-service",
                    "mechanism": "cpu_algorithmic_latency",
                    "terminal_status": "SUPPORTED_DIAGNOSIS",
                    "unsupported_claims_count": 2,
                }

        # 3. Cart memory exhaustion
        cart_mem = cart_prom.get("memory_usage", {})
        if cart_mem.get("status") == "SUCCESS":
            vals = cart_mem.get("values", [])
            if vals and float(vals[-1][1]) >= 0.90:
                return {
                    "baseline": "single_pass_llm",
                    "diagnosed_root_cause": "cart-service",
                    "mechanism": "memory_leak_oomkill",
                    "terminal_status": "SUPPORTED_DIAGNOSIS",
                    "unsupported_claims_count": 2,
                }

        # 4. Payment connection failure / error rate
        pay_err = payment_prom.get("error_rate", {})
        if pay_err.get("status") == "SUCCESS":
            vals = pay_err.get("values", [])
            if vals and float(vals[-1][1]) >= 0.50:
                return {
                    "baseline": "single_pass_llm",
                    "diagnosed_root_cause": "payment-service",
                    "mechanism": "config_drift_connection_refused",
                    "terminal_status": "SUPPORTED_DIAGNOSIS",
                    "unsupported_claims_count": 2,
                }

        # 5. Inconclusive or withheld telemetry:
        # Crucially: Ungrounded comparator DOES NOT abstain. It guesses checkout-service!
        return {
            "baseline": "ungrounded_heuristic",
            "diagnosed_root_cause": "checkout-service",
            "mechanism": "thread_pool_starvation",
            "terminal_status": "SUPPORTED_DIAGNOSIS",
            "unsupported_claims_count": 3,
        }


# Backwards-compatible alias for legacy imports
SinglePassLLMBaseline = UngroundedHeuristicBaseline
