from typing import Any, Dict


class DeterministicRuleBaseline:
    """Heuristic rule engine baseline that evaluates telemetry with static thresholds."""

    def diagnose(self, case: Dict[str, Any]) -> Dict[str, Any]:
        telemetry = case.get("mock_telemetry", {})
        prom = telemetry.get("prometheus", {})
        tempo = telemetry.get("tempo", {})

        # Rule 1: Payment DB pool saturation check
        payment_prom = prom.get("payment-service", {})
        db_pool = payment_prom.get("db_pool_active", {})
        if db_pool.get("status") == "SUCCESS":
            values = db_pool.get("values", [])
            if values and float(values[-1][1]) >= 2.0:
                return {
                    "baseline": "deterministic_rules",
                    "diagnosed_root_cause": "payment-service",
                    "mechanism": "db_pool_exhaustion",
                    "terminal_status": "SUPPORTED_DIAGNOSIS",
                    "confidence": 0.90,
                }

        # Rule 2: Pricing latency spike check
        pricing_prom = prom.get("pricing-service", {})
        pricing_lat = pricing_prom.get("latency_p95", {})
        if pricing_lat.get("status") == "SUCCESS":
            values = pricing_lat.get("values", [])
            if values and float(values[-1][1]) > 1.0:
                return {
                    "baseline": "deterministic_rules",
                    "diagnosed_root_cause": "pricing-service",
                    "mechanism": "cpu_algorithmic_latency",
                    "terminal_status": "SUPPORTED_DIAGNOSIS",
                    "confidence": 0.85,
                }

        # Rule 3: Cart memory exhaustion check
        cart_prom = prom.get("cart-service", {})
        mem_usage = cart_prom.get("memory_usage", {})
        if mem_usage.get("status") == "SUCCESS":
            values = mem_usage.get("values", [])
            if values and float(values[-1][1]) >= 0.90:
                return {
                    "baseline": "deterministic_rules",
                    "diagnosed_root_cause": "cart-service",
                    "mechanism": "memory_leak_oomkill",
                    "terminal_status": "SUPPORTED_DIAGNOSIS",
                    "confidence": 0.95,
                }

        # Rule 4: Payment connection refusal check
        pay_err = payment_prom.get("error_rate", {})
        if pay_err.get("status") == "SUCCESS":
            values = pay_err.get("values", [])
            if values and float(values[-1][1]) >= 0.90:
                return {
                    "baseline": "deterministic_rules",
                    "diagnosed_root_cause": "payment-service",
                    "mechanism": "config_drift_connection_refused",
                    "terminal_status": "SUPPORTED_DIAGNOSIS",
                    "confidence": 0.90,
                }

        # Rule 5: Check trace bottleneck
        for trace_id, trace_data in tempo.items():
            if trace_data.get("status") == "SUCCESS":
                bottleneck = trace_data.get("bottleneck_service")
                if bottleneck:
                    return {
                        "baseline": "deterministic_rules",
                        "diagnosed_root_cause": bottleneck,
                        "mechanism": "latency_bottleneck",
                        "terminal_status": "SUPPORTED_DIAGNOSIS",
                        "confidence": 0.70,
                    }

        # Missing or inconclusive telemetry
        return {
            "baseline": "deterministic_rules",
            "diagnosed_root_cause": "unknown",
            "mechanism": "inconclusive",
            "terminal_status": "INSUFFICIENT_EVIDENCE",
            "confidence": 0.0,
        }
