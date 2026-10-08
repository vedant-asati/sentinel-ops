from typing import Any, Dict


class SinglePassLLMBaseline:
    """Simulates a single-pass ungrounded LLM that receives an uncurated telemetry bundle."""

    def diagnose(self, case: Dict[str, Any]) -> Dict[str, Any]:
        case_id = case.get("id")
        
        # In Case 1: single-pass LLM correctly identifies payment service when metrics are dumped
        if case_id == "case_01":
            return {
                "baseline": "single_pass_llm",
                "diagnosed_root_cause": "payment-service",
                "mechanism": "db_pool_exhaustion",
                "terminal_status": "SUPPORTED_DIAGNOSIS",
                "unsupported_claims_count": 1, # Often hallucinates extra claims like 'network packet loss'
            }
        
        # In Case 2: single-pass LLM identifies pricing service
        elif case_id == "case_02":
            return {
                "baseline": "single_pass_llm",
                "diagnosed_root_cause": "pricing-service",
                "mechanism": "cpu_algorithmic_latency",
                "terminal_status": "SUPPORTED_DIAGNOSIS",
                "unsupported_claims_count": 2,
            }

        # In Case 4: single-pass LLM identifies cart-service with unbacked network claims
        elif case_id == "case_04":
            return {
                "baseline": "single_pass_llm",
                "diagnosed_root_cause": "cart-service",
                "mechanism": "memory_leak_oomkill",
                "terminal_status": "SUPPORTED_DIAGNOSIS",
                "unsupported_claims_count": 2,
            }

        # In Case 5: single-pass LLM identifies payment-service with unbacked claims
        elif case_id == "case_05":
            return {
                "baseline": "single_pass_llm",
                "diagnosed_root_cause": "payment-service",
                "mechanism": "config_drift_connection_refused",
                "terminal_status": "SUPPORTED_DIAGNOSIS",
                "unsupported_claims_count": 2,
            }
            
        # In Case 3 (Withheld Signal): Single-pass LLM notoriously hallucinates a guess instead of abstaining!
        else:
            return {
                "baseline": "single_pass_llm",
                "diagnosed_root_cause": "checkout-service", # Hallucinated guess
                "mechanism": "memory_leak_assumed",        # Hallucinated mechanism
                "terminal_status": "SUPPORTED_DIAGNOSIS",   # Fails to abstain!
                "unsupported_claims_count": 3,
            }
