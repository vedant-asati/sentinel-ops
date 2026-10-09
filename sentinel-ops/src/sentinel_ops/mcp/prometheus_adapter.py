import json
import httpx
from typing import Any, Dict, List, Literal, Optional, Tuple
from sentinel_ops.core.config import settings
from sentinel_ops.security.sanitizer import wrap_telemetry

ALLOWED_SERVICES = ("checkout-service", "cart-service", "pricing-service", "payment-service")

METRIC_QUERY_TEMPLATES = {
    "error_rate": 'payment_error_rate{{service="{service}"}}',
    "latency_p95": 'http_request_duration_seconds_bucket{{service="{service}",le="0.95"}}',
    "db_pool_active": 'payment_db_pool_active{{service="{service}"}}',
    "db_pool_size": 'payment_db_pool_size{{service="{service}"}}',
    "cpu_saturation": 'container_cpu_usage_seconds_total{{container="{service}"}}',
    "memory_usage": 'container_memory_usage_ratio{{container="{service}"}}',
    "container_restarts": 'container_restart_count{{container="{service}"}}',
}


class PrometheusAdapter:
    """Server-enforced Prometheus adapter with time-anchored bounded queries."""

    def __init__(self, base_url: Optional[str] = None, timeout: Optional[float] = None):
        self.base_url = base_url or settings.PROMETHEUS_URL
        self.timeout = timeout or settings.PER_QUERY_TIMEOUT_SECONDS

    async def query_metric(
        self,
        service: str,
        metric_type: Literal["error_rate", "latency_p95", "db_pool_active", "db_pool_size", "cpu_saturation"],
        window: Tuple[str, str],  # (start_iso, end_iso) anchored to T_incident
        step: str = "15s",
        max_series: int = 5
    ) -> Dict[str, Any]:
        """Queries Prometheus metrics over an anchored time window."""
        if service not in ALLOWED_SERVICES:
            return {
                "status": "TOOL_FAILURE",
                "error": f"Service '{service}' is not in allowed services list: {ALLOWED_SERVICES}",
                "result": [],
                "formatted": ""
            }

        if metric_type not in METRIC_QUERY_TEMPLATES:
            return {
                "status": "TOOL_FAILURE",
                "error": f"Unknown metric type '{metric_type}'. Allowed: {list(METRIC_QUERY_TEMPLATES.keys())}",
                "result": [],
                "formatted": ""
            }

        promql = METRIC_QUERY_TEMPLATES[metric_type].format(service=service)
        start_iso, end_iso = window

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                resp = await client.get(
                    f"{self.base_url}/api/v1/query_range",
                    params={"query": promql, "start": start_iso, "end": end_iso, "step": step},
                )
                if resp.status_code == 200:
                    try:
                        resp_json = resp.json()
                        if not resp_json.get("data", {}).get("result"):
                            # Fallback to instant query if range was too narrow or zero samples in window
                            resp = await client.get(
                                f"{self.base_url}/api/v1/query",
                                params={"query": promql},
                            )
                    except (json.JSONDecodeError, ValueError):
                        pass

                resp.raise_for_status()
                try:
                    data = resp.json().get("data", {}).get("result", [])
                except (json.JSONDecodeError, ValueError) as err:
                    return {
                        "status": "TOOL_FAILURE",
                        "promql": promql,
                        "error": f"Failed to parse Prometheus JSON response: {err}",
                        "result": [],
                        "formatted": "",
                    }
                
                # Cap series count to prevent context exhaustion
                capped_data = data[:max_series]
                status = "SUCCESS" if capped_data else "EMPTY"
                
                formatted = wrap_telemetry(
                    name=f"prom_{service}_{metric_type}",
                    raw_content=str(capped_data)
                )
                return {
                    "status": status,
                    "promql": promql,
                    "result": capped_data,
                    "series_count": len(capped_data),
                    "formatted": formatted
                }
            except (httpx.HTTPError, json.JSONDecodeError, ValueError, Exception) as e:
                return {
                    "status": "TOOL_FAILURE",
                    "promql": promql,
                    "error": str(e),
                    "result": [],
                    "formatted": ""
                }
