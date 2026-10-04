import httpx
from typing import Any, Dict, List, Literal, Optional, Tuple
from sentinel_ops.core.config import settings
from sentinel_ops.security.sanitizer import wrap_telemetry

ALLOWED_SERVICES = ("checkout-service", "cart-service", "pricing-service", "payment-service")

METRIC_QUERY_TEMPLATES = {
    "error_rate": 'sum(rate(http_requests_total{{service="{service}",status=~"5.."}}[2m])) / sum(rate(http_requests_total{{service="{service}"}}[2m]))',
    "latency_p95": 'histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket{{service="{service}"}}[2m])) by (le))',
    "db_pool_active": 'payment_db_pool_active{{service="{service}"}}',
    "db_pool_size": 'payment_db_pool_size{{service="{service}"}}',
    "cpu_saturation": 'sum(rate(container_cpu_usage_seconds_total{{container="{service}"}}[2m]))',
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
                resp.raise_for_status()
                data = resp.json().get("data", {}).get("result", [])
                
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
            except httpx.HTTPError as e:
                return {
                    "status": "TOOL_FAILURE",
                    "promql": promql,
                    "error": str(e),
                    "result": [],
                    "formatted": ""
                }
