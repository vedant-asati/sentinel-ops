from datetime import datetime
import json
import math
import re
import httpx
from typing import Any, Dict, List, Literal, Optional, Tuple
from sentinel_ops.core.config import settings
from sentinel_ops.security.sanitizer import wrap_telemetry

ALLOWED_SERVICES = ("checkout-service", "cart-service", "pricing-service", "payment-service")

METRIC_QUERY_TEMPLATES = {
    "error_rate": 'payment_error_rate{{service="{service}"}}',
    "latency_p95": 'histogram_quantile(0.95, sum by (le) (rate(http_request_duration_seconds_bucket{{service="{service}"}}[1m])))',
    "db_pool_active": 'payment_db_pool_active{{service="{service}"}}',
    "db_pool_size": 'payment_db_pool_size{{service="{service}"}}',
    "db_pool_acquire_timeouts_total": 'payment_db_pool_acquire_timeouts_total{{service="{service}"}}',
    "upstream_connect_timeouts_total": 'upstream_connect_timeouts_total{{service="{service}"}}',
    "cpu_saturation": 'container_cpu_usage_seconds_total{{container="{service}"}}',
    "memory_usage": 'container_memory_usage_ratio{{container="{service}"}}',
    "container_restarts": 'container_restart_count{{container="{service}"}}',
}


class PrometheusAdapter:
    """Server-enforced Prometheus adapter with persistent HTTP client and time-anchored bounded queries."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        timeout: Optional[float] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        self.base_url = base_url or settings.PROMETHEUS_URL
        self.timeout = timeout or settings.PER_QUERY_TIMEOUT_SECONDS
        self.headers: Dict[str, str] = headers if headers is not None else self._load_default_headers()
        self.verify: Any = settings.TELEMETRY_CA_BUNDLE or settings.TELEMETRY_TLS_VERIFY
        self.client: httpx.AsyncClient = httpx.AsyncClient(
            timeout=self.timeout,
            headers=self.headers,
            verify=self.verify,
        )

    @staticmethod
    def _load_default_headers() -> Dict[str, str]:
        if settings.PROMETHEUS_HEADERS_JSON:
            try:
                parsed = json.loads(settings.PROMETHEUS_HEADERS_JSON)
                if isinstance(parsed, dict):
                    return {str(k): str(v) for k, v in parsed.items()}
            except Exception:
                pass
        return {}

    async def aclose(self) -> None:
        if self.client and not self.client.is_closed:
            await self.client.aclose()

    def _get_client(self) -> httpx.AsyncClient:
        if self.client is None or self.client.is_closed:
            self.client = httpx.AsyncClient(
                timeout=self.timeout,
                headers=self.headers,
                verify=self.verify,
            )
        return self.client

    async def query_metric(
        self,
        service: str,
        metric_type: str,
        window: Tuple[str, str],  # (start_iso, end_iso) anchored to T_incident
        step: str = "15s",
        max_series: int = 5,
        timeout_override: Optional[float] = None,
        allowed_services: Optional[Tuple[str, ...]] = None,
        promql_templates: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Queries Prometheus metrics over an anchored time window."""
        eff_services = allowed_services if allowed_services is not None else ALLOWED_SERVICES
        eff_templates = promql_templates if promql_templates is not None else METRIC_QUERY_TEMPLATES
        if service not in eff_services:
            return {
                "status": "TOOL_FAILURE",
                "error": f"Service '{service}' is not in allowed services list: {eff_services}",
                "result": [],
                "formatted": ""
            }

        if metric_type not in eff_templates:
            return {
                "status": "TOOL_FAILURE",
                "error": f"Unknown metric type '{metric_type}'. Allowed: {list(eff_templates.keys())}",
                "result": [],
                "formatted": ""
            }

        # Enforce window schema validation safely
        if not window or not isinstance(window, (tuple, list)) or len(window) != 2:
            return {
                "status": "TOOL_FAILURE",
                "promql": "",
                "error": "Invalid window: must be a 2-tuple or 2-element list of (start_iso, end_iso)",
                "result": [],
                "formatted": ""
            }

        start_iso, end_iso = window
        try:
            s_dt = datetime.fromisoformat(str(start_iso).replace("Z", "+00:00"))
            e_dt = datetime.fromisoformat(str(end_iso).replace("Z", "+00:00"))
            if s_dt > e_dt:
                return {
                    "status": "TOOL_FAILURE",
                    "promql": "",
                    "error": f"Invalid inverted window: start '{start_iso}' exceeds end '{end_iso}'",
                    "result": [],
                    "formatted": "",
                }
        except ValueError:
            pass
        # Sanitize step parameter against query string injection
        safe_step = re.sub(r"[^0-9a-zA-Z]", "", step) if step else "15s"
        promql = eff_templates[metric_type].format(service=service)
        effective_timeout = max(0.001, timeout_override) if timeout_override is not None else self.timeout
        client = self._get_client()

        import time as _time
        q_start = _time.perf_counter()
        try:
            resp = await client.get(
                f"{self.base_url}/api/v1/query_range",
                params={"query": promql, "start": start_iso, "end": end_iso, "step": safe_step},
                timeout=effective_timeout,
            )
            if resp.status_code == 200:
                try:
                    resp_json = resp.json()
                    resp_data = resp_json.get("data") or {}
                    if not resp_data.get("result"):
                        elapsed = _time.perf_counter() - q_start
                        rem_timeout = effective_timeout - elapsed
                        # Time-anchored fallback only within the remaining query budget (never doubles timeout)
                        if rem_timeout >= 0.25 and not metric_type.endswith("_total"):
                            resp = await client.get(
                                f"{self.base_url}/api/v1/query",
                                params={"query": promql, "time": end_iso},
                                timeout=rem_timeout,
                            )
                except (json.JSONDecodeError, ValueError):
                    pass

            resp.raise_for_status()
            try:
                resp_json = resp.json()
                data = (resp_json.get("data") or {}).get("result", [])
            except (json.JSONDecodeError, ValueError) as err:
                return {
                    "status": "TOOL_FAILURE",
                    "promql": promql,
                    "error": f"Failed to parse Prometheus JSON response: {err}",
                    "result": [],
                    "formatted": "",
                }

            # Cap series count to prevent context exhaustion while disclosing truncation
            total_series_count = len(data)
            capped_data = data[:max_series]
            retained_series_count = len(capped_data)
            truncated = total_series_count > retained_series_count
            coverage_status = "PARTIAL" if truncated else ("COMPLETE" if capped_data else "EMPTY")
            status = "SUCCESS" if capped_data else "EMPTY"

            formatted = wrap_telemetry(
                name=f"prom_{service}_{metric_type}",
                raw_content=str(capped_data)
            )
            return {
                "status": status,
                "promql": promql,
                "result": capped_data,
                "series_count": retained_series_count,
                "retained_series_count": retained_series_count,
                "total_series_count": total_series_count,
                "truncated": truncated,
                "coverage_status": coverage_status,
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
