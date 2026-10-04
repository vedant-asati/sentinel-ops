import httpx
from typing import Any, Dict, List, Optional
from sentinel_ops.core.config import settings
from sentinel_ops.security.sanitizer import wrap_telemetry


class TempoAdapter:
    """Server-enforced Tempo distributed trace adapter."""

    def __init__(self, base_url: Optional[str] = None, timeout: Optional[float] = None):
        self.base_url = base_url or settings.TEMPO_URL
        self.timeout = timeout or settings.PER_QUERY_TIMEOUT_SECONDS

    async def get_trace_waterfall(
        self,
        trace_id: str,
        max_spans: int = 25
    ) -> Dict[str, Any]:
        """Retrieves and summarizes trace span hierarchy, isolating the bottleneck span."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                resp = await client.get(f"{self.base_url}/api/traces/{trace_id}")
                if resp.status_code == 404:
                    return {
                        "status": "EMPTY",
                        "trace_id": trace_id,
                        "spans": [],
                        "bottleneck_service": None,
                        "formatted": ""
                    }
                resp.raise_for_status()
                data = resp.json()
                
                # Extract batches/spans
                spans_summary = []
                longest_span = None
                max_duration = -1
                
                batches = data.get("batches", [])
                for b in batches:
                    svc = b.get("resource", {}).get("attributes", [{}])[0].get("value", {}).get("stringValue", "unknown")
                    scope_spans = b.get("scopeSpans", [])
                    for ss in scope_spans:
                        for s in ss.get("spans", []):
                            span_name = s.get("name", "span")
                            start_nano = int(s.get("startTimeUnixNano", 0))
                            end_nano = int(s.get("endTimeUnixNano", 0))
                            duration_ms = (end_nano - start_nano) / 1_000_000 if end_nano > start_nano else 0
                            
                            span_info = {
                                "service": svc,
                                "name": span_name,
                                "duration_ms": round(duration_ms, 2)
                            }
                            spans_summary.append(span_info)
                            
                            if duration_ms > max_duration:
                                max_duration = duration_ms
                                longest_span = span_info
                
                capped_spans = spans_summary[:max_spans]
                status = "SUCCESS" if capped_spans else "EMPTY"
                
                raw_repr = (
                    f"Trace: {trace_id}\n"
                    f"Bottleneck Service: {longest_span['service'] if longest_span else 'None'} ({max_duration:.2f}ms)\n"
                    f"Spans: {capped_spans}"
                )
                
                formatted = wrap_telemetry(f"tempo_trace_{trace_id}", raw_repr)
                return {
                    "status": status,
                    "trace_id": trace_id,
                    "spans": capped_spans,
                    "bottleneck_service": longest_span["service"] if longest_span else None,
                    "bottleneck_duration_ms": max_duration,
                    "formatted": formatted
                }
            except httpx.HTTPError as e:
                return {
                    "status": "TOOL_FAILURE",
                    "trace_id": trace_id,
                    "error": str(e),
                    "spans": [],
                    "bottleneck_service": None,
                    "formatted": ""
                }
