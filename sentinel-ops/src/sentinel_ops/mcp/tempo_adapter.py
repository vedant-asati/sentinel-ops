import json
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
        """Retrieves and summarizes trace span hierarchy, isolating the bottleneck span via exclusive self-time."""
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
                try:
                    data = resp.json()
                except (json.JSONDecodeError, ValueError) as err:
                    return {
                        "status": "TOOL_FAILURE",
                        "trace_id": trace_id,
                        "error": f"Failed to decode Tempo JSON response: {err}",
                        "spans": [],
                        "bottleneck_service": None,
                        "formatted": "",
                    }

                # Extract batches/spans
                spans_summary = []
                batches = data.get("batches", [])
                for b in batches:
                    svc = b.get("resource", {}).get("attributes", [{}])[0].get("value", {}).get("stringValue", "unknown")
                    scope_spans = b.get("scopeSpans", [])
                    for ss in scope_spans:
                        for s in ss.get("spans", []):
                            span_id = s.get("spanId", "")
                            parent_span_id = s.get("parentSpanId", "")
                            span_name = s.get("name", "span")
                            start_nano = int(s.get("startTimeUnixNano", 0))
                            end_nano = int(s.get("endTimeUnixNano", 0))
                            duration_ms = (end_nano - start_nano) / 1_000_000 if end_nano > start_nano else 0.0

                            span_info = {
                                "span_id": span_id,
                                "parent_span_id": parent_span_id,
                                "service": svc,
                                "name": span_name,
                                "duration_ms": round(duration_ms, 2),
                            }
                            spans_summary.append(span_info)

                # Attribute bottleneck using exclusive self-time: duration - sum(children_durations)
                children_durations = {}
                for span in spans_summary:
                    p_id = span.get("parent_span_id")
                    if p_id:
                        children_durations[p_id] = children_durations.get(p_id, 0.0) + span["duration_ms"]

                max_exclusive = -1.0
                bottleneck_span = None
                for span in spans_summary:
                    s_id = span.get("span_id")
                    child_time = children_durations.get(s_id, 0.0)
                    exclusive_ms = max(0.0, span["duration_ms"] - child_time)
                    span["exclusive_duration_ms"] = round(exclusive_ms, 2)
                    if exclusive_ms > max_exclusive:
                        max_exclusive = exclusive_ms
                        bottleneck_span = span

                capped_spans = spans_summary[:max_spans]
                status = "SUCCESS" if capped_spans else "EMPTY"

                raw_repr = (
                    f"Trace: {trace_id}\n"
                    f"Bottleneck Service: {bottleneck_span['service'] if bottleneck_span else 'None'} ({max_exclusive:.2f}ms exclusive)\n"
                    f"Spans: {capped_spans}"
                )

                formatted = wrap_telemetry(f"tempo_trace_{trace_id}", raw_repr)
                return {
                    "status": status,
                    "trace_id": trace_id,
                    "spans": capped_spans,
                    "bottleneck_service": bottleneck_span["service"] if bottleneck_span else None,
                    "bottleneck_duration_ms": max_exclusive,
                    "formatted": formatted,
                }
            except httpx.HTTPError as e:
                return {
                    "status": "TOOL_FAILURE",
                    "trace_id": trace_id,
                    "error": str(e),
                    "spans": [],
                    "bottleneck_service": None,
                    "formatted": "",
                }
