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
        # Sanitize against path traversal attacks
        if not trace_id or ".." in trace_id or "/" in trace_id or "\\" in trace_id:
            return {
                "status": "TOOL_FAILURE",
                "trace_id": trace_id,
                "error": "Invalid trace_id: directory traversal or path characters detected",
                "spans": [],
                "bottleneck_service": None,
                "formatted": "",
            }

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                resp = await client.get(f"{self.base_url}/api/traces/{trace_id}")
                if resp.status_code == 404:
                    return {
                        "status": "EMPTY",
                        "trace_id": trace_id,
                        "spans": [],
                        "bottleneck_service": None,
                        "bottleneck_duration_ms": 0.0,
                        "formatted": wrap_telemetry(f"tempo_trace_{trace_id}", f"Trace: {trace_id}\nNo trace spans found\n"),
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

                # Extract batches/spans safely handling empty or malformed structures
                spans_summary = []
                batches = data.get("batches", [])
                for b in batches:
                    res_attrs = b.get("resource", {}).get("attributes") or []
                    svc = "unknown"
                    if res_attrs and isinstance(res_attrs, list) and isinstance(res_attrs[0], dict):
                        svc = res_attrs[0].get("value", {}).get("stringValue", "unknown")

                    scope_spans = b.get("scopeSpans", [])
                    for ss in scope_spans:
                        for s in ss.get("spans", []):
                            span_id = s.get("spanId", "")
                            parent_span_id = s.get("parentSpanId", "")
                            span_name = s.get("name", "span")
                            start_nano = int(s.get("startTimeUnixNano") or 0)
                            end_nano = int(s.get("endTimeUnixNano") or 0)
                            duration_ms = (end_nano - start_nano) / 1_000_000 if end_nano > start_nano else 0.0

                            span_info = {
                                "span_id": span_id,
                                "parent_span_id": parent_span_id,
                                "service": svc,
                                "name": span_name,
                                "duration_ms": round(duration_ms, 2),
                                "start_nano": start_nano,
                                "end_nano": end_nano,
                            }
                            spans_summary.append(span_info)

                if not spans_summary:
                    return {
                        "status": "EMPTY",
                        "trace_id": trace_id,
                        "spans": [],
                        "bottleneck_service": None,
                        "bottleneck_duration_ms": 0.0,
                        "formatted": wrap_telemetry(f"tempo_trace_{trace_id}", f"Trace: {trace_id}\nNo trace spans found\n"),
                    }

                # Attribute bottleneck using interval union self-time (prevents parallel child erasure)
                parent_intervals: Dict[str, List[tuple[int, int]]] = {}
                for span in spans_summary:
                    p_id = span.get("parent_span_id")
                    if p_id and span.get("start_nano") is not None and span.get("end_nano") is not None:
                        parent_intervals.setdefault(p_id, []).append((span["start_nano"], span["end_nano"]))

                def compute_merged_duration_ms(intervals: List[tuple[int, int]]) -> float:
                    if not intervals:
                        return 0.0
                    sorted_intervals = sorted(intervals, key=lambda x: x[0])
                    merged = []
                    curr_start, curr_end = sorted_intervals[0]
                    for s, e in sorted_intervals[1:]:
                        if s <= curr_end:
                            curr_end = max(curr_end, e)
                        else:
                            merged.append((curr_start, curr_end))
                            curr_start, curr_end = s, e
                    merged.append((curr_start, curr_end))
                    return sum(max(0, e - s) for s, e in merged) / 1_000_000.0

                max_exclusive = -1.0
                bottleneck_span = None
                for span in spans_summary:
                    s_id = span.get("span_id")
                    child_active_ms = compute_merged_duration_ms(parent_intervals.get(s_id, []))
                    exclusive_ms = max(0.0, span["duration_ms"] - child_active_ms)
                    span["exclusive_duration_ms"] = round(exclusive_ms, 2)
                    # Clean up internal nano fields
                    span.pop("start_nano", None)
                    span.pop("end_nano", None)
                    if exclusive_ms > max_exclusive:
                        max_exclusive = exclusive_ms
                        bottleneck_span = span

                capped_spans = spans_summary[:max_spans]
                status = "SUCCESS" if capped_spans else "EMPTY"

                raw_repr = (
                    f"Trace: {trace_id}\n"
                    f"Bottleneck Service: {bottleneck_span['service'] if bottleneck_span else 'None'} ({max(0.0, max_exclusive):.2f}ms exclusive)\n"
                    f"Spans: {capped_spans}"
                )

                formatted = wrap_telemetry(f"tempo_trace_{trace_id}", raw_repr)
                return {
                    "status": status,
                    "trace_id": trace_id,
                    "spans": capped_spans,
                    "bottleneck_service": bottleneck_span["service"] if bottleneck_span else None,
                    "bottleneck_duration_ms": max(0.0, max_exclusive),
                    "formatted": formatted,
                }
            except (httpx.HTTPError, json.JSONDecodeError, ValueError, Exception) as e:
                return {
                    "status": "TOOL_FAILURE",
                    "trace_id": trace_id,
                    "error": str(e),
                    "spans": [],
                    "bottleneck_service": None,
                    "formatted": "",
                }
