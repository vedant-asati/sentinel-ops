"""Bounded Neuro-Symbolic LLM Query Planner & Incident Brief Narrative Generator.

Respects Gemini free-tier quota limits for gemini-3.5-flash-lite (15 RPM / 500 RPD / 250K TPM)
and fails safely back to symbolic defaults when rate-limited, timed out, or unconfigured.
"""

import asyncio
import json
import logging
import time
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field

from sentinel_ops.core.config import settings
from sentinel_ops.core.llm import get_chat_model, invoke_with_gemini_failover

logger = logging.getLogger(__name__)


class AsyncRateLimiter:
    """Per-key async interval limiter preventing 15 RPM quota exhaustion on any single key."""

    def __init__(self, min_interval_sec: float = 4.2):
        self.min_interval_sec = min_interval_sec
        self._last_call: float = 0.0
        self._last_by_key: Dict[str, float] = {}
        self._lock: Optional[asyncio.Lock] = None

    async def acquire(
        self,
        deadline_timestamp: Optional[float] = None,
        api_key: str = "__default__",
    ) -> bool:
        """Waits cleanly for rate-limit slot unless waiting would breach deadline_timestamp."""
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            now = time.monotonic()
            last_for_key = self._last_by_key.get(api_key, 0.0)
            wait = (self.min_interval_sec - (now - last_for_key)) if last_for_key > 0 else 0.0
            if deadline_timestamp is not None:
                rem_after_wait = deadline_timestamp - (now + max(0.0, wait))
                if rem_after_wait <= 1.0:
                    return False
            if wait > 0:
                await asyncio.sleep(wait)
            done = time.monotonic()
            self._last_call = done
            self._last_by_key[api_key] = done
            return True


_GEMINI_RATE_LIMITER = AsyncRateLimiter(min_interval_sec=4.2)


class PlannedMetricProbe(BaseModel):
    service: str
    metric_type: str
    rationale: str = Field(description="Why this signal discriminates competing hypotheses")


class LLMInvestigationPlan(BaseModel):
    hypotheses: List[str] = Field(max_length=5)
    probes: List[PlannedMetricProbe] = Field(max_length=6)


class SinglePassDiagnosisSchema(BaseModel):
    diagnosed_root_cause: str
    mechanism: str
    status: Literal["SUPPORTED_DIAGNOSIS", "INSUFFICIENT_EVIDENCE"]
    rationale: str


class LLMBriefNarrative(BaseModel):
    executive_summary: str = Field(description="Concise 2-sentence summary citing only verified [EV-xxx] IDs")
    prioritized_next_check: str = Field(description="Most discriminating follow-up check for the on-call operator")


async def refine_brief_with_llm(
    alert_text: str,
    target_service: str,
    verified_claims: List[Dict[str, Any]],
    evidence: List[Dict[str, Any]],
    next_checks: List[str],
    deadline_timestamp: Optional[float] = None,
) -> Optional[LLMBriefNarrative]:
    """Synthesizes an operator-friendly Incident Brief strictly constrained to verified citations."""
    if not settings.resolve_gemini_api_keys() or not verified_claims:
        return None

    remaining = (deadline_timestamp - time.monotonic()) if deadline_timestamp else settings.PER_LLM_TIMEOUT_SECONDS
    if remaining <= 1.0:
        return None

    prompt = (
        f"Summarize this verified SRE diagnosis for the on-call engineer on '{target_service}'.\n"
        f"Alert: {alert_text}\n"
        f"Verified Claims: {json.dumps(verified_claims)[:2000]}\n"
        f"Verified Evidence Items: {json.dumps([{'id': e.get('id'), 'finding': e.get('finding')} for e in evidence if e.get('status') == 'SUCCESS'])[:2500]}\n"
        f"Candidate Next Checks: {json.dumps(next_checks)}\n\n"
        "Rule: Only reference metrics, services, and [EV-xxx] IDs explicitly present above."
    )

    async def _attempt(api_key: str, timeout: float) -> Optional[LLMBriefNarrative]:
        if not await _GEMINI_RATE_LIMITER.acquire(deadline_timestamp=deadline_timestamp, api_key=api_key):
            raise TimeoutError("Rate-limit wait would exceed run deadline")
        llm = get_chat_model(role="synthesizer", timeout=timeout, api_key=api_key)
        structured = llm.with_structured_output(LLMBriefNarrative)
        return await structured.ainvoke(prompt)

    try:
        return await invoke_with_gemini_failover(
            _attempt,
            per_attempt_timeout=settings.PER_LLM_TIMEOUT_SECONDS,
            deadline_timestamp=deadline_timestamp,
        )
    except Exception as exc:
        logger.warning("LLM brief narrative refinement unavailable (%s); keeping deterministic summary.", exc)
        return None


async def plan_probes_with_llm(
    alert_text: str,
    target_service: str,
    historical_context: List[Dict[str, Any]],
    dependencies: List[str],
    deadline_timestamp: Optional[float] = None,
    allowed_services: Optional[List[str]] = None,
    allowed_signals: Optional[List[str]] = None,
) -> Optional[LLMInvestigationPlan]:
    """Uses Gemini (gemini-3.5-flash-lite) across rotated API keys to prioritize probes."""
    if not settings.resolve_gemini_api_keys():
        return None

    remaining = (deadline_timestamp - time.monotonic()) if deadline_timestamp else settings.PER_LLM_TIMEOUT_SECONDS
    if remaining <= 1.0:
        return None

    svc_list = allowed_services or list(dict.fromkeys([target_service] + list(dependencies)))
    sig_list = allowed_signals or [
        "error_rate",
        "latency_p95",
        "db_pool_active",
        "db_pool_size",
        "db_pool_acquire_timeouts_total",
        "upstream_connect_timeouts_total",
        "cpu_saturation",
        "memory_usage",
        "container_restarts",
    ]
    prompt = (
        f"You are an SRE Incident Investigation Planner.\n"
        f"Alert on '{target_service}': {alert_text}\n"
        f"Allowed services: {svc_list}\n"
        f"Allowed metric signals: {sig_list}\n"
        f"Direct dependencies: {dependencies}\n"
        f"GraphRAG historical precedents: {json.dumps(historical_context[:2])}\n\n"
        "Output at most 4 competing hypotheses and up to 6 priority metric probes using ONLY the allowed services and metric signals "
        "that best discriminate candidate failure mechanisms."
    )

    async def _attempt(api_key: str, timeout: float) -> Optional[LLMInvestigationPlan]:
        if not await _GEMINI_RATE_LIMITER.acquire(deadline_timestamp=deadline_timestamp, api_key=api_key):
            raise TimeoutError("Rate-limit wait would exceed run deadline")
        llm = get_chat_model(role="supervisor", timeout=timeout, api_key=api_key)
        structured = llm.with_structured_output(LLMInvestigationPlan)
        return await structured.ainvoke(prompt)

    try:
        result = await invoke_with_gemini_failover(
            _attempt,
            per_attempt_timeout=settings.PER_LLM_TIMEOUT_SECONDS,
            deadline_timestamp=deadline_timestamp,
        )
        if result and result.probes:
            filtered = [
                p for p in result.probes
                if p.service in svc_list and p.metric_type in sig_list
            ]
            return LLMInvestigationPlan(hypotheses=result.hypotheses, probes=filtered)
        return result
    except Exception as exc:
        logger.warning("LLM query planner unavailable (%s); using deterministic topology fallback.", exc)
        return None


async def run_live_single_pass_gemini(
    alert_text: str,
    target_service: str,
    telemetry_bundle: Dict[str, Any],
) -> Dict[str, Any]:
    """Executes an actual unconstrained single-pass Gemini prompt for honest benchmark comparison."""
    if not settings.resolve_gemini_api_keys():
        return {
            "baseline": "live_single_pass_gemini",
            "diagnosed_root_cause": "unavailable",
            "mechanism": "no_api_key",
            "terminal_status": "OPERATIONAL_FAILURE",
        }

    prompt = (
        f"Alert on {target_service}: {alert_text}\n"
        f"Telemetry snapshot: {json.dumps(telemetry_bundle)[:6000]}\n\n"
        "Diagnose the most likely root cause service and mechanism, or abstain as INSUFFICIENT_EVIDENCE if signals are missing."
    )

    async def _attempt(api_key: str, timeout: float) -> SinglePassDiagnosisSchema:
        await _GEMINI_RATE_LIMITER.acquire(api_key=api_key)
        llm = get_chat_model(role="supervisor", timeout=timeout, api_key=api_key)
        structured = llm.with_structured_output(SinglePassDiagnosisSchema)
        return await structured.ainvoke(prompt)

    try:
        res: SinglePassDiagnosisSchema = await invoke_with_gemini_failover(
            _attempt,
            per_attempt_timeout=settings.PER_LLM_TIMEOUT_SECONDS,
        )
        return {
            "baseline": "live_single_pass_gemini",
            "diagnosed_root_cause": res.diagnosed_root_cause,
            "mechanism": res.mechanism,
            "terminal_status": res.status,
            "rationale": res.rationale,
        }
    except Exception as exc:
        logger.warning("Live single-pass Gemini evaluation failed: %s", exc)
        return {
            "baseline": "live_single_pass_gemini",
            "diagnosed_root_cause": "error",
            "mechanism": str(exc),
            "terminal_status": "OPERATIONAL_FAILURE",
        }
