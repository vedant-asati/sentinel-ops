import asyncio
import logging
import threading
import time
from typing import Awaitable, Callable, Dict, List, Optional, Tuple, TypeVar
from langchain_core.language_models import BaseChatModel
from langchain_google_genai import ChatGoogleGenerativeAI
from sentinel_ops.core.config import settings

logger = logging.getLogger(__name__)
T = TypeVar("T")


def mask_api_key(api_key: str) -> str:
    """Returns a non-reversible masked representation for safe operator diagnostics."""
    if not api_key:
        return "<empty>"
    if len(api_key) <= 10:
        return api_key[:2] + "..." + api_key[-2:]
    return api_key[:6] + "..." + api_key[-4:]


class GeminiKeyRing:
    """Thread-safe round-robin pool & cooldown tracker for multiple Gemini API keys."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._rr_idx: int = 0
        self._cooldown_until: Dict[str, float] = {}

    def available_keys(self) -> List[str]:
        keys = settings.resolve_gemini_api_keys()
        if not keys:
            return []
        now = time.monotonic()
        with self._lock:
            ready = [k for k in keys if self._cooldown_until.get(k, 0.0) <= now]
            return ready or list(keys)

    def acquire_ordered_candidates(self) -> List[str]:
        """Returns configured keys rotated round-robin, placing active non-cooled keys first."""
        keys = settings.resolve_gemini_api_keys()
        if not keys:
            return []
        now = time.monotonic()
        with self._lock:
            start = self._rr_idx % len(keys)
            self._rr_idx = (self._rr_idx + 1) % len(keys)
            rotated = keys[start:] + keys[:start]
            ready = [k for k in rotated if self._cooldown_until.get(k, 0.0) <= now]
            cooled = [k for k in rotated if self._cooldown_until.get(k, 0.0) > now]
            return ready + cooled

    def next_key(self) -> str:
        candidates = self.acquire_ordered_candidates()
        if not candidates:
            raise ValueError(
                "GEMINI_API_KEY is not configured. Please set GEMINI_API_KEY (or GEMINI_API_KEY_2..N) in your .env file."
            )
        return candidates[0]

    def mark_failure(self, api_key: str, exc: Exception) -> None:
        msg = str(exc).lower()
        # Quota / rate-limit gets 60s cooldown; bad/revoked key gets 1h cooldown
        if any(tok in msg for tok in ("429", "resource_exhausted", "quota", "rate limit", "rate_limit")):
            cooldown = 60.0
        elif any(tok in msg for tok in ("api_key_invalid", "invalid api key", "401", "403", "permission_denied")):
            cooldown = 3600.0
        else:
            cooldown = 15.0
        with self._lock:
            self._cooldown_until[api_key] = time.monotonic() + cooldown
        logger.warning("Gemini key %s hit %s; cooling down %.0fs and rotating.", mask_api_key(api_key), type(exc).__name__, cooldown)

    def reset(self) -> None:
        with self._lock:
            self._rr_idx = 0
            self._cooldown_until.clear()


_KEY_RING = GeminiKeyRing()


def get_gemini_key_ring() -> GeminiKeyRing:
    return _KEY_RING


def get_chat_model(
    role: str = "supervisor",
    model_name: Optional[str] = None,
    temperature: float = 0.0,
    timeout: Optional[float] = None,
    api_key: Optional[str] = None,
) -> BaseChatModel:
    """Builds a configured ChatGoogleGenerativeAI instance using the rotated key ring."""
    resolved_key = api_key or _KEY_RING.next_key()

    resolved_model = model_name
    if not resolved_model:
        if role in ("synthesizer", "adversarial"):
            resolved_model = settings.GEMINI_MODEL_SYNTHESIZER
        else:
            resolved_model = settings.GEMINI_MODEL_SUPERVISOR

    resolved_timeout = timeout or settings.PER_LLM_TIMEOUT_SECONDS

    return ChatGoogleGenerativeAI(
        model=resolved_model,
        google_api_key=resolved_key,
        temperature=temperature,
        timeout=resolved_timeout,
        max_retries=1,
    )


async def invoke_with_gemini_failover(
    call_fn: Callable[[str, float], Awaitable[T]],
    *,
    per_attempt_timeout: Optional[float] = None,
    deadline_timestamp: Optional[float] = None,
) -> T:
    """Executes an async Gemini call, failing over across configured API keys within budget."""
    candidates = _KEY_RING.acquire_ordered_candidates()
    if not candidates:
        raise ValueError("No Gemini API keys configured.")

    last_exc: Optional[Exception] = None
    for idx, key in enumerate(candidates):
        now = time.monotonic()
        if deadline_timestamp is not None:
            rem = deadline_timestamp - now
            if rem <= 1.0:
                break
            timeout = min(per_attempt_timeout or settings.PER_LLM_TIMEOUT_SECONDS, max(1.0, rem))
        else:
            timeout = per_attempt_timeout or settings.PER_LLM_TIMEOUT_SECONDS
        try:
            return await asyncio.wait_for(call_fn(key, timeout), timeout=timeout)
        except Exception as exc:
            last_exc = exc
            _KEY_RING.mark_failure(key, exc)
            if idx + 1 >= len(candidates):
                raise
    if last_exc is not None:
        raise last_exc
    raise TimeoutError("Run deadline exhausted before Gemini API call could complete.")
