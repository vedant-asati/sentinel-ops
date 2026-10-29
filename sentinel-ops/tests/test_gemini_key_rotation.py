"""Tests for multi-key Gemini API key resolution, round-robin rotation, per-key rate limiting, and failover."""

from unittest.mock import MagicMock, patch
import pytest

from sentinel_ops.agents.llm_planner import AsyncRateLimiter, LLMInvestigationPlan, PlannedMetricProbe, plan_probes_with_llm
from sentinel_ops.core.config import Settings, settings
from sentinel_ops.core.llm import GeminiKeyRing, invoke_with_gemini_failover, mask_api_key


def test_resolve_gemini_api_keys_deduplicates_and_orders(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "key-one-12345678")
    monkeypatch.setenv("GEMINI_API_KEY_2", "key-two-12345678")
    monkeypatch.setenv("GEMINI_API_KEY_5", "key-five-12345678")
    monkeypatch.setenv("GEMINI_API_KEY_11", "key-eleven-12345")
    monkeypatch.setenv("GEMINI_API_KEYS", "key-two-12345678, key-csv-12345678")

    cfg = Settings(_env_file=None)
    keys = cfg.resolve_gemini_api_keys(include_env=True)
    assert keys == [
        "key-one-12345678",
        "key-two-12345678",
        "key-five-12345678",
        "key-eleven-12345",
        "key-csv-12345678",
    ]


def test_mask_api_key_redacts_secret_middle():
    masked = mask_api_key("AIzaSySuperSecretKeyValue9876")
    assert masked.startswith("AIzaSy")
    assert masked.endswith("9876")
    assert "SuperSecret" not in masked


@pytest.mark.asyncio
async def test_gemini_key_ring_round_robin_and_429_failover(monkeypatch):
    ring = GeminiKeyRing()
    ring.reset()
    fake_keys = ["k1-secret-1111", "k2-secret-2222", "k3-secret-3333"]
    monkeypatch.setattr(Settings, "resolve_gemini_api_keys", lambda self, include_env=True: list(fake_keys))

    assert ring.next_key() == "k1-secret-1111"
    assert ring.next_key() == "k2-secret-2222"
    assert ring.next_key() == "k3-secret-3333"

    ring.reset()
    attempted = []

    async def _call(api_key: str, timeout: float) -> str:
        attempted.append(api_key)
        if api_key == "k1-secret-1111":
            raise RuntimeError("429 RESOURCE_EXHAUSTED quota exceeded")
        return f"ok:{api_key}"

    with patch("sentinel_ops.core.llm._KEY_RING", ring):
        result = await invoke_with_gemini_failover(_call, per_attempt_timeout=5.0)

    assert result == "ok:k2-secret-2222"
    assert attempted == ["k1-secret-1111", "k2-secret-2222"]
    # Cooldown pushes k1 behind healthy k3 and k2
    ordered_next = ring.acquire_ordered_candidates()
    assert ordered_next[-1] == "k1-secret-1111"


@pytest.mark.asyncio
async def test_per_key_rate_limiter_does_not_block_distinct_keys():
    limiter = AsyncRateLimiter(min_interval_sec=4.2)
    assert await limiter.acquire(api_key="keyA") is True
    # Distinct key acquires immediately without waiting 4.2s
    assert await limiter.acquire(api_key="keyB") is True


@pytest.mark.asyncio
async def test_plan_probes_with_llm_fails_over_on_rate_limit(monkeypatch):
    ring = GeminiKeyRing()
    ring.reset()
    monkeypatch.setattr(Settings, "resolve_gemini_api_keys", lambda self, include_env=True: ["k1-test", "k2-test"])
    plan_obj = LLMInvestigationPlan(
        hypotheses=["Pool exhausted"],
        probes=[PlannedMetricProbe(service="payment-service", metric_type="db_pool_active", rationale="Check pool")],
    )

    used_keys = []

    def _fake_model(*, role: str, timeout: float, api_key: str):
        used_keys.append(api_key)
        mock_structured = MagicMock()

        async def _ainvoke(prompt: str):
            if api_key == "k1-test":
                raise RuntimeError("429 Too Many Requests")
            return plan_obj

        mock_structured.ainvoke = _ainvoke
        mock_llm = MagicMock()
        mock_llm.with_structured_output.return_value = mock_structured
        return mock_llm

    with (
        patch("sentinel_ops.core.llm._KEY_RING", ring),
        patch("sentinel_ops.agents.llm_planner._GEMINI_RATE_LIMITER", AsyncRateLimiter(min_interval_sec=0.0)),
        patch("sentinel_ops.agents.llm_planner.get_chat_model", side_effect=_fake_model),
    ):
        res = await plan_probes_with_llm(
            alert_text="Checkout 504",
            target_service="checkout-service",
            historical_context=[],
            dependencies=["payment-service"],
        )

    assert res is not None
    assert res.hypotheses == ["Pool exhausted"]
    assert used_keys == ["k1-test", "k2-test"]
