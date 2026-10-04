from typing import Optional
from langchain_core.language_models import BaseChatModel
from langchain_google_genai import ChatGoogleGenerativeAI
from sentinel_ops.core.config import settings


def get_chat_model(
    role: str = "supervisor",
    model_name: Optional[str] = None,
    temperature: float = 0.0,
    timeout: Optional[float] = None
) -> BaseChatModel:
    """Builds a configured ChatGoogleGenerativeAI instance.
    
    Roles:
      - 'supervisor'  -> gemini-2.5-flash (fast parallel decomposition & tool dispatch)
      - 'synthesizer' -> gemini-2.5-pro (deep inductive reasoning & grounded synthesis)
      - 'adversarial' -> gemini-2.5-pro (skeptic prosecutor review)
    """
    if not settings.GEMINI_API_KEY:
        raise ValueError(
            "GEMINI_API_KEY is not configured. Please set GEMINI_API_KEY in your .env file."
        )

    resolved_model = model_name
    if not resolved_model:
        if role in ("synthesizer", "adversarial"):
            resolved_model = settings.GEMINI_MODEL_SYNTHESIZER
        else:
            resolved_model = settings.GEMINI_MODEL_SUPERVISOR

    resolved_timeout = timeout or settings.PER_LLM_TIMEOUT_SECONDS

    return ChatGoogleGenerativeAI(
        model=resolved_model,
        google_api_key=settings.GEMINI_API_KEY,
        temperature=temperature,
        timeout=resolved_timeout,
        max_retries=2,
    )
