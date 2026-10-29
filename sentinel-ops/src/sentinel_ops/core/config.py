import os
from pathlib import Path
import re
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Model configuration (gemini-3.5-flash-lite has 500 RPD / 15 RPM / 250K TPM per key on free tier)
    GEMINI_API_KEY: str = ""
    GEMINI_API_KEY_2: str = ""
    GEMINI_API_KEY_3: str = ""
    GEMINI_API_KEY_4: str = ""
    GEMINI_API_KEY_5: str = ""
    GEMINI_API_KEY_6: str = ""
    GEMINI_API_KEY_7: str = ""
    GEMINI_API_KEY_8: str = ""
    GEMINI_API_KEY_9: str = ""
    GEMINI_API_KEY_10: str = ""
    GEMINI_API_KEYS: str = ""
    GEMINI_MODEL_SUPERVISOR: str = "gemini-3.5-flash-lite"
    GEMINI_MODEL_SYNTHESIZER: str = "gemini-3.5-flash-lite"
    
    # Telemetry backend endpoints (Server-side enforced only)
    PROMETHEUS_URL: str = "http://localhost:59090"
    TEMPO_URL: str = "http://localhost:53201"
    PROMETHEUS_HEADERS_JSON: str = ""
    TEMPO_HEADERS_JSON: str = ""
    TELEMETRY_TLS_VERIFY: bool = True
    TELEMETRY_CA_BUNDLE: str = ""

    # Persistence & operational controls
    RUN_STORE_PATH: str = ""
    DEFAULT_PROFILE_ID: str = "checkout-demo"
    SENTINEL_ENV_SCOPE: str = ""
    SENTINEL_REDACT_RAW_PAYLOADS: bool = False
    EXPERIMENTAL_RULES_ENABLED: bool = False
    
    # Deadlines and timeouts (seconds)
    RUN_DEADLINE_SECONDS: float = 30.0
    PER_QUERY_TIMEOUT_SECONDS: float = 3.0
    PER_LLM_TIMEOUT_SECONDS: float = 15.0  # Google GenAI requires >= 10s
    
    # Tolerances
    MAX_CRAG_ITERATIONS: int = 2
    MAX_ADVERSARIAL_ITERATIONS: int = 2

    model_config = SettingsConfigDict(
        # Check both local .env and workspace root .env
        env_file=[
            Path(".env"),
            Path("../.env"),
            Path(__file__).resolve().parents[3] / ".env",
            Path(__file__).resolve().parents[4] / ".env",
        ],
        env_file_encoding="utf-8",
        extra="ignore"
    )

    def resolve_gemini_api_keys(self, include_env: bool = True) -> List[str]:
        """Returns deduplicated Gemini API keys from primary, numbered (_2.._N), and CSV env vars."""
        candidates: List[str] = []

        def _add(raw: str) -> None:
            for item in str(raw or "").split(","):
                val = item.strip()
                if val and val not in candidates:
                    candidates.append(val)

        env_primary = os.environ.get("GEMINI_API_KEY", "") if include_env else ""
        _add(env_primary or self.GEMINI_API_KEY)

        numbered_indices = list(range(2, 11))
        if include_env:
            for k in os.environ:
                m = re.fullmatch(r"GEMINI_API_KEY_(\d+)", k)
                if m and int(m.group(1)) not in numbered_indices and int(m.group(1)) >= 2:
                    numbered_indices.append(int(m.group(1)))
            numbered_indices.sort()

        for idx in numbered_indices:
            field_name = f"GEMINI_API_KEY_{idx}"
            env_val = os.environ.get(field_name, "") if include_env else ""
            attr_val = getattr(self, field_name, "")
            _add(env_val or attr_val)

        env_csv = os.environ.get("GEMINI_API_KEYS", "") if include_env else ""
        _add(env_csv or self.GEMINI_API_KEYS)
        return candidates


settings = Settings()
