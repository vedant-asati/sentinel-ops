from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Model configuration (gemini-3.5-flash-lite has 500 RPD / 15 RPM / 250K TPM on free tier)
    GEMINI_API_KEY: str = ""
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
            Path(__file__).resolve().parents[3] / ".env"
        ],
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()
