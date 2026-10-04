import re
from typing import Any, Mapping

_SECRET_DENYLIST = re.compile(
    r"(authorization|password|passwd|secret|token|api[-_]?key|credential|private[-_]?key|session[-_]?id)",
    re.IGNORECASE,
)
_BEARER_PATTERN = re.compile(r"(?i)bearer\s+[a-zA-Z0-9._\-]{8,}")
_JWT_PATTERN = re.compile(r"eyJ[a-zA-Z0-9_-]{5,}\.eyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]+")
_GENERIC_KEY_PATTERN = re.compile(r"(?i)(api[_-]?key|secret|password)\s*[:=]\s*['\"]?[a-zA-Z0-9._\-]{8,}['\"]?")


def scrub_credentials(text: str) -> str:
    """Redacts Bearer tokens, JWTs, and potential passwords from raw telemetry text."""
    text = _BEARER_PATTERN.sub("Bearer [REDACTED_TOKEN]", text)
    text = _JWT_PATTERN.sub("[REDACTED_JWT]", text)
    text = _GENERIC_KEY_PATTERN.sub(r"\1: [REDACTED]", text)
    return text


def scrub_attributes(attrs: Mapping[str, Any], max_len: int = 500) -> dict[str, str]:
    """Drops/redacts secret-looking dictionary attributes and stringifies the rest."""
    out: dict[str, str] = {}
    for key, value in attrs.items():
        if _SECRET_DENYLIST.search(key):
            out[key] = "[REDACTED]"
            continue
        cleaned = scrub_credentials(str(value))
        if len(cleaned) > max_len:
            cleaned = cleaned[:max_len] + "...[truncated]"
        out[key] = cleaned
    return out
