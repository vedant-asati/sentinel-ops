import re
from typing import Any, Mapping

_SECRET_DENYLIST = re.compile(
    r"(authorization|password|passwd|secret|token|api[-_]?key|credential|private[-_]?key|session[-_]?id|database_url|conn_str|cookie|x[-_]?auth)",
    re.IGNORECASE,
)

# Auth headers and tokens
_BEARER_PATTERN = re.compile(r"(?i)\bbearer\s+[a-zA-Z0-9._\-\+~/=%$]{4,}")
_BASIC_PATTERN = re.compile(r"(?i)\bbasic\s+[a-zA-Z0-9+/=]{8,}")
_TOKEN_HEADER_PATTERN = re.compile(r"(?i)\btoken\s+[a-zA-Z0-9._\-]{8,}")
_OAUTH_HEADER_PATTERN = re.compile(r"(?i)\boauth\s+[a-zA-Z0-9._\-]{8,}")
_JWT_PATTERN = re.compile(r"eyJ[a-zA-Z0-9_-]{5,}\.eyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]+")

# Cloud & high-value credentials
_AWS_KEY_PATTERN = re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b")
_GH_PAT_PATTERN = re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b")
_SLACK_TOKEN_PATTERN = re.compile(r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*\b")
_PRIVATE_KEY_PATTERN = re.compile(r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9_-]+ )?PRIVATE KEY-----")
_DB_URI_PATTERN = re.compile(r"(?i)\b([a-z0-9+]+://[^:\s]+):([^@\s]+)@([^\s/:]+)")

# Generic password and key assignments
_GENERIC_KEY_PATTERN = re.compile(r"(?i)(api[_-]?key|secret|password|passwd)\s*[:=]\s*['\"]?[^\s'\"]{4,}['\"]?")

# PII Patterns
_SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CC_PATTERN = re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b")
_EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE_PATTERN = re.compile(r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")


def scrub_credentials(text: str) -> str:
    """Redacts Bearer tokens, JWTs, cloud keys, database URIs, PII, and credentials from telemetry text."""
    text = _PRIVATE_KEY_PATTERN.sub("[REDACTED_PRIVATE_KEY]", text)
    text = _BEARER_PATTERN.sub("Bearer [REDACTED_TOKEN]", text)
    text = _BASIC_PATTERN.sub("Basic [REDACTED_BASIC_AUTH]", text)
    text = _TOKEN_HEADER_PATTERN.sub("Token [REDACTED_TOKEN]", text)
    text = _OAUTH_HEADER_PATTERN.sub("OAuth [REDACTED_TOKEN]", text)
    text = _JWT_PATTERN.sub("[REDACTED_JWT]", text)
    text = _AWS_KEY_PATTERN.sub("[REDACTED_AWS_KEY]", text)
    text = _GH_PAT_PATTERN.sub("[REDACTED_GITHUB_TOKEN]", text)
    text = _SLACK_TOKEN_PATTERN.sub("[REDACTED_SLACK_TOKEN]", text)
    text = _DB_URI_PATTERN.sub(r"\1:[REDACTED_PASSWORD]@\3", text)
    text = _GENERIC_KEY_PATTERN.sub(r"\1: [REDACTED]", text)
    
    # Redact PII
    text = _SSN_PATTERN.sub("[REDACTED_SSN]", text)
    text = _CC_PATTERN.sub("[REDACTED_CREDIT_CARD]", text)
    text = _EMAIL_PATTERN.sub("[REDACTED_EMAIL]", text)
    text = _PHONE_PATTERN.sub("[REDACTED_PHONE]", text)
    return text


def scrub_attributes(attrs: Mapping[str, Any], max_len: int = 500) -> dict[str, Any]:
    """Recursively drops/redacts secret-looking dictionary attributes and stringifies the rest."""
    out: dict[str, Any] = {}
    for key, value in attrs.items():
        if _SECRET_DENYLIST.search(str(key)):
            out[key] = "[REDACTED]"
            continue
        if isinstance(value, dict):
            out[key] = scrub_attributes(value, max_len=max_len)
        else:
            cleaned = scrub_credentials(str(value))
            if len(cleaned) > max_len:
                cleaned = cleaned[:max_len] + "...[truncated]"
            out[key] = cleaned
    return out
