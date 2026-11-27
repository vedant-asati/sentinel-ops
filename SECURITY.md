# Security Policy

## Security Controls

Sentinel-Ops operates in read-only observability mode and applies the following controls:

1. **Telemetry Sanitization (`sentinel_ops/security/sanitizer.py`):**
   Metric labels, trace error strings, and span attributes are stripped of null bytes, escaped against role/block delimiters (`<telemetry>`, `<system>`, `<assistant>`, `<evidence>`), length-capped, and wrapped inside `<telemetry>` blocks before prompt construction.
2. **Secret and PII Redaction (`sentinel_ops/security/redact.py`, `agents/synthesizer.py`):**
   Bearer/Basic/OAuth headers, JWTs, API keys (`AIza...`, `sk-...`, `AKIA...`, `ghp_...`, `xox...`), PEM keys, database credential URIs, and common PII patterns are scrubbed at observation wrap time and recursively redacted from exported JSON and Markdown incident briefs.
3. **Server-Side Endpoint Allowlists (`sentinel_ops/mcp/`, `profiles/schema.py`):**
   Prometheus and Tempo URLs come strictly from server settings rather than model arguments. Service names are validated against the active `SystemProfile`, trace IDs are regex-checked against path traversal, and inverted time windows are rejected before queries run.
4. **Environment Isolation & Fail-Closed Verification (`server/app.py`, `agents/adversarial.py`):**
   Run lookups, SSE streams, cancellations, and brief downloads check `SENTINEL_ENV_SCOPE` (`403` on mismatch). Unrecognized or disabled fault mechanisms fail closed inside the claim verifier.
5. **API Key Handling (`core/llm.py`):**
   Gemini keys rotate in memory through `GeminiKeyRing`, pass via the `x-goog-api-key` header (not URL query strings), and log only masked prefixes/suffixes.

## Reporting a Vulnerability

If you discover a security bug or credential exposure risk, please do not open a public issue with exploit steps. Email details to **vedant.dev.jsr@gmail.com**.
