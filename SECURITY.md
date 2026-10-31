# Security Policy

## Architectural Security Controls

Sentinel-Ops is designed as a **strictly read-only** observability triage engine with defense-in-depth safeguards:

1. **Indirect Prompt-Injection Firewall (`sentinel_ops/security/sanitizer.py`):**
   Untrusted metric labels, error strings, and span payloads are stripped of null bytes, defanged against XML/HTML role-spoofing tags (`<telemetry>`, `<system>`, `<assistant>`, `<evidence>`), length-capped, and wrapped inside delimited non-executable `<telemetry>` blocks.
2. **Credential & PII Redaction (`sentinel_ops/security/redact.py`, `agents/synthesizer.py`):**
   Bearer/Basic/OAuth tokens, JWTs, cloud/API keys (`AIza...`, `sk-...`, `AKIA...`, `ghp_...`, `xox...`), PEM private keys, database password URIs, and PII patterns are scrubbed at ingestion and recursively redacted across exported JSON and Markdown briefs.
3. **Server-Enforced Telemetry & Tool Boundaries (`sentinel_ops/mcp/`, `profiles/schema.py`):**
   Prometheus and Tempo base URLs come strictly from server configuration (`Settings`), never from LLM arguments. Service names are constrained to the active `SystemProfile` allowlist, trace IDs are regex-validated to prevent path traversal, and inverted time windows are rejected locally.
4. **Environment Scope & Fail-Closed Verifier (`server/app.py`, `agents/adversarial.py`):**
   Run queries, SSE streams, cancellations, and brief exports enforce `SENTINEL_ENV_SCOPE` isolation (`403` on mismatch or forged `X-Sentinel-Env` headers). Unrecognized or disabled fault mechanisms fail closed inside the independent verifier.
5. **Credential Hygiene:**
   Multi-key Gemini credentials rotate in memory via `GeminiKeyRing`, authenticate via `x-goog-api-key` headers (never URL query strings), and emit only masked prefixes/suffixes in logs.

## Reporting a Vulnerability

If you discover a security issue or credential exposure risk, please do **not** open a public issue with exploit details. Report privately to **vedant.dev.jsr@gmail.com** with reproduction steps and affected components.
