# Sentinel-Ops Package Reference

Python package workspace for **Sentinel-Ops**. See the root [README.md](../README.md) and [ARCHITECTURE.md](../ARCHITECTURE.md) for architecture and evaluation details.

## Development & CLI usage

```bash
uv sync --extra dev

# Run tests (242 tests)
uv run --extra dev pytest -q

# Counterfactual harness & 5-case replay suite
uv run --extra dev python -m benchmarks.challenge_gate --seed 42
uv run python -m benchmarks.runner

# Replay CLI scenarios (add --use-llm to enable Gemini query planning)
uv run python -m sentinel_ops.cli --case-id case_01
uv run python -m sentinel_ops.cli --case-id case_03 --export-brief ../tmp/brief.md
uv run python -m sentinel_ops.cli --case-id case_01 --export-dpo ../tmp/dpo.jsonl

# Validate YAML topology and signal mappings
uv run python -m sentinel_ops.cli --profile checkout-demo --preflight
uv run python -m sentinel_ops.cli --profile document-pipeline --preflight

# Start API server & SSE UI
uv run uvicorn sentinel_ops.server.app:app --port 8000
```

## Live sandbox commands

```bash
cd deploy && docker compose up -d && cd ..
uv run python -m sentinel_ops.chaos inject payment-service db_pool_exhaustion
uv run python -m sentinel_ops.chaos status
uv run python -m sentinel_ops.cli --live --target-service checkout-service
uv run python -m sentinel_ops.chaos recover
```

## Package layout

| Directory | Contents |
|---|---|
| `sentinel_ops/agents/` | LangGraph `StateGraph`, `Send()` fan-out, reducers, sufficiency gate, claim verifier, blast radius |
| `sentinel_ops/rules/` | Profile-agnostic rule predicates and trace localization helpers |
| `sentinel_ops/telemetry/` | Normalization, strict replica joins, counter/ratio validation, interval-union span attribution |
| `sentinel_ops/memory/` | Postmortem similarity and service-graph retrieval (`TopologyGraphRAG`) |
| `sentinel_ops/profiles/` | YAML `SystemProfile` schema validation and registry |
| `sentinel_ops/mcp/` | Dual-transport JSON-RPC 2.0 MCP server (`stdio` + `POST /mcp`), Prometheus/Tempo HTTP adapters |
| `sentinel_ops/server/`, `service/` | FastAPI run lifecycle endpoints, resumable SSE streams, idempotency checks, env scoping |
| `sentinel_ops/storage/` | `SQLiteRunRepository` (`WAL` + `busy_timeout=5000`) and run recovery |
| `sentinel_ops/security/` | Prompt-injection `<telemetry>` wrapping and secret/PII scrubbing |
| `sentinel_ops/dpo/` | Opt-in JSONL trajectory export for DPO |
