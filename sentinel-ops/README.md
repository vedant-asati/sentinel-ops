# Sentinel-Ops Platform

> **Read-Only SRE Incident Triage & Observability Contract Platform**  
> Built with LangGraph, SystemProfile-driven telemetry normalization, CRAG sufficiency gating, independent claim/span verification, profile-aware FastMCP schemas, and optional opt-in DPO trajectory logging.

---

## 🚀 Key Architecture Highlights

- **Evidence-Backed Investigation:** Claims cite immutable typed observations (`OBS-prom-...` / `OBS-tempo-...`) backed by explicit `ProbeAttempt` provenance, `claim_scope`, and replica/series coverage disclosures (`PARTIAL` on truncated responses).
- **Strict Terminal Safety Invariants:** Explicitly distinguishes confirmed timeout mechanisms (`SUPPORTED_DIAGNOSIS`) from inconclusive/invalid measurements (`INSUFFICIENT_EVIDENCE` with localized bottleneck + discriminating check) and collector outages (`OPERATIONAL_FAILURE`).
- **Independent Claim & Span Verifier:** Verifies citations, sample timestamps, replica keys, span IDs, and timeout preconditions directly against immutable observations without re-invoking rule selection.
- **Two-Stage Preflight:** Validates signal semantics (rejecting cumulative counters mapped as utilization gauges) and optionally probes read-only live Prometheus/Tempo endpoints.
- **Single-Process Pilot Controls:** SQLite run persistence with startup orphan recovery, `(environment, idempotency_key)` deduplication (`409` on payload conflict), per-backend semaphore budgets, and environment-scoped access enforcement.

---

## 🛠️ Quickstart

### 1. Run Verification Test Suite (242 Tests)
```bash
cd sentinel-ops
uv run --extra dev pytest -v
```

### 2. Run Replay Matrix & Blind Counterfactual Gate (5 Replay Cases + 84 Challenge Cases)
```bash
uv run --extra dev python -m benchmarks.runner
uv run --extra dev python -m benchmarks.challenge_gate --seed 20261124
```

### 3. Interactive Operator CLI
Run interactive terminal triage with rich reasoning streams and Human-in-the-Loop (HITL) approval:
```bash
# Triage Case 01 (Payment DB Pool Exhaustion)
uv run python -m sentinel_ops.cli --case-id case_01

# Triage Case 02 (Pricing Algorithmic Latency)
uv run python -m sentinel_ops.cli --case-id case_02

# Triage Case 03 (Abstention on Withheld Telemetry)
uv run python -m sentinel_ops.cli --case-id case_03
```

### 4. Cyber Command Center Web Dashboard
Launch the web UI with real-time Server-Sent Events (SSE) streaming and interactive HITL modal:
```bash
uv run uvicorn sentinel_ops.server.app:app --port 8000
```
Open [http://localhost:8000](http://localhost:8000) in your browser.

### 5. Deploy Local Telemetry & Chaos Sandbox (Docker Compose)
Spins up synthetic e-commerce microservices, Prometheus (`:59090`), and Grafana Tempo (`:53201`):
```bash
cd deploy
docker compose up -d
```

---

## 📊 Evaluation Matrix

| Case ID | Incident Ground Truth | Deterministic Rules | Ungrounded Heuristic | Sentinel-Ops LangGraph Agent |
| :--- | :--- | :--- | :--- | :--- |
| **`case_01`** | `payment-service` (DB pool exhaustion) | `payment-service` [SUPP] | `payment-service` [SUPP] | **`payment-service` (SUPPORTED)** |
| **`case_02`** | `pricing-service` (CPU algorithmic latency) | `pricing-service` [SUPP] | `pricing-service` [SUPP] | **`pricing-service` (Localized · ABSTAINED in pilot)** |
| **`case_03`** | `unknown` (Telemetry signal withheld) | `unknown` [INSU] | `checkout-service` [SUPP] *(Overclaimed!)* | **`ABSTAINED` (INSUFFICIENT)** |

**Metrics:**
- **Supported Diagnosis Precision:** 100.0% (pilot-certified timeout mechanisms).
- **Safe Abstention & Localization Rate:** 100.0% on withheld/non-pilot cases.
- **Blind Counterfactual Gate:** **84 / 84 (100%)** passing with 0 false-support decisions.
- **Citation Contract & Verifier:** 100% of claims backed by verified immutable observations.
