# Sentinel-Ops: Evidence-Grounded Incident Investigation & Observability Gym

[![CI/CD](https://github.com/vedant-asati/sentinel-ops/actions/workflows/ci.yml/badge.svg)](https://github.com/vedant-asati/sentinel-ops/actions/workflows/ci.yml)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![LangGraph](https://img.shields.io/badge/Orchestration-LangGraph-orange.svg)](https://github.com/langchain-ai/langgraph)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Challenge Gate: 84/84](https://img.shields.io/badge/Challenge_Gate-84%2F84_Passing-brightgreen.svg)](#-benchmark-replay-matrix)

> **Sentinel-Ops** is a neuro-symbolic Site Reliability Engineering (SRE) **Read-Only Incident Brief & Observability Contract Platform** built on **LangGraph**, **profile-driven FastMCP 2024-11-05 tool schemas**, a **Docker Compose microservices & OTLP/Prometheus chaos sandbox**, **Topology-Aware GraphRAG**, **CRAG sufficiency gating**, **Independent Claim & Span Verification**, and optional bounded **`gemini-3.5-flash-lite` planning**.

---

## 🏛️ 3-Tier Architecture

```
                  ┌──────────────────────────────────────────────┐
                  │          Incoming Incident Alert             │
                  │  (e.g., checkout-service latency > 4.5s)     │
                  └──────────────────────┬───────────────────────┘
                                         │
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │       Topology-Aware GraphRAG Engine         │
                  │ (Cosine Sim + Shortest Path + Recency Decay) │
                  └──────────────────────┬───────────────────────┘
                                         │
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │   Supervisor & Bounded Planner (--use-llm)   │
                  │  (Symbolic Default / Gemini 3.5 Flash Lite)  │
                  └──────────────────────┬───────────────────────┘
                                         │
                    ┌────────────────────┴────────────────────┐
                    │ Parallel Dynamic Fan-Out: Send() API    │
                    ▼                                         ▼
     ┌─────────────────────────────┐           ┌─────────────────────────────┐
     │  Metrics Specialist Node    │           │   Trace Specialist Node     │
     │  (Anchored PromQL Adapter)  │           │   (Tempo Interval-Union)    │
     └──────────────┬──────────────┘           └──────────────┬──────────────┘
                    │                                         │
                    └────────────────────┬────────────────────┘
                                         │ Commutative Immutable Merge
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │          CRAG Sufficiency Evaluator          │
                  │  Is evidence sufficient to confirm a cause?  │
                  └──────────────┬───────────────────────────────┘
                                 │
                   ┌─────────────┴─────────────┐
        Sufficient │                           │ Inconclusive / Collector Down
                   ▼                           ▼
     ┌───────────────────────────┐   ┌──────────────────────────────────────┐
     │   RCA Synthesizer & Brief │   │ TERMINAL: INSUFFICIENT_EVIDENCE      │
     │  Enforces Atomic Claims & │   │        or OPERATIONAL_FAILURE        │
     │     Citation Contract     │   │  (Outputs Next Discriminating Check) │
     └─────────────┬─────────────┘   └──────────────────────────────────────┘
                   │
                   ▼
     ┌───────────────────────────┐
     │ Cold-Slate Formal Skeptic │
     │ (Zero Prior Bias Verifier)│
     └─────────────┬─────────────┘
                   │ Entailment Verified
                   ▼
     ┌───────────────────────────┐
     │ Mechanism-Driven Advisory │
     │   Blast Radius & Export   │
     │ (Read-Only Incident Brief)│
     └───────────────────────────┘
```

---

## 🚀 Key Technical Innovations

1. **Topology-Aware GraphRAG:** Evaluates historical postmortems by balancing semantic similarity ($w_1 = 0.5$), microservice graph shortest-path topological distance ($w_2 = 0.3$), and exponential recency decay ($w_3 = 0.2, \tau = 90\text{ days}$):
   $$\text{CompositeScore}(P) = w_1 \cdot \text{CosineSim}(E_{\text{alert}}, E_P) + w_2 \cdot \frac{1}{1 + \text{GraphDistance}(S_{\text{alert}}, S_P)} + w_3 \cdot e^{-\frac{\Delta t}{\tau}}$$

2. **Corrective RAG (CRAG) Sufficiency Gating:** Prevents hallucinated leaps by evaluating evidence quality before synthesis. When telemetry is withheld or inconclusive, it strictly terminates as `INSUFFICIENT_EVIDENCE` and forbids ungrounded remediation.

3. **Fresh-Context Adversarial Prosecutor:** Eliminates confirmation bias by subjecting draft claims to an isolated skeptic reviewer initialized with zero prior reasoning context. Claims must cite successful observations (`status == "SUCCESS"`). Citations to empty or failed queries are deterministically rejected.

4. **Indirect Prompt-Injection Firewall:** Fences all untrusted telemetry inside `<telemetry>` non-executable blocks, strips null bytes, defangs escape tags, and scrubs Bearer tokens, JWTs, and passwords.

5. **Opt-In DPO Trajectory Export (Deferred):** Offline `--export-dpo` writes pairwise $(y_w, y_l)$ trajectories cleanly on explicit opt-in without affecting runtime triage.

6. **Reverse Upstream Blast Radius Traversal:** When proposing action on dependency $D$, impact affects upstream callers. Causal impact is calculated using upstream ancestors `nx.ancestors(graph, target_service)` rather than naive descendants.

---

## 📊 Benchmark Replay & Counterfactual Challenge Matrix

Sentinel-Ops is evaluated in **Pilot Scope** (causal certification enabled for verified timeout-family mechanisms with explicit claim scopes, strict replica joins, partial-coverage disclosure, and safe localization + abstention elsewhere) across **84 seeded blind counterfactual cases** (`benchmarks.challenge_gate`) plus a **5-case replay suite**:

| Case ID | Incident Ground Truth | Pilot Behavior |
| :--- | :--- | :--- |
| **`case_01`** | `payment-service` (DB pool exhaustion) | **`payment-service` (`SUPPORTED_DIAGNOSIS`, scope=`service_fleet`)** |
| **`case_02`** | `pricing-service` (CPU latency spike) | **Localizes `pricing-service` + safe abstention (`INSUFFICIENT_EVIDENCE`, pilot scope)** |
| **`case_03`** | `unknown` (Telemetry signal withheld) | **Abstains cleanly (`INSUFFICIENT_EVIDENCE`)** |
| **`case_04`** | `cart-service` (Memory pressure / restarts) | **Abstains cleanly without leak/OOM overclaim (`INSUFFICIENT_EVIDENCE`)** |
| **`case_05`** | `payment-service` (Error rate / downstream span) | **Localizes `payment-service` + safe abstention without config-drift guess (`INSUFFICIENT_EVIDENCE`)** |

**Verified Benchmark & Gate Metrics:**
- **Counterfactual Challenge Gate:** **84/84 passed** across timeout positives, multi-span localization, 6-pod truncation disclosure, cross-pod service-label collapse, raw & in-range cumulative CPU counter rejection, conflicting retries, and stale/outage controls.
- **Empirical Replay Latency & Probe Budget:** Measured ~**0.04s–0.15s per offline replay case** with tracked per-run `ProbeAttempt` counts (`--live-llm` compares optional LLM planning under identical probe budgets).

---

## 🛠️ Quickstart Guide

### Prerequisites
- Python 3.12+
- `uv` package manager (`curl -LsSf https://astral.sh/uv/install.sh | sh`)
- Docker & Docker Compose (for the live microservices sandbox)

### 0. One-Command Live Showcase (All-in-One)
```bash
./demo.sh
```
Injects a live chaos fault into the containerized microservices sandbox, drives `/checkout` traffic emitting OTLP trace spans & Prometheus wait/histogram metrics, runs Sentinel-Ops triage on the captured trace ID, prints latency analytics, and cleanly recovers sandbox services.

### 1. Run Complete Automated Test Suite (141 Tests)
```bash
cd sentinel-ops
uv run --extra dev pytest -v
```

### 2. Run Comparative Benchmark & Opt-In Live LLM Comparison
```bash
cd sentinel-ops
uv run python -m benchmarks.runner
# Compare real single-pass Gemini vs Neuro-Symbolic planner (requires GEMINI_API_KEY):
uv run python -m benchmarks.runner --live-llm
```

### 3. Export Read-Only Incident Brief & Invoke Neuro-Symbolic LLM Mode
```bash
cd sentinel-ops
# Export a grounded Read-Only Incident Brief to Markdown (or JSON):
uv run python -m sentinel_ops.cli --case-id case_01 --export-brief ../tmp/incident_briefs/case_01.md
uv run python -m sentinel_ops.cli --case-id case_03 --export-brief ../tmp/incident_briefs/case_03.md

# Enable bounded Gemini 3.5 Flash Lite query planning on live telemetry:
uv run python -m sentinel_ops.cli --live --target-service checkout-service --use-llm
```

CI also runs a seeded incident decision gate. Reproduce a run locally with
`uv run --extra dev python -m benchmarks.challenge_gate --seed 20261124` from
`sentinel-ops/`. [Challenge protocol and private holdout instructions](sentinel-ops/benchmarks/README.md)

### 3. Interactive Terminal CLI Triage
```bash
cd sentinel-ops
# Live Telemetry Investigation against Docker Sandbox
uv run python -m sentinel_ops.cli --live --target-service checkout-service

# Triage Case 01 (Payment DB Connection Exhaustion)
uv run python -m sentinel_ops.cli --case-id case_01

# Triage Case 02 (Pricing Algorithmic Latency)
uv run python -m sentinel_ops.cli --case-id case_02

# Triage Case 03 (Abstention on Withheld Telemetry)
uv run python -m sentinel_ops.cli --case-id case_03

# Triage Case 04 (Cart Memory Leak & OOM Killer)
uv run python -m sentinel_ops.cli --case-id case_04

# Triage Case 05 (Gateway Configuration Drift)
uv run python -m sentinel_ops.cli --case-id case_05
```

### 4. Cyber Command Center Web Dashboard
```bash
cd sentinel-ops
uv run uvicorn sentinel_ops.server.app:app --port 8000
```
Open [http://localhost:8000](http://localhost:8000) to view live Server-Sent Events (SSE) reasoning timelines and trigger human-in-the-loop approvals.

### 5. Live Chaos Injection in Docker Sandbox
```bash
cd sentinel-ops/deploy
docker compose up -d

# Inject payment database connection exhaustion
uv run python -m sentinel_ops.chaos inject payment-service db_pool_exhaustion

# Inspect live Prometheus scraping
uv run python -m sentinel_ops.chaos status

# Recover sandbox to healthy baseline
uv run python -m sentinel_ops.chaos recover
```

---

## 📚 Technical Documentation & Deep-Dives

- [High-Level Design Specification (HLD)](docs/HLD.md)
- [Detailed Low-Level Design Specification (LLD)](docs/LLD.md)
- [Portfolio & Technical Deep-Dive Guide](docs/PORTFOLIO_GUIDE.md)
- [SDE & AI Engineering STAR Interview Guide](docs/RESUME_STAR_GUIDE.md)
