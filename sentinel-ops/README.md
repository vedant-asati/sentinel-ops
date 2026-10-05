# Sentinel-Ops Platform

> **Autonomous AI Site Reliability Engineering (AI SRE) & Root Cause Analysis Platform**  
> Powered by LangGraph multi-agent teams, Topology-Aware GraphRAG, CRAG sufficiency gating, fresh-context adversarial red-teaming, FastMCP telemetry integration, and DPO trajectory logging.

---

## 🚀 Key Architecture Highlights

- **Evidence-Backed Investigation:** All claims must cite deterministic telemetry observations (`EV-xxx`). Citations to failed or empty telemetry are deterministically rejected.
- **Strict Terminal Safety Invariants:** Explicitly distinguishes confirmed causes (`SUPPORTED_DIAGNOSIS`) from absent telemetry (`INSUFFICIENT_EVIDENCE`), strictly refusing ungrounded remediation proposals.
- **Fresh-Context Adversarial Red-Team Reviewer:** A skeptic prosecutor node with zero access to prior conversational reasoning evaluates draft claims against raw telemetry to prevent confirmation bias.
- **Topology-Aware GraphRAG:** Combines text semantic similarity ($\text{CosineSim}$), microservice dependency topological distance ($1 / (1 + \text{GraphDistance})$), and exponential recency decay ($e^{-\Delta t / \tau}$) to retrieve relevant incident postmortems.
- **Direct Preference Optimization (DPO) Trajectory Pipeline:** Pairs grounded, verified agent executions against baseline hallucinated runs, exporting $(y_w, y_l)$ trajectory pairs to `data/dpo/trajectories.jsonl`.
- **Server-Enforced Telemetry Bounds & Prompt-Injection Firewall:** Server-side parameterized queries anchored strictly to $T_{\text{incident}} \pm \Delta t$ with automated credential scrubbing, defanging, and length capping.
- **Reverse Upstream Blast Radius Traversal:** Navigates caller dependencies (`nx.ancestors()`) to accurately quantify transitive blast radius impact before remediation.

---

## 🛠️ Quickstart

### 1. Run Verification Test Suite (18 Automated Unit Tests)
```bash
cd sentinel-ops
uv run pytest
```

### 2. Run Comparative Replay Benchmark (3 Held-Out Cases)
Replays Payment DB connection exhaustion, Pricing CPU algorithmic latency, and Telemetry Signal Withheld (Abstention Test):
```bash
uv run python -m benchmarks.runner
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

| Case ID | Incident Ground Truth | Deterministic Baseline | Single-Pass LLM | Sentinel-Ops LangGraph Agent |
| :--- | :--- | :--- | :--- | :--- |
| **`case_01`** | `payment-service` (DB pool exhaustion) | `payment-service` [SUPP] | `payment-service` [SUPP] | **`payment-service` (SUPPORTED)** |
| **`case_02`** | `pricing-service` (CPU latency spike) | `pricing-service` [SUPP] | `pricing-service` [SUPP] | **`pricing-service` (SUPPORTED)** |
| **`case_03`** | `unknown` (Telemetry signal withheld) | `unknown` [INSU] | `checkout-service` [SUPP] *(Hallucinated!)* | **`ABSTAINED` (INSUFFICIENT)** |

**Metrics:**
- **Root-Cause Precision:** 100% across cases with present telemetry.
- **Correct Abstention Rate:** 100% on withheld signals.
- **Citation Contract Support:** 100% of claims backed by verified observations.
- **Adversarial Entailment:** Eliminates hallucinated assumptions.
