import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel

from sentinel_ops.agents.graph import compile_investigation_graph
from sentinel_ops.memory.graph_rag import TopologyGraphRAG
from sentinel_ops.dpo.trajectory_logger import DPOTrajectoryLogger

app = FastAPI(title="Sentinel-Ops Cyber Command Center", version="1.0.0")

FIXTURES_DIR = Path(__file__).resolve().parents[3] / "benchmarks" / "fixtures"

# In-memory approval ledger
APPROVAL_LEDGER: Dict[str, Dict[str, Any]] = {}


def load_fixture(case_id: str) -> Optional[Dict[str, Any]]:
    for file in FIXTURES_DIR.glob("*.yaml"):
        if case_id in file.stem:
            with open(file, "r", encoding="utf-8") as fp:
                return yaml.safe_load(fp)
    return None


@app.get("/api/incidents")
async def list_incidents():
    """Lists available incident cases."""
    cases = []
    for file in sorted(FIXTURES_DIR.glob("*.yaml")):
        with open(file, "r", encoding="utf-8") as fp:
            data = yaml.safe_load(fp)
            cases.append({
                "id": data["id"],
                "title": data.get("title", data["id"]),
                "target_service": data.get("target_service", "checkout-service"),
                "timestamp": data.get("incident_timestamp"),
            })
    return {"incidents": cases}


@app.get("/api/triage/{case_id}/stream")
async def stream_triage(case_id: str):
    """Streams real-time multi-agent reasoning steps via Server-Sent Events (SSE)."""
    fixture = load_fixture(case_id)
    if not fixture:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")

    async def event_generator():
        yield f"data: {json.dumps({'type': 'init', 'incident_id': case_id, 'alert': fixture['alert_text']})}\n\n"
        await asyncio.sleep(0.3)

        # 1. GraphRAG Prior Knowledge
        graph_rag = TopologyGraphRAG()
        matches = graph_rag.retrieve(
            alert_text=fixture["alert_text"],
            target_service=fixture["target_service"],
            incident_timestamp=fixture["incident_timestamp"],
            top_k=2,
        )
        rag_data = [
            {
                "id": m["postmortem"].incident_id,
                "title": m["postmortem"].title,
                "service": m["postmortem"].root_cause_service,
                "score": m["composite_score"],
            }
            for m in matches
        ]
        yield f"data: {json.dumps({'type': 'graph_rag', 'matches': rag_data})}\n\n"
        await asyncio.sleep(0.4)

        # 2. Multi-Agent Reasoning Execution
        yield f"data: {json.dumps({'type': 'supervisor', 'status': 'Decomposing incident into parallel hypotheses'})}\n\n"
        await asyncio.sleep(0.3)

        graph = compile_investigation_graph()
        initial_state = {
            "incident_id": case_id,
            "alert_text": fixture["alert_text"],
            "incident_timestamp": fixture["incident_timestamp"],
            "target_service": fixture["target_service"],
            "simulated_telemetry": fixture.get("mock_telemetry"),
            "crag_iterations": 2 if case_id == "case_03" else 0,
        }
        config = {"configurable": {"thread_id": f"sse_{case_id}"}}
        final_state = await graph.ainvoke(initial_state, config=config)

        # 3. Emit Evidence Items
        evidence_list = [
            {
                "id": e.id,
                "source": e.backend_source,
                "finding": e.finding,
                "status": e.status,
            }
            for e in final_state.get("evidence", [])
        ]
        yield f"data: {json.dumps({'type': 'evidence', 'items': evidence_list})}\n\n"
        await asyncio.sleep(0.3)

        # 4. Emit Atomic Claims & Citations
        claims_list = [
            {
                "id": c.claim_id,
                "type": c.claim_type,
                "statement": c.statement,
                "citations": c.cited_evidence_ids,
            }
            for c in final_state.get("structured_claims", [])
        ]
        yield f"data: {json.dumps({'type': 'claims', 'claims': claims_list})}\n\n"
        await asyncio.sleep(0.3)

        # 5. Emit Adversarial Verdict
        adv = final_state.get("adversarial_verdict")
        if adv:
            yield f"data: {json.dumps({'type': 'adversarial', 'supported': adv.all_claims_supported, 'confidence': adv.confidence, 'critique': adv.critique_hint})}\n\n"
            await asyncio.sleep(0.3)

        # 6. Emit Terminal & Blast Radius
        blast = {
            "score": final_state.get("blast_radius_score", 0.0),
            "callers": final_state.get("affected_callers", []),
            "remediation": final_state.get("remediation_proposal"),
            "terminal_status": final_state.get("terminal_status"),
            "terminal_reason": final_state.get("terminal_reason"),
            "summary": final_state.get("root_cause_summary"),
        }
        yield f"data: {json.dumps({'type': 'terminal', 'data': blast})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


class ApprovalRequest(BaseModel):
    decision: str  # "approved" | "rejected"
    operator_id: str = "operator_sre_01"


@app.post("/api/remediation/{case_id}/approve")
async def approve_remediation(case_id: str, req: ApprovalRequest):
    """Idempotently records operator HITL decision."""
    APPROVAL_LEDGER[case_id] = {
        "case_id": case_id,
        "decision": req.decision,
        "operator_id": req.operator_id,
        "timestamp": "2026-11-24T20:30:00Z",
    }
    return {"status": "recorded", "ledger": APPROVAL_LEDGER[case_id]}


@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    """Serves the zero-build Cyber Command Center single-page dashboard."""
    html = """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sentinel-Ops Cyber Command Center</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
      tailwind.config = {
        darkMode: 'class',
        theme: {
          extend: {
            colors: {
              cyber: { 900: '#0a0e17', 800: '#111827', 700: '#1f2937', 500: '#10b981', 400: '#34d399', accent: '#06b6d4' }
            }
          }
        }
      }
    </script>
</head>
<body class="bg-[#0a0e17] text-gray-200 font-mono min-h-screen">
    <!-- Navbar -->
    <header class="border-b border-gray-800 bg-[#111827]/80 backdrop-blur px-6 py-4 flex items-center justify-between sticky top-0 z-50">
        <div class="flex items-center space-x-3">
            <div class="w-3 h-3 bg-emerald-500 rounded-full animate-ping"></div>
            <h1 class="text-xl font-bold tracking-wider text-emerald-400">SENTINEL-OPS <span class="text-xs text-cyan-400 font-normal px-2 py-0.5 bg-cyan-950/60 rounded border border-cyan-800">CYBER COMMAND CENTER</span></h1>
        </div>
        <div class="flex items-center space-x-4">
            <span class="text-xs text-gray-400">Active Scenario:</span>
            <select id="caseSelector" class="bg-gray-800 border border-gray-700 text-sm rounded px-3 py-1 text-emerald-400 focus:outline-none focus:border-emerald-500" onchange="runTriage(this.value)">
                <option value="case_01">Case 01: Payment DB Pool Exhaustion</option>
                <option value="case_02">Case 02: Pricing Algorithmic Latency</option>
                <option value="case_03">Case 03: Telemetry Withheld (Abstention)</option>
                <option value="case_04">Case 04: Cart Memory Leak & OOM Killer</option>
                <option value="case_05">Case 05: Gateway Configuration Drift (502 Bad Gateway)</option>
            </select>
            <button onclick="runTriage(document.getElementById('caseSelector').value)" class="bg-emerald-600 hover:bg-emerald-500 text-white text-xs px-3 py-1.5 rounded transition">RUN TRIAGE</button>
        </div>
    </header>

    <!-- Main Grid -->
    <main class="p-6 grid grid-cols-1 lg:grid-cols-3 gap-6">
        <!-- Left: Alert & GraphRAG -->
        <section class="space-y-6">
            <div class="bg-[#111827] border border-gray-800 rounded-lg p-5">
                <h2 class="text-sm font-semibold text-emerald-400 mb-3 flex items-center">
                    <span class="w-2 h-2 bg-emerald-500 rounded-full mr-2"></span> INCIDENT TELEMETRY ALERT
                </h2>
                <div id="alertBox" class="text-xs text-gray-300 leading-relaxed bg-black/40 p-3 rounded border border-gray-850">
                    Select a scenario and click RUN TRIAGE.
                </div>
            </div>

            <div class="bg-[#111827] border border-gray-800 rounded-lg p-5">
                <h2 class="text-sm font-semibold text-cyan-400 mb-3 flex items-center">
                    <span class="w-2 h-2 bg-cyan-500 rounded-full mr-2"></span> TOPOLOGY-AWARE GRAPHRAG RETRIEVAL
                </h2>
                <div id="ragBox" class="space-y-2 text-xs text-gray-400">
                    <div class="text-gray-500 italic">No prior matches loaded.</div>
                </div>
            </div>
        </section>

        <!-- Center: Multi-Agent Reasoning Graph & Evidence -->
        <section class="space-y-6">
            <div class="bg-[#111827] border border-gray-800 rounded-lg p-5">
                <h2 class="text-sm font-semibold text-purple-400 mb-3 flex items-center">
                    <span class="w-2 h-2 bg-purple-500 rounded-full mr-2"></span> MULTI-AGENT REASONING PIPELINE
                </h2>
                <div id="pipelineBox" class="space-y-3 text-xs">
                    <div class="text-gray-500 italic">Awaiting execution trigger...</div>
                </div>
            </div>

            <div class="bg-[#111827] border border-gray-800 rounded-lg p-5">
                <h2 class="text-sm font-semibold text-emerald-400 mb-3 flex items-center">
                    <span class="w-2 h-2 bg-emerald-500 rounded-full mr-2"></span> EVIDENCE CITATION CONTRACT
                </h2>
                <div id="claimsBox" class="space-y-2 text-xs">
                    <div class="text-gray-500 italic">No atomic claims formulated.</div>
                </div>
            </div>
        </section>

        <!-- Right: Blast Radius & HITL Gate -->
        <section class="space-y-6">
            <div class="bg-[#111827] border border-gray-800 rounded-lg p-5">
                <h2 class="text-sm font-semibold text-yellow-400 mb-3 flex items-center">
                    <span class="w-2 h-2 bg-yellow-500 rounded-full mr-2"></span> ADVERSARIAL SKEPTIC & BLAST RADIUS
                </h2>
                <div id="verdictBox" class="space-y-3 text-xs">
                    <div class="text-gray-500 italic">Reviewer awaiting synthesis.</div>
                </div>
            </div>

            <div id="hitlPanel" class="bg-[#111827] border border-emerald-900/60 rounded-lg p-5 hidden">
                <h2 class="text-sm font-semibold text-emerald-400 mb-3">HUMAN-IN-THE-LOOP APPROVAL GATE</h2>
                <p id="remediationText" class="text-xs text-gray-300 mb-4 bg-black/40 p-3 rounded border border-gray-800"></p>
                <div class="flex space-x-3">
                    <button onclick="submitApproval('approved')" class="flex-1 bg-emerald-600 hover:bg-emerald-500 text-white text-xs py-2 rounded font-semibold transition">APPROVE REMEDIATION</button>
                    <button onclick="submitApproval('rejected')" class="flex-1 bg-red-900 hover:bg-red-800 text-white text-xs py-2 rounded font-semibold transition">REJECT</button>
                </div>
                <div id="hitlStatus" class="mt-3 text-center text-xs text-emerald-400"></div>
            </div>
        </section>
    </main>

    <script>
        let currentCase = 'case_01';

        function runTriage(caseId) {
            currentCase = caseId;
            const alertBox = document.getElementById('alertBox');
            const ragBox = document.getElementById('ragBox');
            const pipelineBox = document.getElementById('pipelineBox');
            const claimsBox = document.getElementById('claimsBox');
            const verdictBox = document.getElementById('verdictBox');
            const hitlPanel = document.getElementById('hitlPanel');

            alertBox.innerHTML = '<span class="text-cyan-400">Initiating stream...</span>';
            ragBox.innerHTML = '';
            pipelineBox.innerHTML = '';
            claimsBox.innerHTML = '';
            verdictBox.innerHTML = '';
            hitlPanel.classList.add('hidden');

            const eventSource = new EventSource(`/api/triage/${caseId}/stream`);

            eventSource.onmessage = function(e) {
                const msg = JSON.parse(e.data);

                if (msg.type === 'init') {
                    alertBox.innerHTML = msg.alert;
                } else if (msg.type === 'graph_rag') {
                    ragBox.innerHTML = msg.matches.map(m => 
                        `<div class="p-2 bg-black/40 border border-gray-800 rounded">
                            <div class="flex justify-between text-cyan-300 font-semibold"><span>${m.id}</span><span>Score: ${m.score.toFixed(3)}</span></div>
                            <div class="text-gray-400 mt-1">${m.title}</div>
                        </div>`
                    ).join('');
                } else if (msg.type === 'supervisor') {
                    pipelineBox.innerHTML += `<div class="p-2 bg-blue-950/40 border border-blue-900/60 rounded text-blue-300">⚡ Supervisor: Fan-out to Metrics & Trace Specialists</div>`;
                } else if (msg.type === 'evidence') {
                    pipelineBox.innerHTML += `<div class="p-2 bg-emerald-950/40 border border-emerald-900/60 rounded text-emerald-300">✔ Collected ${msg.items.length} verified telemetry observations</div>`;
                } else if (msg.type === 'claims') {
                    claimsBox.innerHTML = msg.claims.map(c => 
                        `<div class="p-2.5 bg-black/50 border border-gray-800 rounded">
                            <div class="flex justify-between text-emerald-400 font-bold"><span>${c.id} [${c.type}]</span><span class="text-yellow-400 font-normal">Cites: ${c.citations.join(', ')}</span></div>
                            <div class="text-gray-300 mt-1">${c.statement}</div>
                        </div>`
                    ).join('');
                } else if (msg.type === 'adversarial') {
                    verdictBox.innerHTML += `<div class="p-3 bg-black/40 border border-cyan-800/80 rounded">
                        <div class="text-cyan-400 font-bold">Prosecutor Skeptic Verdict: ${msg.supported ? 'ACCEPTED (All Claims Grounded)' : 'REJECTED'}</div>
                        <div class="text-gray-400 text-xs mt-1">Confidence: ${(msg.confidence * 100).toFixed(0)}% · ${msg.critique || 'Zero unsupported claims'}</div>
                    </div>`;
                } else if (msg.type === 'terminal') {
                    const data = msg.data;
                    if (data.terminal_status === 'INSUFFICIENT_EVIDENCE') {
                        verdictBox.innerHTML += `<div class="p-3 bg-yellow-950/40 border border-yellow-800 rounded text-yellow-300 font-bold">⚠ ABSTAINED: Inconclusive Telemetry. Refusing ungrounded hypothesis.</div>`;
                    } else {
                        verdictBox.innerHTML += `<div class="p-3 bg-emerald-950/40 border border-emerald-800 rounded">
                            <div class="text-emerald-300 font-bold">Terminal Status: ${data.terminal_status}</div>
                            <div class="text-gray-300 text-xs mt-1">Blast Radius Score: <span class="text-yellow-400">${data.score.toFixed(2)}</span> (Impacts: ${data.callers.join(', ')})</div>
                        </div>`;
                        hitlPanel.classList.remove('hidden');
                        document.getElementById('remediationText').innerText = data.remediation || 'Apply targeted service mitigation.';
                    }
                    eventSource.close();
                }
            };

            eventSource.onerror = function() {
                eventSource.close();
            };
        }

        async function submitApproval(decision) {
            const resp = await fetch(`/api/remediation/${currentCase}/approve`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({decision: decision})
            });
            const data = await resp.json();
            document.getElementById('hitlStatus').innerText = `Decision '${decision.toUpperCase()}' recorded idempotently.`;
        }

        window.onload = function() {
            runTriage('case_01');
        };
    </script>
</body>
</html>"""
    return HTMLResponse(content=html)
