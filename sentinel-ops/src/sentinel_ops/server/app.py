import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import json
import logging
import re
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional
import yaml

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field

from sentinel_ops.agents.graph import compile_investigation_graph
from sentinel_ops.agents.synthesizer import format_incident_brief
from sentinel_ops.core.config import settings
from sentinel_ops.mcp.server import handle_jsonrpc_request
from sentinel_ops.memory.graph_rag import TopologyGraphRAG
from sentinel_ops.dpo.trajectory_logger import DPOTrajectoryLogger
from sentinel_ops.service.runner import InvestigationService
from sentinel_ops.storage.repository import (
    ApprovalRecord,
    MemoryRunRepository,
    SQLiteRunRepository,
)

logger = logging.getLogger(__name__)

_SERVICE_INSTANCE: Optional[InvestigationService] = None


def get_investigation_service() -> InvestigationService:
    """Lazy-safe singleton accessor supporting both lifespan-managed servers and bare TestClient(app)."""
    global _SERVICE_INSTANCE
    if _SERVICE_INSTANCE is None:
        if settings.RUN_STORE_PATH:
            repo = SQLiteRunRepository(settings.RUN_STORE_PATH)
        else:
            repo = MemoryRunRepository(maxsize=500)
        _SERVICE_INSTANCE = InvestigationService(repository=repo)
    return _SERVICE_INSTANCE


def reset_investigation_service(service: Optional[InvestigationService] = None) -> None:
    global _SERVICE_INSTANCE
    _SERVICE_INSTANCE = service


@asynccontextmanager
async def lifespan(_app: FastAPI):
    svc = get_investigation_service()
    try:
        yield
    finally:
        await svc.aclose()


app = FastAPI(title="Sentinel-Ops Cyber Command Center", version="3.0.0", lifespan=lifespan)

FIXTURES_DIR = Path(__file__).resolve().parents[3] / "benchmarks" / "fixtures"

# Bounded in-memory approval ledger to prevent OOM
class BoundedLedger(dict):
    def __init__(self, maxsize: int = 1000, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.maxsize = maxsize

    def __setitem__(self, key, value):
        if len(self) >= self.maxsize and key not in self:
            oldest_key = next(iter(self))
            del self[oldest_key]
        super().__setitem__(key, value)

APPROVAL_LEDGER: BoundedLedger = BoundedLedger(maxsize=1000)
RUN_HISTORY_LEDGER: BoundedLedger = BoundedLedger(maxsize=500)


def load_fixture(case_id: str) -> Optional[Dict[str, Any]]:
    """Loads a replay fixture strictly by exact YAML 'id' or exact filename stem."""
    if not case_id or not isinstance(case_id, str):
        return None
    for file in sorted(FIXTURES_DIR.glob("*.yaml")):
        try:
            with open(file, "r", encoding="utf-8") as fp:
                data = yaml.safe_load(fp)
                if not isinstance(data, dict):
                    continue
                if data.get("id") == case_id or file.stem == case_id:
                    return data
        except Exception:
            continue
    return None


@app.get("/api/incidents")
async def list_incidents():
    """Lists available incident cases."""
    cases = []
    for file in sorted(FIXTURES_DIR.glob("*.yaml")):
        try:
            with open(file, "r", encoding="utf-8") as fp:
                data = yaml.safe_load(fp)
                if not isinstance(data, dict) or "id" not in data:
                    continue
                cases.append({
                    "id": data["id"],
                    "title": data.get("title", data["id"]),
                    "target_service": data.get("target_service", "checkout-service"),
                    "timestamp": data.get("incident_timestamp"),
                })
        except Exception as e:
            logger.warning("Skipping malformed incident fixture %s: %s", file, e)
            continue
    return {"incidents": cases}


def _resolve_case_intake(
    case_id: Optional[str],
    target_service: str = "checkout-service",
    trace_id: Optional[str] = None,
    profile_id: str = "checkout-demo",
    alert_text: Optional[str] = None,
    incident_timestamp: Optional[str] = None,
) -> Dict[str, Any]:
    if case_id == "__live__" or case_id is None:
        now_iso = incident_timestamp or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        return {
            "id": f"live_{datetime.now(timezone.utc).strftime('%H%M%S')}",
            "alert_text": alert_text or f"Live Sandbox Triage: {target_service} latency & downstream error inspection.",
            "incident_timestamp": now_iso,
            "target_service": target_service,
            "profile_id": profile_id,
            "trace_id": trace_id,
            "mock_telemetry": None,
        }
    fixture = load_fixture(case_id)
    if not fixture:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
    return fixture


class RunCreateRequest(BaseModel):
    case_id: Optional[str] = None
    target_service: str = "checkout-service"
    alert_text: Optional[str] = None
    incident_timestamp: Optional[str] = None
    trace_id: Optional[str] = None
    profile_id: str = "checkout-demo"
    environment: str = "default"
    window_before_minutes: int = Field(default=2, ge=1, le=60)
    window_after_minutes: int = Field(default=3, ge=1, le=60)
    use_llm: bool = False


@app.post("/api/runs", status_code=202)
async def create_run(
    req: RunCreateRequest,
    x_sentinel_env: Optional[str] = Header(default=None),
):
    """Creates and launches an independent incident investigation returning its immutable run_id."""
    svc = get_investigation_service()
    eff_env = x_sentinel_env or req.environment
    fixture = _resolve_case_intake(
        case_id=req.case_id,
        target_service=req.target_service,
        trace_id=req.trace_id,
        profile_id=req.profile_id,
        alert_text=req.alert_text,
        incident_timestamp=req.incident_timestamp,
    )
    try:
        run_id = await svc.start_run(
            case_id=req.case_id,
            incident_id=fixture["id"],
            alert_text=req.alert_text or fixture["alert_text"],
            incident_timestamp=req.incident_timestamp or fixture["incident_timestamp"],
            target_service=req.target_service if req.case_id in (None, "__live__") else fixture["target_service"],
            profile_id=fixture.get("profile_id", req.profile_id),
            environment=eff_env,
            trace_id=req.trace_id or fixture.get("trace_id"),
            use_llm=req.use_llm,
            window_before_minutes=req.window_before_minutes,
            window_after_minutes=req.window_after_minutes,
            simulated_telemetry=fixture.get("mock_telemetry"),
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {"run_id": run_id, "status": "PENDING"}


@app.get("/api/runs/{run_id}")
async def get_run_status(
    run_id: str,
    x_sentinel_env: Optional[str] = Header(default=None),
):
    """Returns run metadata and status without exposing raw logs across environments."""
    svc = get_investigation_service()
    rec = svc.repo.get_run(run_id)
    if rec is None:
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")
    if settings.SENTINEL_ENV_SCOPE and (x_sentinel_env or rec.environment) != settings.SENTINEL_ENV_SCOPE:
        raise HTTPException(status_code=403, detail="Forbidden for this environment scope")
    return {
        "run_id": rec.run_id,
        "case_id": rec.case_id,
        "environment": rec.environment,
        "profile_id": rec.profile_id,
        "profile_version": rec.profile_version,
        "schema_version": rec.schema_version,
        "status": rec.status,
        "created_at": rec.created_at,
        "completed_at": rec.completed_at,
    }


@app.post("/api/runs/{run_id}/cancel")
async def cancel_run_endpoint(run_id: str):
    """Cancels an active run cleanly and commits one terminal outcome."""
    svc = get_investigation_service()
    rec = await svc.cancel_run(run_id)
    if rec is None:
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")
    return {"run_id": rec.run_id, "status": rec.status}


@app.get("/api/runs/{run_id}/events")
async def stream_run_events(
    run_id: str,
    last_event_id: Optional[int] = None,
    last_event_id_header: Optional[int] = Header(default=None, alias="Last-Event-ID"),
):
    """Subscribes to sequenced SSE events for an existing run, supporting Last-Event-ID reconnection."""
    svc = get_investigation_service()
    rec = svc.repo.get_run(run_id)
    if rec is None:
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")
    cursor = last_event_id if last_event_id is not None else (last_event_id_header or 0)

    async def sse_gen():
        async for ev in svc.subscribe_events(run_id, last_event_id=cursor):
            yield f"id: {ev['seq']}\ndata: {json.dumps(ev['data'])}\n\n"

    return StreamingResponse(sse_gen(), media_type="text/event-stream")


@app.get("/api/triage/{case_id}/stream")
async def stream_triage(
    case_id: str,
    target_service: str = "checkout-service",
    trace_id: Optional[str] = None,
    use_llm: bool = False,
):
    """Backward-compatible SSE endpoint creating a decoupled InvestigationService run and streaming events."""
    fixture = _resolve_case_intake(case_id=case_id, target_service=target_service, trace_id=trace_id)
    svc = get_investigation_service()

    async def event_generator():
        try:
            run_id = await svc.start_run(
                case_id=case_id,
                incident_id=fixture["id"],
                alert_text=fixture["alert_text"],
                incident_timestamp=fixture["incident_timestamp"],
                target_service=fixture["target_service"],
                profile_id=fixture.get("profile_id", "checkout-demo"),
                trace_id=trace_id or fixture.get("trace_id"),
                use_llm=use_llm,
                simulated_telemetry=fixture.get("mock_telemetry"),
            )
            async for ev in svc.subscribe_events(run_id, last_event_id=0):
                if ev["data"].get("type") == "terminal":
                    rec = svc.repo.get_run(run_id)
                    if rec and rec.final_state:
                        RUN_HISTORY_LEDGER[run_id] = dict(rec.final_state)
                yield f"id: {ev['seq']}\ndata: {json.dumps(ev['data'])}\n\n"
        except Exception as err:
            logger.error("SSE stream error during triage for %s: %s", case_id, err)
            yield f"data: {json.dumps({'type': 'error', 'error': str(err)})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/api/runs/{run_id}/brief")
async def export_stored_run_brief(
    run_id: str,
    fmt: Literal["markdown", "json"] = "markdown",
    x_sentinel_env: Optional[str] = Header(default=None),
):
    """Exports Markdown or JSON brief directly from RunRepository or RUN_HISTORY_LEDGER without re-running."""
    svc = get_investigation_service()
    rec = svc.repo.get_run(run_id)
    if rec is not None:
        if settings.SENTINEL_ENV_SCOPE and (x_sentinel_env or rec.environment) != settings.SENTINEL_ENV_SCOPE:
            raise HTTPException(status_code=403, detail="Forbidden for this environment scope")
        if fmt == "json" and rec.brief_json:
            return PlainTextResponse(content=rec.brief_json, media_type="application/json")
        if fmt == "markdown" and rec.brief_markdown:
            return PlainTextResponse(content=rec.brief_markdown, media_type="text/markdown")
        if rec.final_state:
            rendered = format_incident_brief(rec.final_state, fmt=fmt)
            media = "application/json" if fmt == "json" else "text/markdown"
            return PlainTextResponse(content=rendered, media_type=media)

    stored_state = RUN_HISTORY_LEDGER.get(run_id)
    if not stored_state:
        raise HTTPException(status_code=404, detail=f"Completed run '{run_id}' not found")
    rendered = format_incident_brief(stored_state, fmt=fmt)
    media = "application/json" if fmt == "json" else "text/markdown"
    return PlainTextResponse(content=rendered, media_type=media)


@app.get("/api/brief/{case_id}")
async def get_incident_brief(
    case_id: str,
    fmt: Literal["markdown", "json"] = "markdown",
    run_id: Optional[str] = None,
):
    """Generates or retrieves a Read-Only Incident Brief (exports stored state when run_id is given)."""
    if run_id is not None:
        return await export_stored_run_brief(run_id=run_id, fmt=fmt)

    if case_id == "__live__":
        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        fixture = {
            "id": f"live_{datetime.now(timezone.utc).strftime('%H%M%S')}",
            "alert_text": "Live Sandbox Triage: checkout-service telemetry check.",
            "incident_timestamp": now_iso,
            "target_service": "checkout-service",
            "trace_id": None,
            "mock_telemetry": None,
        }
    else:
        fixture = load_fixture(case_id)
        if not fixture:
            raise HTTPException(status_code=404, detail=f"Case {case_id} not found")

    graph = compile_investigation_graph()
    final_state = await graph.ainvoke(
        {
            "incident_id": fixture["id"],
            "alert_text": fixture["alert_text"],
            "incident_timestamp": fixture["incident_timestamp"],
            "target_service": fixture["target_service"],
            "trace_id": fixture.get("trace_id"),
            "simulated_telemetry": fixture.get("mock_telemetry"),
            "deadline_timestamp": time.monotonic() + settings.RUN_DEADLINE_SECONDS,
            "crag_iterations": 0,
        },
        config={"configurable": {"thread_id": f"brief_{fixture['id']}_{uuid.uuid4().hex[:8]}"}},
    )
    rendered = format_incident_brief(final_state, fmt=fmt)
    media = "application/json" if fmt == "json" else "text/markdown"
    return PlainTextResponse(content=rendered, media_type=media)


class ApprovalRequest(BaseModel):
    decision: Literal["approved", "rejected"]
    operator_id: str = Field(
        default="operator_sre_01",
        pattern=r"^[a-zA-Z0-9_\-\.]{2,64}$",
        description="Validated operator identifier",
    )
    run_id: Optional[str] = Field(default=None, pattern=r"^[a-zA-Z0-9_\-]{1,64}$")
    proposal_id: Optional[str] = Field(default=None, pattern=r"^[a-zA-Z0-9_\-]{1,64}$")
    environment: str = Field(default="default", pattern=r"^[a-zA-Z0-9_\-]{1,32}$")


@app.post("/api/remediation/{case_id}/approve")
async def approve_remediation(case_id: str, req: ApprovalRequest):
    """Idempotently records validated operator HITL decision linked to case/run/proposal identity."""
    if not re.fullmatch(r"^[a-zA-Z0-9_\-]{1,64}$", case_id):
        raise HTTPException(status_code=422, detail="Invalid case_id format; expected alphanumeric/underscore/hyphen identifier.")
    ts_now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    record = ApprovalRecord(
        case_id=case_id,
        run_id=req.run_id,
        proposal_id=req.proposal_id,
        decision=req.decision,
        operator_id=req.operator_id,
        environment=req.environment,
        timestamp=ts_now,
    )
    get_investigation_service().repo.save_approval(record)
    APPROVAL_LEDGER[case_id] = record.model_dump()
    return {"status": "recorded", "ledger": APPROVAL_LEDGER[case_id]}


@app.post("/mcp")
async def mcp_jsonrpc_endpoint(request: Dict[str, Any]):
    """HTTP JSON-RPC 2.0 transport endpoint for Model Context Protocol (MCP)."""
    if not isinstance(request, dict) or request.get("jsonrpc") != "2.0" or "method" not in request:
        return JSONResponse(
            status_code=400,
            content={"jsonrpc": "2.0", "id": request.get("id") if isinstance(request, dict) else None, "error": {"code": -32600, "message": "Invalid JSON-RPC 2.0 request"}},
        )
    resp = await handle_jsonrpc_request(request)
    return JSONResponse(status_code=200, content=resp)


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
            <button onclick="exportBrief('markdown')" class="bg-cyan-800 hover:bg-cyan-700 text-white text-xs px-3 py-1.5 rounded transition">EXPORT BRIEF (.MD)</button>
            <button onclick="exportBrief('json')" class="bg-gray-800 hover:bg-gray-700 text-gray-200 text-xs px-3 py-1.5 rounded border border-gray-700 transition">EXPORT BRIEF (.JSON)</button>
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
        let currentRunId = null;

        function escapeHtml(str) {
            if (!str) return '';
            return String(str)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#039;');
        }

        function exportBrief(fmt) {
            const url = currentRunId
                ? `/api/runs/${encodeURIComponent(currentRunId)}/brief?fmt=${encodeURIComponent(fmt)}`
                : `/api/brief/${encodeURIComponent(currentCase)}?fmt=${encodeURIComponent(fmt)}`;
            const link = document.createElement('a');
            link.href = url;
            link.download = `${currentCase}_${currentRunId || 'latest'}_brief.${fmt === 'json' ? 'json' : 'md'}`;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }

        async function runTriage(caseId) {
            currentCase = caseId;
            currentRunId = null;
            const alertBox = document.getElementById('alertBox');
            const ragBox = document.getElementById('ragBox');
            const pipelineBox = document.getElementById('pipelineBox');
            const claimsBox = document.getElementById('claimsBox');
            const verdictBox = document.getElementById('verdictBox');
            const hitlPanel = document.getElementById('hitlPanel');

            alertBox.innerHTML = '<span class="text-cyan-400">Creating run & initiating stream...</span>';
            ragBox.innerHTML = '';
            pipelineBox.innerHTML = '';
            claimsBox.innerHTML = '';
            verdictBox.innerHTML = '';
            hitlPanel.classList.add('hidden');

            let eventSource;
            try {
                const startResp = await fetch('/api/runs', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({case_id: caseId})
                });
                if (startResp.ok) {
                    const started = await startResp.json();
                    currentRunId = started.run_id;
                    eventSource = new EventSource(`/api/runs/${encodeURIComponent(started.run_id)}/events`);
                } else {
                    eventSource = new EventSource(`/api/triage/${caseId}/stream`);
                }
            } catch (e) {
                eventSource = new EventSource(`/api/triage/${caseId}/stream`);
            }

            eventSource.onmessage = function(e) {
                const msg = JSON.parse(e.data);

                if (msg.type === 'init') {
                    if (msg.run_id) currentRunId = msg.run_id;
                    alertBox.textContent = msg.alert;
                } else if (msg.type === 'graph_rag') {
                    ragBox.innerHTML = msg.matches.map(m => 
                        `<div class="p-2 bg-black/40 border border-gray-800 rounded">
                            <div class="flex justify-between text-cyan-300 font-semibold"><span>${escapeHtml(m.id)}</span><span>Score: ${m.score.toFixed(3)}</span></div>
                            <div class="text-gray-400 mt-1">${escapeHtml(m.title)}</div>
                        </div>`
                    ).join('');
                } else if (msg.type === 'supervisor') {
                    pipelineBox.innerHTML += `<div class="p-2 bg-blue-950/40 border border-blue-900/60 rounded text-blue-300">⚡ Supervisor: Fan-out to Metrics & Trace Specialists</div>`;
                } else if (msg.type === 'evidence') {
                    pipelineBox.innerHTML += `<div class="p-2 bg-emerald-950/40 border border-emerald-900/60 rounded text-emerald-300">✔ Collected ${msg.items.length} verified telemetry observations</div>`;
                } else if (msg.type === 'claims') {
                    claimsBox.innerHTML = msg.claims.map(c => 
                        `<div class="p-2.5 bg-black/50 border border-gray-800 rounded">
                            <div class="flex justify-between text-emerald-400 font-bold"><span>${escapeHtml(c.id)} [${escapeHtml(c.type)}]</span><span class="text-yellow-400 font-normal">Cites: ${escapeHtml(c.citations.join(', '))}</span></div>
                            <div class="text-gray-300 mt-1">${escapeHtml(c.statement)}</div>
                        </div>`
                    ).join('');
                } else if (msg.type === 'adversarial') {
                    verdictBox.innerHTML += `<div class="p-3 bg-black/40 border border-cyan-800/80 rounded">
                        <div class="text-cyan-400 font-bold">Prosecutor Skeptic Verdict: ${msg.supported ? 'ACCEPTED (All Claims Grounded)' : 'REJECTED'}</div>
                        <div class="text-gray-400 text-xs mt-1">Confidence: ${(msg.confidence * 100).toFixed(0)}% · ${escapeHtml(msg.critique || 'Zero unsupported claims')}</div>
                    </div>`;
                } else if (msg.type === 'terminal') {
                    const data = msg.data;
                    if (data.run_id) currentRunId = data.run_id;
                    if (data.terminal_status === 'INSUFFICIENT_EVIDENCE') {
                        let checksHtml = '';
                        if (data.next_discriminating_checks && data.next_discriminating_checks.length > 0) {
                            checksHtml = `<div class="mt-2 text-xs font-normal text-yellow-200"><b>Next Discriminating Checks:</b><ul class="list-disc pl-4 mt-1">` +
                                data.next_discriminating_checks.map(c => `<li>${escapeHtml(c)}</li>`).join('') + `</ul></div>`;
                        }
                        verdictBox.innerHTML += `<div class="p-3 bg-yellow-950/40 border border-yellow-800 rounded text-yellow-300 font-bold">⚠ ABSTAINED: Inconclusive Telemetry. Refusing ungrounded hypothesis.${checksHtml}</div>`;
                    } else {
                        let runbookHtml = '';
                        if (data.recommended_runbook_action) {
                            runbookHtml = `<div class="mt-2 text-xs text-cyan-300 bg-cyan-950/40 p-2 rounded border border-cyan-800"><b>Recommended SRE Runbook Action:</b><br><code class="text-white">${escapeHtml(data.recommended_runbook_action)}</code></div>`;
                        }
                        verdictBox.innerHTML += `<div class="p-3 bg-emerald-950/40 border border-emerald-800 rounded">
                            <div class="text-emerald-300 font-bold">Terminal Status: ${escapeHtml(data.terminal_status)}</div>
                            <div class="text-gray-300 text-xs mt-1">Blast Radius Score: <span class="text-yellow-400">${data.score.toFixed(2)}</span> (Impacts: ${escapeHtml(data.callers.join(', '))})</div>
                            ${runbookHtml}
                        </div>`;
                        hitlPanel.classList.remove('hidden');
                        document.getElementById('remediationText').textContent = data.recommended_runbook_action || data.remediation || 'Apply targeted service mitigation.';
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

        window.onload = async function() {
            try {
                const resp = await fetch('/api/incidents');
                if (resp.ok) {
                    const data = await resp.json();
                    const sel = document.getElementById('caseSelector');
                    if (data.incidents && data.incidents.length > 0) {
                        const opts = data.incidents.map(inc =>
                            `<option value="${escapeHtml(inc.id)}">${escapeHtml(inc.id)}: ${escapeHtml(inc.title)}</option>`
                        );
                        opts.push('<option value="__live__">LIVE SANDBOX: Checkout Telemetry Probe</option>');
                        sel.innerHTML = opts.join('');
                        runTriage(data.incidents[0].id);
                        return;
                    }
                }
            } catch (e) {}
            runTriage('case_01');
        };
    </script>
</body>
</html>"""
    return HTMLResponse(content=html)
