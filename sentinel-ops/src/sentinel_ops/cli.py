import argparse
import asyncio
from datetime import datetime, timezone
import signal
import sys
import time
import uuid
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Confirm

from sentinel_ops.agents.graph import compile_investigation_graph
from sentinel_ops.agents.state import AtomicClaim, EvidenceItem
from sentinel_ops.agents.synthesizer import format_incident_brief
from sentinel_ops.core.config import settings
from sentinel_ops.dpo.trajectory_logger import DPOTrajectoryLogger
from sentinel_ops.memory.graph_rag import TopologyGraphRAG

console = Console()
FIXTURES_DIR = Path(__file__).resolve().parents[2] / "benchmarks" / "fixtures"


def load_fixture(case_id: str) -> Optional[Dict[str, Any]]:
    """Loads a replay fixture strictly by exact YAML 'id' or exact filename stem."""
    if not case_id or not isinstance(case_id, str):
        return None
    for file in sorted(FIXTURES_DIR.glob("*.yaml")):
        try:
            with open(file, "r", encoding="utf-8") as fp:
                data = yaml.safe_load(fp)
                if isinstance(data, dict) and (data.get("id") == case_id or file.stem == case_id):
                    return data
        except Exception:
            continue
    return None


async def _probe_live_preflight(
    profile,
    target_service: str,
    window: tuple[str, str],
) -> Dict[str, Any]:
    """Stage 2 preflight: read-only backend probe verifying observable signals, replica labels, and traces."""
    from sentinel_ops.mcp.prometheus_adapter import PrometheusAdapter
    from sentinel_ops.mcp.tempo_adapter import TempoAdapter
    from sentinel_ops.telemetry.normalize import extract_replica_key

    prom = PrometheusAdapter()
    tempo = TempoAdapter()
    observable: set[str] = set()
    identities: Dict[str, List[str]] = {}
    empty_count = 0
    error_count = 0
    templates = profile.to_promql_templates()
    allowed = profile.resolve_service_names()
    try:
        for logical, mapping in profile.signals.items():
            svc = next((s for s, sp in profile.services.items() if logical in sp.metrics or mapping.metric_name in sp.metrics), target_service)
            res = await prom.query_metric(
                service=svc,
                metric_type=logical,
                window=window,
                allowed_services=allowed,
                promql_templates=templates,
            )
            st = res.get("status", "EMPTY")
            if st == "SUCCESS" and res.get("result"):
                observable.add(logical)
                observable.add(mapping.metric_name)
                rkeys = [extract_replica_key(e.get("metric") or {}) for e in res.get("result", [])]
                identities[logical] = [k or "unlabeled" for k in rkeys]
            elif st == "EMPTY":
                empty_count += 1
            else:
                error_count += 1

        tid = await tempo.search_traces(service=target_service, start_iso=window[0], end_iso=window[1], limit=5)
        trace_status = "OBSERVED" if tid else "INCONCLUSIVE_EMPTY_WINDOW"
    finally:
        await prom.aclose()
        await tempo.aclose()

    window_inconclusive = len(observable) == 0 and error_count == 0
    return {
        "observable_signals": sorted(observable),
        "replica_identities": identities,
        "trace_availability": trace_status,
        "window_inconclusive": window_inconclusive,
        "error_count": error_count,
    }


def run_triage(
    case_id: Optional[str] = "case_01",
    live: bool = False,
    target_service: Optional[str] = None,
    alert_text: Optional[str] = None,
    trace_id: Optional[str] = None,
    use_llm: bool = False,
    export_brief: Optional[str] = None,
    brief_format: str = "markdown",
    auto_approve: bool = False,
    export_dpo: bool = False,
    profile_id: str = "checkout-demo",
    environment: str = "default",
    incident_timestamp: Optional[str] = None,
    window_before_minutes: int = 2,
    window_after_minutes: int = 3,
    preflight: bool = False,
) -> Dict[str, Any]:
    """Executes end-to-end incident investigation triage with interactive Rich output."""
    from sentinel_ops.agents.supervisor import compute_incident_window
    from sentinel_ops.profiles.registry import get_profile

    profile = get_profile(profile_id)
    if preflight:
        warnings = profile.validate_mappings()
        console.print(f"\n[bold cyan]SystemProfile Stage 1 Preflight (Mapping Validation):[/bold cyan] {profile.profile_id} (v{profile.version}, env={environment})")
        if warnings:
            for w in warnings:
                console.print(f"  [yellow]WARNING:[/yellow] {w}")
        else:
            console.print("  [green]Mappings valid:[/green] no cumulative/ratio mismatches or missing capacities.")

        live_probe: Optional[Dict[str, Any]] = None
        available: Optional[set[str]] = None
        if live:
            ts = incident_timestamp or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            win = compute_incident_window(ts, before_minutes=window_before_minutes, after_minutes=window_after_minutes)
            svc0 = target_service or next(iter(profile.resolve_service_names()), "checkout-service")
            live_probe = asyncio.run(_probe_live_preflight(profile, svc0, win))
            available = set(live_probe["observable_signals"])
            console.print(f"\n[bold cyan]Stage 2 Preflight (Read-Only Backend Probe [{win[0]}..{win[1]}]):[/bold cyan]")
            if live_probe["window_inconclusive"]:
                console.print("  [yellow]INCONCLUSIVE AVAILABILITY:[/yellow] empty incident window returned zero samples; re-run against an active traffic window.")
            else:
                console.print(f"  Observable signals ({len(available)}): {', '.join(live_probe['observable_signals']) or 'none'}")
                console.print(f"  Trace availability: {live_probe['trace_availability']}")

        pf = profile.preflight(available_signals=available if (live and not (live_probe or {}).get("window_inconclusive")) else None)
        for rule_id, res in pf.items():
            console.print(f"  - {rule_id}: [bold]{res.status}[/bold] ({res.notes})")
        return {
            "profile_id": profile.profile_id,
            "mapping_warnings": warnings,
            "live_probe": live_probe,
            "preflight": {k: v.model_dump() for k, v in pf.items()},
        }

    console.print("\n[bold cyan]════════════════════════════════════════════════════════════════════════════[/bold cyan]")
    console.print("[bold white]Sentinel-Ops Autonomous AI SRE: Incident Triage & Root Cause Analysis[/bold white]")
    console.print("[bold cyan]════════════════════════════════════════════════════════════════════════════[/bold cyan]\n")

    if live:
        incident_id = f"live_{datetime.now(timezone.utc).strftime('%H%M%S')}"
        default_svc = next(iter(profile.resolve_service_names()), "checkout-service")
        target_service = target_service or default_svc
        alert_text = alert_text or f"Alert: {target_service} latency/error anomaly detected in {profile.profile_id}."
        incident_timestamp = incident_timestamp or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        mock_telemetry = None
        console.print(f"[bold green]Mode:[/bold green] [bold cyan]LIVE TELEMETRY PROBING[/bold cyan] (profile={profile.profile_id})\n")
    else:
        fixture = load_fixture(case_id) if case_id else None
        if fixture is None and case_id and Path(case_id).is_file():
            with open(case_id, "r", encoding="utf-8") as fp:
                fixture = yaml.safe_load(fp)
        if fixture:
            incident_id = fixture["id"]
            alert_text = fixture["alert_text"].strip()
            incident_timestamp = incident_timestamp or fixture["incident_timestamp"]
            target_service = target_service or fixture["target_service"]
            trace_id = trace_id or fixture.get("trace_id")
            profile_id = fixture.get("profile_id", profile_id)
            profile = get_profile(profile_id)
            mock_telemetry = fixture.get("mock_telemetry")
        else:
            incident_id = "default_case"
            alert_text = "checkout-service p95 latency increased from 400ms to 4.5s; 504 errors on downstream dependencies."
            incident_timestamp = incident_timestamp or "2026-11-24T14:32:00Z"
            target_service = target_service or "checkout-service"
            mock_telemetry = None
        console.print(f"[bold green]Mode:[/bold green] [bold yellow]REPLAY FIXTURE BENCHMARK[/bold yellow] (Case: {incident_id}, profile={profile.profile_id})\n")

    # Step 1: Incident Header Panel
    console.print(
        Panel(
            f"[bold yellow]Incident ID:[/bold yellow] {incident_id}\n"
            f"[bold yellow]Target Service:[/bold yellow] {target_service}\n"
            f"[bold yellow]Timestamp Anchor (T_incident):[/bold yellow] {incident_timestamp}\n"
            f"[bold yellow]Alert Narrative:[/bold yellow] {alert_text}",
            title="[bold green]Active Incident Alert[/bold green]",
            border_style="green",
        )
    )

    # Step 2 & 3: Unified InvestigationService Initialization & LangGraph Execution
    from sentinel_ops.service.runner import InvestigationService

    service = InvestigationService()
    initial_state = service.build_initial_state(
        incident_id=incident_id,
        alert_text=alert_text,
        incident_timestamp=incident_timestamp,
        target_service=target_service,
        profile_id=profile.profile_id,
        environment=environment,
        window_before_minutes=window_before_minutes,
        window_after_minutes=window_after_minutes,
        trace_id=trace_id,
        use_llm=use_llm,
        simulated_telemetry=mock_telemetry,
    )
    console.print("[bold white]1. Topology-Aware GraphRAG Historical Retrieval:[/bold white]")
    graph_rag = TopologyGraphRAG(profile=profile)
    historical_matches = graph_rag.retrieve(
        alert_text=alert_text,
        target_service=target_service,
        incident_timestamp=incident_timestamp,
        top_k=2,
    )
    rag_table = Table(show_header=True, header_style="bold magenta")
    rag_table.add_column("Historical ID", style="cyan", width=14)
    rag_table.add_column("Postmortem Title", style="white", width=36)
    rag_table.add_column("Root Cause Service", style="yellow", width=18)
    rag_table.add_column("Composite Score", style="bold green", width=16)

    for match in historical_matches:
        pm = match["postmortem"]
        rag_table.add_row(
            pm.incident_id,
            pm.title[:35] + "...",
            pm.root_cause_service,
            f"{match['composite_score']:.3f} (Sim: {match['sim_score']:.2f}, Topo: {match['topo_score']:.2f})",
        )
    console.print(rag_table)

    console.print("\n[bold white]2. Multi-Agent Reasoning Execution (LangGraph):[/bold white]")
    with console.status("[bold green]Orchestrating supervisor, specialists, CRAG gate & adversarial skeptic...[/bold green]"):
        final_state = asyncio.run(
            service.execute_state_sync(initial_state, thread_id=f"cli_{incident_id}_{uuid.uuid4().hex[:8]}")
        )

    terminal_status = final_state.get("terminal_status", "OPERATIONAL_FAILURE")

    if export_brief:
        brief_path = Path(export_brief)
        brief_path.parent.mkdir(parents=True, exist_ok=True)
        brief_text = format_incident_brief(final_state, fmt=brief_format)
        brief_path.write_text(brief_text, encoding="utf-8")
        console.print(f"[bold cyan]Incident Brief exported to:[/bold cyan] {brief_path}\n")

    # Step 4: Display Evidence Ledger
    console.print("\n[bold white]3. Telemetry Evidence Ledger (Sanitized & Redacted):[/bold white]")
    ev_table = Table(show_header=True, header_style="bold cyan")
    ev_table.add_column("Evidence ID", style="cyan", width=16)
    ev_table.add_column("Source", style="magenta", width=12)
    ev_table.add_column("Observed Finding", style="white", width=48)
    ev_table.add_column("Status", style="bold", width=12)

    for ev in final_state.get("evidence", []):
        status_color = "green" if ev.status == "SUCCESS" else ("yellow" if ev.status == "EMPTY" else "red")
        ev_table.add_row(ev.id, ev.backend_source, ev.finding, f"[{status_color}]{ev.status}[/{status_color}]")
    console.print(ev_table)

    # Step 5: Check Terminal Outcome & Claims
    if terminal_status == "INSUFFICIENT_EVIDENCE":
        next_checks = final_state.get("next_discriminating_checks", [
            "Query downstream microservice database connection pool metrics",
            "Verify OpenTelemetry distributed trace collector health",
        ])
        loc = final_state.get("localized_dependency") or {}
        rule_eval = final_state.get("rule_evaluation") or {}
        loc_line = ""
        if loc.get("bottleneck_service"):
            loc_line = f"[bold cyan]Localized Bottleneck:[/bold cyan] {loc['bottleneck_service']} ({loc.get('bottleneck_operation') or 'slow_span'}, {loc.get('exclusive_duration_ms', 0.0):.1f}ms)\n"
        cov_line = f"[bold cyan]Coverage Status:[/bold cyan] {rule_eval.get('coverage_status', 'UNKNOWN')}\n"
        console.print(
            Panel(
                f"[bold red]ABSTENTION TRIGGERED:[/bold red] {final_state.get('terminal_reason')}\n"
                f"{loc_line}"
                f"{cov_line}"
                f"[bold yellow]Safety Invariant:[/bold yellow] Automated remediation is strictly prohibited on inconclusive signals.\n\n"
                f"[bold cyan]Actionable Next Discriminating Checks for Operator:[/bold cyan]\n" +
                "\n".join(f"  • {chk}" for chk in next_checks),
                title="[bold yellow]Terminal Outcome: INSUFFICIENT_EVIDENCE (Safe Abstention)[/bold yellow]",
                border_style="yellow",
            )
        )
        return final_state

    if terminal_status == "OPERATIONAL_FAILURE":
        console.print(
            Panel(
                f"[bold red]OPERATIONAL TOOL FAILURE:[/bold red] {final_state.get('terminal_reason')}\n"
                f"[bold yellow]Infrastructure Status:[/bold yellow] Telemetry collectors experienced unrecoverable connection errors or timeout.",
                title="[bold red]Terminal Outcome: OPERATIONAL_FAILURE[/bold red]",
                border_style="red",
            )
        )
        return final_state

    # Step 6: Atomic Claims & Citation Entailment Table
    console.print("\n[bold white]4. Grounded Atomic Claims & Citations:[/bold white]")
    claim_table = Table(show_header=True, header_style="bold green")
    claim_table.add_column("Claim ID", style="cyan", width=10)
    claim_table.add_column("Type", style="magenta", width=14)
    claim_table.add_column("Assertion Statement", style="white", width=46)
    claim_table.add_column("Citations", style="bold yellow", width=16)

    for c in final_state.get("structured_claims", []):
        claim_table.add_row(c.claim_id, c.claim_type, c.statement, ", ".join(c.cited_evidence_ids))
    console.print(claim_table)

    # Step 7: Adversarial Red-Team Reviewer
    verdict = final_state.get("adversarial_verdict")
    if verdict:
        console.print(
            Panel(
                f"[bold green]Entailment Status:[/bold green] {'All Claims Supported' if verdict.all_claims_supported else 'REJECTED'}\n"
                f"[bold green]Reviewer Confidence:[/bold green] {verdict.confidence:.2f}\n"
                f"[bold green]Prosecutor Critique:[/bold green] {verdict.critique_hint or 'Zero unbacked claims found. Entailment verified.'}",
                title="[bold cyan]Adversarial Red-Team Reviewer Verdict[/bold cyan]",
                border_style="cyan",
            )
        )

    # Step 8: Upstream Blast Radius & Advisory Remediation
    blast_score = final_state.get("blast_radius_score", 0.0)
    callers = final_state.get("affected_callers", [])
    proposal = final_state.get("remediation_proposal", "Restart affected service.")
    next_checks = final_state.get("next_discriminating_checks", [])
    runbook_action = final_state.get("recommended_runbook_action")

    guidance_lines = [
        f"[bold yellow]Diagnosed Root Cause:[/bold yellow] {final_state.get('root_cause_summary')}",
        f"[bold yellow]Upstream Affected Callers:[/bold yellow] {', '.join(callers) if callers else 'None'}",
        f"[bold yellow]Blast Radius Score:[/bold yellow] {blast_score:.2f} ({'High Risk (>0.6)' if blast_score > 0.6 else 'Medium Risk'})",
    ]
    if runbook_action:
        guidance_lines.append(f"\n[bold cyan]Recommended SRE Runbook Action:[/bold cyan]\n  [bold white]{runbook_action}[/bold white]")
    if next_checks:
        guidance_lines.append("\n[bold cyan]Actionable Next Discriminating Checks:[/bold cyan]\n" + "\n".join(f"  • {chk}" for chk in next_checks))

    console.print(
        Panel(
            "\n".join(guidance_lines),
            title="[bold magenta]Actionable Mitigation Plan & Impact Assessment[/bold magenta]",
            border_style="magenta",
        )
    )

    # Step 9: Human-In-The-Loop Approval Gate (Read-Only Advisory)
    if not auto_approve:
        console.print("\n[bold yellow]Human-in-the-Loop (HITL) Advisory Acknowledgment Gate:[/bold yellow]")
        try:
            approved = Confirm.ask("Acknowledge proposed runbook action for operator execution?", default=True)
        except (EOFError, KeyboardInterrupt):
            approved = False
            console.print("[dim italic]Non-interactive/EOF environment detected: defaulting to safe deferral.[/dim italic]")
    else:
        approved = True
        console.print("[dim italic]--auto-approve set: acknowledging advisory runbook action.[/dim italic]")

    if approved:
        console.print("[bold green]✔ Advisory runbook action acknowledged by operator. (Platform operating in safe Read-Only Triage mode; execute the suggested commands via your deployment pipeline).[/bold green]")
    else:
        console.print("[bold yellow]✖ Runbook action deferred by operator. Investigation findings preserved.[/bold yellow]")

    # Step 10: DPO Trajectory Logging
    if export_dpo:
        dpo_logger = DPOTrajectoryLogger()
        if terminal_status == "SUPPORTED_DIAGNOSIS":
            chosen_steps = [
                {"role": "supervisor", "content": "Decomposed alert into competing hypotheses using topology and GraphRAG"},
                {"role": "graph_rag", "top_match": historical_matches[0]["postmortem"].incident_id if historical_matches else None},
                {"role": "evidence", "findings": [e.finding for e in final_state.get("evidence", [])]},
                {"role": "synthesizer", "claims": [c.model_dump() for c in final_state.get("structured_claims", [])]},
                {"role": "adversarial", "verdict": "ACCEPTED"},
                {"role": "blast_radius", "score": blast_score, "callers": callers},
                {"role": "hitl", "decision": "APPROVED" if approved else "DEFERRED", "runbook_action": runbook_action},
            ]
            rejected_steps = [
                {"role": "single_pass", "content": "Unverified single pass guess"},
                {"role": "claim", "statement": "Ungrounded speculation without citations"},
            ]
        elif not approved and terminal_status != "INSUFFICIENT_EVIDENCE":
            chosen_steps = [
                {"role": "operator", "action": "DEFERRED_ACTION", "reason": "Operator deferred execution on unverified triage"},
            ]
            rejected_steps = [
                {"role": "synthesizer", "proposal": proposal, "runbook_action": runbook_action},
            ]
        else:
            chosen_steps = [
                {"role": "crag_gate", "status": "ABSTAIN", "reason": final_state.get("terminal_reason")},
                {"role": "advisory", "next_checks": final_state.get("next_discriminating_checks", [])},
            ]
            rejected_steps = [
                {"role": "single_pass", "content": "Hallucinated root cause guess without telemetry"},
            ]

        dpo_path = dpo_logger.log_pair(
            incident_id=incident_id,
            prompt=alert_text,
            target_service=target_service,
            chosen_steps=chosen_steps,
            rejected_steps=rejected_steps,
            metadata={"status": terminal_status, "approved": approved, "mode": "live" if live else "replay"},
        )
        console.print(f"[dim italic]Preference trajectory logged to DPO dataset at: {dpo_path}[/dim italic]")

    return final_state


def main() -> int:
    if hasattr(signal, "SIGPIPE"):
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)

    parser = argparse.ArgumentParser(description="Sentinel-Ops AI SRE Investigation CLI")
    parser.add_argument("--case-id", default=None, help="Replay case ID or YAML fixture path (cannot be combined with --live)")
    parser.add_argument("--live", action="store_true", help="Execute triage against live Prometheus/Tempo endpoints instead of replay fixtures")
    parser.add_argument("--profile", default="checkout-demo", help="SystemProfile ID or path (e.g., checkout-demo, document-pipeline)")
    parser.add_argument("--env", default="default", help="Scoped deployment environment identifier")
    parser.add_argument("--alert-time", default=None, help="Historical alert timestamp in ISO-8601 UTC (overrides current clock in --live mode)")
    parser.add_argument("--window-before", type=int, default=2, help="Minutes before alert-time to query (default: 2)")
    parser.add_argument("--window-after", type=int, default=3, help="Minutes after alert-time to query (default: 3)")
    parser.add_argument("--preflight", action="store_true", help="Check SystemProfile signal readiness without executing triage")
    parser.add_argument("--use-llm", action="store_true", help="Enable bounded Gemini 3.5 Flash Lite Neuro-Symbolic query planning")
    parser.add_argument("--target-service", default=None, help="Target service for investigation")
    parser.add_argument("--trace-id", default=None, help="Explicit distributed trace ID to inspect")
    parser.add_argument("--export-brief", default=None, help="Write Read-Only Incident Brief to Markdown or JSON file")
    parser.add_argument("--brief-format", default="markdown", choices=["markdown", "json"], help="Format for --export-brief")
    parser.add_argument("--auto-approve", action="store_true", help="Bypass interactive HITL approval prompt")
    parser.add_argument("--export-dpo", action="store_true", help="Opt-in DPO trajectory export")
    parser.add_argument("--no-dpo", action="store_true", help="Disable DPO trajectory export")

    args = parser.parse_args()
    if args.live and args.case_id is not None:
        parser.error("Cannot combine --live with --case-id; specify either live probing or a replay fixture.")

    resolved_case_id = None if (args.live or args.preflight) else (args.case_id or "case_01")
    should_export_dpo = bool(args.export_dpo) and not bool(args.no_dpo)
    try:
        final_state = run_triage(
            case_id=resolved_case_id,
            live=args.live,
            target_service=args.target_service,
            trace_id=args.trace_id,
            use_llm=args.use_llm,
            export_brief=args.export_brief,
            brief_format=args.brief_format,
            auto_approve=args.auto_approve,
            export_dpo=should_export_dpo,
            profile_id=args.profile,
            environment=args.env,
            incident_timestamp=args.alert_time,
            window_before_minutes=args.window_before,
            window_after_minutes=args.window_after,
            preflight=args.preflight,
        )
    except BrokenPipeError:
        return 0
    except (KeyError, ValueError) as exc:
        console.print(f"[bold red]Configuration / Profile Error:[/bold red] {exc}")
        return 1

    if args.preflight:
        return 0

    status = final_state.get("terminal_status", "OPERATIONAL_FAILURE")
    if status == "SUPPORTED_DIAGNOSIS":
        return 0
    if status == "INSUFFICIENT_EVIDENCE":
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main())
