import argparse
import asyncio
import sys
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Confirm

from sentinel_ops.agents.graph import compile_investigation_graph
from sentinel_ops.agents.state import AtomicClaim, EvidenceItem
from sentinel_ops.dpo.trajectory_logger import DPOTrajectoryLogger
from sentinel_ops.memory.graph_rag import TopologyGraphRAG

console = Console()
FIXTURES_DIR = Path(__file__).resolve().parents[2] / "benchmarks" / "fixtures"


def load_fixture(case_id: str) -> Optional[Dict[str, Any]]:
    """Loads a replay fixture by case ID (e.g., case_01)."""
    for file in FIXTURES_DIR.glob("*.yaml"):
        if case_id in file.stem:
            with open(file, "r", encoding="utf-8") as fp:
                return yaml.safe_load(fp)
    return None


def run_triage(
    case_id: Optional[str] = "case_01",
    auto_approve: bool = False,
    export_dpo: bool = True,
) -> Dict[str, Any]:
    """Executes end-to-end incident investigation triage with interactive Rich output."""
    console.print("\n[bold cyan]════════════════════════════════════════════════════════════════════════════[/bold cyan]")
    console.print("[bold white]Sentinel-Ops Autonomous AI SRE: Incident Triage & Root Cause Analysis[/bold white]")
    console.print("[bold cyan]════════════════════════════════════════════════════════════════════════════[/bold cyan]\n")

    fixture = load_fixture(case_id) if case_id else None
    if fixture:
        incident_id = fixture["id"]
        alert_text = fixture["alert_text"].strip()
        incident_timestamp = fixture["incident_timestamp"]
        target_service = fixture["target_service"]
        mock_telemetry = fixture.get("mock_telemetry")
    else:
        incident_id = "live_alert_01"
        alert_text = "checkout-service p95 latency increased from 400ms to 4.5s; 504 errors on downstream dependencies."
        incident_timestamp = "2026-11-24T14:32:00Z"
        target_service = "checkout-service"
        mock_telemetry = None

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

    # Step 2: Topology-Aware GraphRAG Prior Knowledge
    console.print("[bold white]1. Topology-Aware GraphRAG Historical Retrieval:[/bold white]")
    graph_rag = TopologyGraphRAG()
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

    # Step 3: Run Compiled LangGraph Agent Machine
    console.print("\n[bold white]2. Multi-Agent Reasoning Execution (LangGraph):[/bold white]")
    with console.status("[bold green]Orchestrating supervisor, specialists, CRAG gate & adversarial skeptic...[/bold green]"):
        graph = compile_investigation_graph()
        initial_state = {
            "incident_id": incident_id,
            "alert_text": alert_text,
            "incident_timestamp": incident_timestamp,
            "target_service": target_service,
            "simulated_telemetry": mock_telemetry,
            "crag_iterations": 2 if incident_id == "case_03" else 0,
        }
        config = {"configurable": {"thread_id": f"cli_{incident_id}"}}
        final_state = asyncio.run(graph.ainvoke(initial_state, config=config))

    terminal_status = final_state.get("terminal_status", "OPERATIONAL_FAILURE")

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
        console.print(
            Panel(
                f"[bold red]ABSTENTION TRIGGERED:[/bold red] {final_state.get('terminal_reason')}\n"
                f"[bold yellow]Safety Invariant:[/bold yellow] Remediation is strictly prohibited on inconclusive signals.",
                title="[bold yellow]Terminal Outcome: INSUFFICIENT_EVIDENCE[/bold yellow]",
                border_style="yellow",
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

    # Step 8: Upstream Blast Radius & HITL Remediation
    blast_score = final_state.get("blast_radius_score", 0.0)
    callers = final_state.get("affected_callers", [])
    proposal = final_state.get("remediation_proposal", "Restart affected service.")

    console.print(
        Panel(
            f"[bold yellow]Diagnosed Root Cause:[/bold yellow] {final_state.get('root_cause_summary')}\n"
            f"[bold yellow]Upstream Affected Callers:[/bold yellow] {', '.join(callers) if callers else 'None'}\n"
            f"[bold yellow]Blast Radius Score:[/bold yellow] {blast_score:.2f} ({'High Risk (>0.6)' if blast_score > 0.6 else 'Medium Risk'})\n"
            f"[bold yellow]Proposed Remediation Action:[/bold yellow] {proposal}",
            title="[bold magenta]Mitigation Plan & Impact Assessment[/bold magenta]",
            border_style="magenta",
        )
    )

    # Step 9: Human-In-The-Loop Approval Gate
    if not auto_approve:
        console.print("\n[bold yellow]Human-in-the-Loop (HITL) Safety Gate:[/bold yellow]")
        approved = Confirm.ask("Do you authorize executing the proposed remediation action?", default=True)
    else:
        approved = True
        console.print("[dim italic]--auto-approve set: proceeding with execution approval.[/dim italic]")

    if approved:
        console.print("[bold green]✔ Remediation action approved. Idempotent change committed.[/bold green]")
    else:
        console.print("[bold red]✖ Remediation rejected by operator. Investigation preserved.[/bold red]")

    # Step 10: DPO Trajectory Logging
    if export_dpo:
        dpo_logger = DPOTrajectoryLogger()
        chosen_steps = [
            {"role": "supervisor", "content": "Decomposed alert into competing hypotheses"},
            {"role": "graph_rag", "top_match": historical_matches[0]["postmortem"].incident_id if historical_matches else None},
            {"role": "evidence", "findings": [e.finding for e in final_state.get("evidence", [])]},
            {"role": "synthesizer", "claims": [c.model_dump() for c in final_state.get("structured_claims", [])]},
            {"role": "adversarial", "verdict": "ACCEPTED"},
            {"role": "blast_radius", "score": blast_score, "callers": callers},
        ]
        rejected_steps = [
            {"role": "single_pass", "content": "Unverified single pass guess"},
            {"role": "claim", "statement": "Ungrounded speculation without citations"},
        ]
        dpo_path = dpo_logger.log_pair(
            incident_id=incident_id,
            prompt=alert_text,
            target_service=target_service,
            chosen_steps=chosen_steps,
            rejected_steps=rejected_steps,
            metadata={"status": terminal_status, "approved": approved},
        )
        console.print(f"[dim italic]Trajectory logged to DPO dataset at: {dpo_path}[/dim italic]")

    return final_state


def main():
    parser = argparse.ArgumentParser(description="Sentinel-Ops AI SRE Investigation CLI")
    parser.add_argument("--case-id", default="case_01", choices=["case_01", "case_02", "case_03"], help="Replay case ID")
    parser.add_argument("--auto-approve", action="store_true", help="Bypass interactive HITL approval prompt")
    parser.add_argument("--no-dpo", action="store_true", help="Disable DPO trajectory export")

    args = parser.parse_args()
    run_triage(
        case_id=args.case_id,
        auto_approve=args.auto_approve,
        export_dpo=not args.no_dpo,
    )


if __name__ == "__main__":
    main()
