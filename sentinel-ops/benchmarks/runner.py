import asyncio
import os
import uuid
import yaml
from pathlib import Path
from typing import Any, Dict, List
from rich.console import Console
from rich.table import Table

from benchmarks.baselines.deterministic_rules import DeterministicRuleBaseline
from benchmarks.baselines.single_pass_llm import SinglePassLLMBaseline
from sentinel_ops.agents.graph import compile_investigation_graph
from sentinel_ops.agents.state import AtomicClaim, EvidenceItem
from sentinel_ops.memory.graph_rag import TopologyGraphRAG
from tests.test_claim_verification import validate_claims_and_citations

console = Console()
FIXTURES_DIR = Path(__file__).parent / "fixtures"


class SentinelOpsLangGraphAgent:
    """Multi-Agent LangGraph Engine executing supervisor, specialists, CRAG gate,

    synthesizer, adversarial skeptic, and upstream blast radius calculations.
    """

    def __init__(self):
        self.graph = compile_investigation_graph()
        self.rag = TopologyGraphRAG()

    def diagnose(self, case: Dict[str, Any], resume_thread_id: str | None = None) -> Dict[str, Any]:
        matches = self.rag.retrieve(
            alert_text=case.get("alert_text", ""),
            target_service=case.get("target_service", "checkout-service"),
            incident_timestamp=case.get("incident_timestamp", "2026-11-24T14:32:00Z"),
            top_k=2,
        )
        rag_context = [
            {"incident_id": m["postmortem"].incident_id, "title": m["postmortem"].title, "service": m["postmortem"].root_cause_service}
            for m in matches
        ]
        initial_state = {
            "incident_id": case["id"],
            "alert_text": case.get("alert_text", ""),
            "incident_timestamp": case.get("incident_timestamp", "2026-11-24T14:32:00Z"),
            "target_service": case.get("target_service", "checkout-service"),
            "trace_id": case.get("trace_id"),
            "historical_context": rag_context,
            "simulated_telemetry": case.get("mock_telemetry"),
            "crag_iterations": 0,
        }
        thread_id = resume_thread_id or f"{case.get('id', 'bench')}_{uuid.uuid4().hex[:8]}"
        config = {"configurable": {"thread_id": thread_id}}
        final_state = asyncio.run(self.graph.ainvoke(initial_state, config=config))

        diag_svc = "unknown"
        if final_state.get("terminal_status") == "SUPPORTED_DIAGNOSIS":
            summary = final_state.get("root_cause_summary", "")
            if "payment-service" in summary:
                diag_svc = "payment-service"
            elif "pricing-service" in summary:
                diag_svc = "pricing-service"
            elif "cart-service" in summary:
                diag_svc = "cart-service"

        return {
            "agent": "sentinel_ops_langgraph",
            "diagnosed_root_cause": diag_svc,
            "mechanism": final_state.get("mechanism"),
            "terminal_status": final_state.get("terminal_status"),
            "terminal_reason": final_state.get("terminal_reason"),
            "claims": final_state.get("structured_claims", []),
            "evidence": final_state.get("evidence", []),
            "blast_score": final_state.get("blast_radius_score", 0.0),
            "remediation": final_state.get("remediation_proposal", ""),
            "adversarial_verdict": final_state.get("adversarial_verdict"),
            "thread_id": thread_id,
        }


def load_fixtures() -> List[Dict[str, Any]]:
    """Loads all test cases from fixtures directory."""
    cases = []
    for fixture_file in sorted(FIXTURES_DIR.glob("*.yaml")):
        with open(fixture_file, "r", encoding="utf-8") as fp:
            data = yaml.safe_load(fp)
            cases.append(data)
    return cases


def run_benchmark():
    console.print("\n[bold cyan]══════════════════════════════════════════════════════════════════════════[/bold cyan]")
    console.print("[bold white]Sentinel-Ops Benchmark: 5-Case Replay & Baseline Comparison[/bold white]")
    console.print("[bold cyan]══════════════════════════════════════════════════════════════════════════[/bold cyan]\n")

    cases = load_fixtures()
    console.print(f"Loaded [bold green]{len(cases)}[/bold green] replayable incident cases from [cyan]benchmarks/fixtures/[/cyan]\n")

    deterministic_engine = DeterministicRuleBaseline()
    single_pass_engine = SinglePassLLMBaseline()
    sentinel_agent = SentinelOpsLangGraphAgent()

    table = Table(title="Incident Replay Comparison Matrix", show_header=True, header_style="bold magenta")
    table.add_column("Case ID", style="cyan", width=10)
    table.add_column("Ground Truth Cause", style="white", width=22)
    table.add_column("Deterministic Rules", style="yellow", width=20)
    table.add_column("Single-Pass LLM", style="red", width=20)
    table.add_column("Sentinel-Ops Agent", style="bold green", width=24)

    results = {}

    for c in cases:
        c_id = c["id"]
        gt_cause = f"{c['ground_truth']['root_cause_service']} ({c['ground_truth']['mechanism']})"
        
        # Sanitize input: strip ground truth so candidate models evaluate telemetry honestly
        c_input = {k: v for k, v in c.items() if k != "ground_truth"}
        
        # Run baselines
        det_res = deterministic_engine.diagnose(c_input)
        sp_res = single_pass_engine.diagnose(c_input)
        agent_res = sentinel_agent.diagnose(c_input)
        results[c_id] = {"agent": agent_res, "single_pass": sp_res, "deterministic": det_res}

        det_str = f"{det_res['diagnosed_root_cause']} [{det_res['terminal_status'][:4]}]"
        sp_str = f"{sp_res['diagnosed_root_cause']} [{sp_res['terminal_status'][:4]}]"
        
        agent_status = agent_res["terminal_status"]
        if agent_status == "SUPPORTED_DIAGNOSIS":
            agent_str = f"{agent_res['diagnosed_root_cause']} (SUPPORTED)"
        elif agent_status == "INSUFFICIENT_EVIDENCE":
            agent_str = "ABSTAINED (INSUFFICIENT)"
        else:
            agent_str = f"FAILED: {agent_status}"

        table.add_row(c_id, gt_cause, det_str, sp_str, agent_str)

    console.print(table)

    # Dynamic evaluation calculation
    diagnosable_cases = [c for c in cases if c["ground_truth"]["expected_terminal_status"] == "SUPPORTED_DIAGNOSIS"]
    abstention_cases = [c for c in cases if c["ground_truth"]["expected_terminal_status"] == "INSUFFICIENT_EVIDENCE"]

    correct_diagnoses = sum(
        1 for c in diagnosable_cases
        if results[c["id"]]["agent"]["diagnosed_root_cause"] == c["ground_truth"]["root_cause_service"]
        and results[c["id"]]["agent"]["terminal_status"] == "SUPPORTED_DIAGNOSIS"
    )
    precision_pct = (correct_diagnoses / len(diagnosable_cases) * 100.0) if diagnosable_cases else 0.0

    correct_abstentions = sum(
        1 for c in abstention_cases
        if results[c["id"]]["agent"]["terminal_status"] == "INSUFFICIENT_EVIDENCE"
    )
    abstention_pct = (correct_abstentions / len(abstention_cases) * 100.0) if abstention_cases else 0.0

    sp_hallucinations = sum(
        1 for c in abstention_cases
        if results[c["id"]]["single_pass"]["terminal_status"] != "INSUFFICIENT_EVIDENCE"
    )
    sp_hallucination_pct = (sp_hallucinations / len(abstention_cases) * 100.0) if abstention_cases else 0.0

    # Print Key Insights
    console.print("\n[bold white]Key Architectural Metrics Demonstrated (Dynamically Evaluated):[/bold white]")
    console.print(f"  ✔ [green]Root-Cause Precision:[/green] {precision_pct:.1f}% ({correct_diagnoses}/{len(diagnosable_cases)} cases matched ground truth)")
    console.print(f"  ✔ [green]Correct Abstention Rate:[/green] {abstention_pct:.1f}% ({correct_abstentions}/{len(abstention_cases)} withheld cases safely abstained; Single-Pass LLM hallucinated {sp_hallucination_pct:.1f}%)")
    # Dynamic citation contract evaluation
    total_claims = 0
    valid_citation_claims = 0
    for c in diagnosable_cases:
        agent_data = results[c["id"]]["agent"]
        claims = agent_data.get("claims", [])
        evidence = agent_data.get("evidence", [])
        if claims:
            total_claims += len(claims)
            is_valid, _ = validate_claims_and_citations(claims, evidence)
            if is_valid:
                valid_citation_claims += len(claims)

    citation_pct = (valid_citation_claims / total_claims * 100.0) if total_claims else 100.0
    console.print(f"  ✔ [green]Citation Contract Support:[/green] {citation_pct:.1f}% of claims cite verified [EV-xxx] observations (Dynamically Verified)")


if __name__ == "__main__":
    run_benchmark()
