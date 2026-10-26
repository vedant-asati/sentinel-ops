import argparse
import asyncio
import os
import sys
import time
import uuid
import yaml
from pathlib import Path
from typing import Any, Dict, List
from rich.console import Console
from rich.table import Table

from benchmarks.baselines.deterministic_rules import DeterministicRuleBaseline
from benchmarks.baselines.single_pass_llm import SinglePassLLMBaseline, UngroundedHeuristicBaseline
from sentinel_ops.agents.adversarial import validate_claims_and_citations
from sentinel_ops.agents.graph import compile_investigation_graph
from sentinel_ops.agents.llm_planner import run_live_single_pass_gemini
from sentinel_ops.agents.state import AtomicClaim, EvidenceItem
from sentinel_ops.analytics.dora import compute_dora_benchmark
from sentinel_ops.memory.graph_rag import TopologyGraphRAG

console = Console()
FIXTURES_DIR = Path(__file__).parent / "fixtures"


class SentinelOpsLangGraphAgent:
    """Multi-Agent LangGraph Engine executing supervisor, specialists, CRAG gate,

    synthesizer, adversarial skeptic, and upstream blast radius calculations.
    """

    def __init__(self):
        from sentinel_ops.service.runner import InvestigationService
        self.service = InvestigationService()
        self.graph = compile_investigation_graph()
        self.rag = TopologyGraphRAG()

    def diagnose(self, case: Dict[str, Any], resume_thread_id: str | None = None, use_llm: bool = False) -> Dict[str, Any]:
        initial_state = self.service.build_initial_state(
            incident_id=case["id"],
            alert_text=case.get("alert_text", ""),
            incident_timestamp=case.get("incident_timestamp", "2026-11-24T14:32:00Z"),
            target_service=case.get("target_service", "checkout-service"),
            profile_id=case.get("profile_id", "checkout-demo"),
            trace_id=case.get("trace_id"),
            use_llm=use_llm,
            simulated_telemetry=case.get("mock_telemetry"),
        )
        thread_id = resume_thread_id or f"{case.get('id', 'bench')}_{uuid.uuid4().hex[:8]}"
        t0 = time.perf_counter()
        final_state = asyncio.run(self.service.execute_state_sync(initial_state, thread_id=thread_id))
        elapsed_s = time.perf_counter() - t0

        diag_svc = "unknown"
        if final_state.get("terminal_status") == "SUPPORTED_DIAGNOSIS":
            rule_eval = final_state.get("rule_evaluation") or {}
            if rule_eval.get("root_cause_service"):
                diag_svc = rule_eval["root_cause_service"]
            else:
                claims = final_state.get("structured_claims") or []
                root_claim_text = " ".join(c.statement for c in claims if getattr(c, "claim_type", None) == "root_cause")
                source_text = root_claim_text or final_state.get("root_cause_summary", "")
                for svc in ("payment-service", "pricing-service", "cart-service"):
                    if svc in source_text:
                        diag_svc = svc
                        break

        return {
            "agent": "sentinel_ops_langgraph",
            "diagnosed_root_cause": diag_svc,
            "mechanism": final_state.get("mechanism"),
            "terminal_status": final_state.get("terminal_status"),
            "terminal_reason": final_state.get("terminal_reason"),
            "claims": final_state.get("structured_claims", []),
            "evidence": final_state.get("evidence", []),
            "queries_executed": len(final_state.get("probe_attempts") or final_state.get("evidence", [])),
            "blast_score": final_state.get("blast_radius_score", 0.0),
            "remediation": final_state.get("remediation_proposal", ""),
            "adversarial_verdict": final_state.get("adversarial_verdict"),
            "thread_id": thread_id,
            "elapsed_seconds": round(elapsed_s, 4),
        }


def load_fixtures() -> List[Dict[str, Any]]:
    """Loads all test cases from fixtures directory."""
    cases = []
    for fixture_file in sorted(FIXTURES_DIR.glob("*.yaml")):
        with open(fixture_file, "r", encoding="utf-8") as fp:
            data = yaml.safe_load(fp)
            cases.append(data)
    return cases


def run_benchmark(live_llm: bool = False) -> int:
    console.print("\n[bold cyan]══════════════════════════════════════════════════════════════════════════[/bold cyan]")
    mode_label = "Live Gemini 3.5 Flash Lite Neuro-Symbolic Comparison" if live_llm else "Offline Replay & Heuristic Comparison"
    console.print(f"[bold white]Sentinel-Ops Benchmark: 5-Case {mode_label}[/bold white]")
    console.print("[bold cyan]══════════════════════════════════════════════════════════════════════════[/bold cyan]\n")

    cases = load_fixtures()
    console.print(f"Loaded [bold green]{len(cases)}[/bold green] replayable incident cases from [cyan]benchmarks/fixtures/[/cyan]\n")

    deterministic_engine = DeterministicRuleBaseline()
    ungrounded_engine = UngroundedHeuristicBaseline()
    sentinel_agent = SentinelOpsLangGraphAgent()

    baseline_col_title = "Live Gemini Single-Pass" if live_llm else "Ungrounded Heuristic"
    table = Table(title="Incident Replay Comparison Matrix", show_header=True, header_style="bold magenta")
    table.add_column("Case ID", style="cyan", width=10)
    table.add_column("Ground Truth Cause", style="white", width=22)
    table.add_column("Deterministic Rules", style="yellow", width=20)
    table.add_column(baseline_col_title, style="red", width=22)
    table.add_column("Sentinel-Ops Agent", style="bold green", width=24)

    results = {}
    latencies: List[float] = []

    for c in cases:
        c_id = c["id"]
        gt_cause = f"{c['ground_truth']['root_cause_service']} ({c['ground_truth']['mechanism']})"

        # Sanitize input: strip ground truth so candidate models evaluate telemetry honestly
        c_input = {k: v for k, v in c.items() if k != "ground_truth"}

        det_res = deterministic_engine.diagnose(c_input)
        if live_llm:
            sp_res = asyncio.run(
                run_live_single_pass_gemini(
                    alert_text=c_input.get("alert_text", ""),
                    target_service=c_input.get("target_service", "checkout-service"),
                    telemetry_bundle=c_input.get("mock_telemetry") or {},
                )
            )
        else:
            sp_res = ungrounded_engine.diagnose(c_input)

        agent_res = sentinel_agent.diagnose(c_input, use_llm=live_llm)
        latencies.append(agent_res.get("elapsed_seconds", 0.0))
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

    sp_attempted = len(abstention_cases)
    sp_provider_failures = sum(
        1 for c in abstention_cases
        if results[c["id"]]["single_pass"]["terminal_status"] == "OPERATIONAL_FAILURE"
    )
    sp_completed = sp_attempted - sp_provider_failures
    sp_hallucinations = sum(
        1 for c in abstention_cases
        if results[c["id"]]["single_pass"]["terminal_status"] == "SUPPORTED_DIAGNOSIS"
    )
    sp_hallucination_pct = (sp_hallucinations / sp_completed * 100.0) if sp_completed else 0.0

    total_provider_failures = sum(
        1 for c in cases
        if results[c["id"]]["single_pass"]["terminal_status"] == "OPERATIONAL_FAILURE"
    )
    total_completed_sp = len(cases) - total_provider_failures

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
    avg_latency_sec = (sum(latencies) / len(latencies)) if latencies else 0.0
    avg_queries = (
        sum(results[c["id"]]["agent"].get("queries_executed", len(results[c["id"]]["agent"].get("evidence", []))) for c in cases) / len(cases)
        if cases else 0.0
    )
    dora_summary = compute_dora_benchmark(
        agent_mttr_seconds=max(0.001, avg_latency_sec),
        citation_support_rate=citation_pct / 100.0,
        correct_abstention_rate=abstention_pct / 100.0,
    )

    console.print("\n[bold white]Measured Benchmark Results (Dynamically Evaluated):[/bold white]")
    console.print(f"  ✔ [green]Root-Cause Precision:[/green] {precision_pct:.1f}% ({correct_diagnoses}/{len(diagnosable_cases)} cases matched ground truth)")
    if sp_completed == 0:
        baseline_note = f"{baseline_col_title}: UNAVAILABLE (0/{len(cases)} completed; {total_provider_failures} provider failures)"
    else:
        baseline_note = f"{baseline_col_title} guessed wrong {sp_hallucination_pct:.1f}% ({sp_hallucinations}/{sp_completed} completed, {sp_provider_failures} failed)"
    console.print(f"  ✔ [green]Correct Abstention Rate:[/green] {abstention_pct:.1f}% ({correct_abstentions}/{len(abstention_cases)} withheld cases safely abstained; {baseline_note})")
    console.print(f"  ✔ [green]Citation Contract Support:[/green] {citation_pct:.1f}% of claims cite verified [EV-xxx] observations")
    console.print(f"  ✔ [green]Measured Mean Triage Latency:[/green] {avg_latency_sec:.4f}s per case (vs. 2700s manual ref: {dora_summary.acceleration_factor:.0f}x)")
    console.print(f"  ✔ [green]Mean Telemetry Queries Executed:[/green] {avg_queries:.1f} probes per case")

    if precision_pct < 100.0 or abstention_pct < 100.0 or citation_pct < 100.0:
        return 1
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sentinel-Ops Replay Benchmark Runner")
    parser.add_argument("--live-llm", action="store_true", help="Compare live Gemini 3.5 Flash Lite Neuro-Symbolic planner vs unconstrained single-pass Gemini")
    args = parser.parse_args()
    sys.exit(run_benchmark(live_llm=args.live_llm))
