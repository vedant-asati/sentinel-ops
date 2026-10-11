import asyncio
import json
import time
import urllib.request
from typing import List, Optional
import httpx
from pydantic import BaseModel, Field
from rich.console import Console
from rich.table import Table

from sentinel_ops.core.config import settings
from sentinel_ops.core.llm import get_chat_model

console = Console()


class ProbeResult(BaseModel):
    test_passed: bool
    model_name: str
    greeting: str
    detected_platform: str
    latency_ms: float


class SmokeTestSchema(BaseModel):
    service_name: str = Field(description="Name of microservice identified")
    is_healthy: bool = Field(description="Health status indicator")
    observed_code: int = Field(description="HTTP status code")


async def async_list_available_gemini_models() -> List[str]:
    """Non-blocking async Gemini catalog lookup using httpx.AsyncClient."""
    if not settings.GEMINI_API_KEY:
        return []
    url = f"https://generativelanguage.googleapis.com/v1beta/models?key={settings.GEMINI_API_KEY}"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url, headers={"User-Agent": "Sentinel-Ops/0.1"})
            resp.raise_for_status()
            data = resp.json()
            return [
                m["name"].replace("models/", "")
                for m in data.get("models", [])
                if "generateContent" in m.get("supportedGenerationMethods", [])
            ]
    except Exception as e:
        console.print(f"[bold red]Failed to fetch Gemini model catalog: {e}[/bold red]")
        return []


def list_available_gemini_models() -> List[str]:
    """Queries the Gemini API to list models supporting content generation."""
    if not settings.GEMINI_API_KEY:
        return []
    url = f"https://generativelanguage.googleapis.com/v1beta/models?key={settings.GEMINI_API_KEY}"
    req = urllib.request.Request(url, headers={"User-Agent": "Sentinel-Ops/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            data = json.loads(resp.read().decode())
            return [
                m["name"].replace("models/", "")
                for m in data.get("models", [])
                if "generateContent" in m.get("supportedGenerationMethods", [])
            ]
    except Exception as e:
        console.print(f"[bold red]Failed to fetch Gemini model catalog: {e}[/bold red]")
        return []


async def async_run_structured_output_smoke_test(model_name: Optional[str] = None) -> ProbeResult:
    """Executes non-blocking async structured output smoke test via ainvoke."""
    target_model = model_name or settings.GEMINI_MODEL_SUPERVISOR
    llm = get_chat_model(role="supervisor", model_name=target_model)
    structured_llm = llm.with_structured_output(SmokeTestSchema)
    prompt = "Telemetry alert: checkout-service responded with HTTP status 200. Parse into schema."
    t0 = time.perf_counter()
    result: SmokeTestSchema = await asyncio.wait_for(
        structured_llm.ainvoke(prompt), timeout=settings.PER_LLM_TIMEOUT_SECONDS
    )
    elapsed_ms = (time.perf_counter() - t0) * 1000
    assert result.service_name == "checkout-service", f"Unexpected service: {result.service_name}"
    assert result.is_healthy is True, f"Expected is_healthy=True, got {result.is_healthy}"
    assert result.observed_code == 200, f"Expected code=200, got {result.observed_code}"
    return ProbeResult(
        test_passed=True,
        model_name=target_model,
        greeting="Structured output contract verified",
        detected_platform="Google Gemini API",
        latency_ms=round(elapsed_ms, 2),
    )


def run_structured_output_smoke_test(model_name: Optional[str] = None) -> ProbeResult:
    """Executes a structured output smoke test to verify function calling / JSON schema."""
    target_model = model_name or settings.GEMINI_MODEL_SUPERVISOR
    llm = get_chat_model(role="supervisor", model_name=target_model)
    structured_llm = llm.with_structured_output(SmokeTestSchema)

    prompt = "Telemetry alert: checkout-service responded with HTTP status 200. Parse into schema."
    
    t0 = time.perf_counter()
    result: SmokeTestSchema = structured_llm.invoke(prompt)
    elapsed_ms = (time.perf_counter() - t0) * 1000

    assert result.service_name == "checkout-service", f"Unexpected service: {result.service_name}"
    assert result.is_healthy is True, f"Expected is_healthy=True, got {result.is_healthy}"
    assert result.observed_code == 200, f"Expected code=200, got {result.observed_code}"

    return ProbeResult(
        test_passed=True,
        model_name=target_model,
        greeting="Structured output contract verified",
        detected_platform="Google Gemini API",
        latency_ms=round(elapsed_ms, 2)
    )


def probe_and_display() -> bool:
    """Full CLI probe routine displaying verified models and smoke test."""
    console.print("[bold cyan]════════════════════════════════════════════════════════════[/bold cyan]")
    console.print("[bold white]Sentinel-Ops: Pre-Flight LLM & Model Capabilities Probe[/bold white]")
    console.print("[bold cyan]════════════════════════════════════════════════════════════[/bold cyan]")

    if not settings.GEMINI_API_KEY:
        console.print("[bold red]❌ ERROR: GEMINI_API_KEY is not set in environment or .env![/bold red]")
        return False

    console.print("[green]✔ GEMINI_API_KEY found[/green] (mask: " + settings.GEMINI_API_KEY[:6] + "..." + settings.GEMINI_API_KEY[-4:] + ")")
    
    # 1. Catalog check
    models = list_available_gemini_models()
    console.print(f"[green]✔ Model catalog queried successfully[/green] ({len(models)} models available)")

    table = Table(title="Verified Active Models", show_header=True, header_style="bold magenta")
    table.add_column("Model ID", style="cyan")
    table.add_column("Configured Role", style="yellow")
    table.add_column("Status", style="green")

    supervisor_model = settings.GEMINI_MODEL_SUPERVISOR
    synthesizer_model = settings.GEMINI_MODEL_SYNTHESIZER

    table.add_row(supervisor_model, "Supervisor / Specialists", "ACTIVE" if supervisor_model in models else "FALLBACK")
    table.add_row(synthesizer_model, "Synthesizer / Reviewer", "ACTIVE" if synthesizer_model in models else "FALLBACK")
    console.print(table)

    # 2. Structured Output Smoke Test
    console.print(f"\n[cyan]Running structured output smoke test on '{supervisor_model}'...[/cyan]")
    try:
        smoke = run_structured_output_smoke_test(supervisor_model)
        console.print(f"[bold green]✔ Smoke test PASSED[/bold green] (Structured Pydantic Output verified in {smoke.latency_ms}ms)")
        return True
    except Exception as e:
        console.print(f"[bold red]❌ Smoke test FAILED: {e}[/bold red]")
        return False


if __name__ == "__main__":
    probe_and_display()
