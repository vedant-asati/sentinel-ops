import argparse
import httpx
from rich.console import Console
from rich.table import Table

console = Console()

SERVICE_PORTS = {
    "checkout-service": 8001,
    "cart-service": 8002,
    "pricing-service": 8003,
    "payment-service": 8004,
}


def inject_fault(service: str, fault_type: str):
    """Injects chaos fault into target service."""
    port = SERVICE_PORTS.get(service)
    if not port:
        console.print(f"[bold red]Unknown service: {service}[/bold red]")
        return

    url = f"http://localhost:{port}/fault/inject?fault_type={fault_type}"
    try:
        resp = httpx.post(url, timeout=5.0)
        resp.raise_for_status()
        console.print(f"[bold green]✔ Injected '{fault_type}' into {service} successfully.[/bold green]")
        console.print(f"[cyan]Current state:[/cyan] {resp.json().get('state')}")
    except Exception as e:
        console.print(f"[bold red]Failed to inject fault into {service}: {e}[/bold red]")


def recover_all():
    """Recovers all microservices to healthy baseline state."""
    console.print("[bold yellow]Recovering all sandbox microservices to healthy baseline...[/bold yellow]")
    for svc, port in SERVICE_PORTS.items():
        try:
            resp = httpx.post(f"http://localhost:{port}/fault/inject?fault_type=recover", timeout=5.0)
            console.print(f"  ✔ {svc} recovered.")
        except Exception as e:
            console.print(f"  [red]✖ {svc} recovery error: {e}[/red]")


def print_status():
    """Displays health and active fault state across all microservices."""
    table = Table(title="Sandbox Microservices Telemetry Status", show_header=True, header_style="bold magenta")
    table.add_column("Service", style="cyan", width=18)
    table.add_column("Port", style="white", width=8)
    table.add_column("Health", style="bold green", width=10)
    table.add_column("Active Fault", style="yellow", width=22)

    for svc, port in SERVICE_PORTS.items():
        try:
            resp = httpx.get(f"http://localhost:{port}/health", timeout=2.0)
            health_str = "[green]OK[/green]" if resp.status_code == 200 else "[red]FAIL[/red]"
            
            # Check metrics for active fault
            m_resp = httpx.get(f"http://localhost:{port}/metrics", timeout=2.0)
            fault = "None (Healthy)"
            if "payment_db_pool_active{service=\"payment-service\"} 2.0" in m_resp.text:
                fault = "[bold red]db_pool_exhaustion[/bold red]"
            elif "container_cpu_usage_seconds_total{container=\"pricing-service\"} 0.98" in m_resp.text:
                fault = "[bold red]cpu_saturation[/bold red]"
            
            table.add_row(svc, str(port), health_str, fault)
        except Exception:
            table.add_row(svc, str(port), "[red]DOWN[/red]", "[dim]Unreachable[/dim]")

    console.print(table)


def main():
    parser = argparse.ArgumentParser(description="Sentinel-Ops Chaos & Fault Injection Controller")
    subparsers = parser.add_subparsers(dest="command")

    # inject command
    inject_parser = subparsers.add_parser("inject", help="Inject chaos fault into service")
    inject_parser.add_argument("service", choices=list(SERVICE_PORTS.keys()), help="Target microservice")
    inject_parser.add_argument("fault", choices=["db_pool_exhaustion", "cpu_saturation", "recover"], help="Fault scenario")

    # status command
    subparsers.add_parser("status", help="Show sandbox microservices status")

    # recover command
    subparsers.add_parser("recover", help="Reset all services to normal baseline")

    args = parser.parse_args()
    if args.command == "inject":
        inject_fault(args.service, args.fault)
    elif args.command == "status":
        print_status()
    elif args.command == "recover":
        recover_all()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
