#!/usr/bin/env python3
"""Multi-fault live Docker Compose verifier with positive and negative controls.

Verifies live Prometheus (:59090) and Tempo (:53201) collection against synthetic
microservices (:8001-:8004) across healthy baseline, busy-without-wait negative
controls, and injected payment/pricing root-cause faults.
"""

from datetime import datetime, timezone
import sys
import time
import httpx

from benchmarks.runner import SentinelOpsLangGraphAgent


SERVICES = {
    "checkout-service": "http://localhost:8001",
    "cart-service": "http://localhost:8002",
    "pricing-service": "http://localhost:8003",
    "payment-service": "http://localhost:8004",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def recover_all(client: httpx.Client) -> None:
    for name, url in SERVICES.items():
        resp = client.post(f"{url}/fault/inject?fault_type=recover", timeout=5.0)
        resp.raise_for_status()


def inject_fault(client: httpx.Client, service: str, fault_type: str) -> None:
    resp = client.post(f"{SERVICES[service]}/fault/inject?fault_type={fault_type}", timeout=5.0)
    resp.raise_for_status()


def generate_checkout_traffic(client: httpx.Client, count: int = 5) -> str | None:
    trace_id = None
    for _ in range(count):
        resp = client.get(f"{SERVICES['checkout-service']}/checkout", timeout=10.0)
        tid = resp.headers.get("X-Trace-Id")
        if tid:
            trace_id = tid
    return trace_id


def check_case(agent: SentinelOpsLangGraphAgent, name: str, case: dict, expected_status: str, expected_svc: str) -> None:
    res = agent.diagnose(case)
    status = res.get("terminal_status")
    svc = res.get("diagnosed_root_cause")
    mech = res.get("mechanism")
    print(f"[{name}] status={status} root_cause={svc} mechanism={mech}")
    if status != expected_status or (expected_svc and svc != expected_svc):
        raise AssertionError(
            f"{name} FAILED: expected ({expected_status}, {expected_svc}), "
            f"got ({status}, {svc}, mech={mech}, reason={res.get('failure_reason')})"
        )


def main() -> int:
    agent = SentinelOpsLangGraphAgent()
    with httpx.Client() as client:
        try:
            # Check sandbox availability first
            for name, url in SERVICES.items():
                client.get(f"{url}/metrics", timeout=5.0).raise_for_status()

            # Negative Control 1: Healthy traffic
            recover_all(client)
            healthy_tid = generate_checkout_traffic(client, count=4)
            time.sleep(12.0)
            check_case(
                agent,
                "Negative 1 (Healthy Baseline)",
                {
                    "id": "live_neg_healthy",
                    "alert_text": "Routine checkout canary check",
                    "incident_timestamp": now_iso(),
                    "target_service": "checkout-service",
                    "trace_id": healthy_tid,
                    "mock_telemetry": None,
                },
                expected_status="INSUFFICIENT_EVIDENCE",
                expected_svc="unknown",
            )

            # Negative Control 2: Busy DB pool (2/2) with zero acquire wait timeouts (no traffic)
            recover_all(client)
            time.sleep(6.0)
            inject_fault(client, "payment-service", "db_pool_exhaustion")
            time.sleep(12.0)
            check_case(
                agent,
                "Negative 2 (Busy Pool Without Wait Contention)",
                {
                    "id": "live_neg_busy_pool",
                    "alert_text": "Payment connection pool occupancy at 100%",
                    "incident_timestamp": now_iso(),
                    "target_service": "checkout-service",
                    "mock_telemetry": None,
                },
                expected_status="INSUFFICIENT_EVIDENCE",
                expected_svc="unknown",
            )

            # Positive 1: payment-service db_pool_exhaustion (with wait timeouts + trace)
            tid_pool = generate_checkout_traffic(client, count=6)
            time.sleep(12.0)
            check_case(
                agent,
                "Positive 1 (Payment DB Pool Exhaustion - Targeted)",
                {
                    "id": "live_pos_db_pool",
                    "alert_text": f"Checkout 504 timeout on trace {tid_pool}",
                    "incident_timestamp": now_iso(),
                    "target_service": "checkout-service",
                    "trace_id": tid_pool,
                    "mock_telemetry": None,
                },
                expected_status="SUPPORTED_DIAGNOSIS",
                expected_svc="payment-service",
            )

            # Positive 2: payment-service upstream_connect_timeout
            recover_all(client)
            time.sleep(6.0)
            inject_fault(client, "payment-service", "upstream_connect_timeout")
            tid_upstream = generate_checkout_traffic(client, count=6)
            time.sleep(12.0)
            check_case(
                agent,
                "Positive 2 (Payment Upstream Connect Timeout)",
                {
                    "id": "live_pos_upstream_timeout",
                    "alert_text": f"Checkout 502 downstream failure trace {tid_upstream}",
                    "incident_timestamp": now_iso(),
                    "target_service": "checkout-service",
                    "trace_id": tid_upstream,
                    "mock_telemetry": None,
                },
                expected_status="SUPPORTED_DIAGNOSIS",
                expected_svc="payment-service",
            )

            # Positive 3: pricing-service cpu_saturation
            recover_all(client)
            time.sleep(6.0)
            inject_fault(client, "pricing-service", "cpu_saturation")
            tid_cpu = generate_checkout_traffic(client, count=6)
            time.sleep(12.0)
            check_case(
                agent,
                "Positive 3 (Pricing CPU Saturation)",
                {
                    "id": "live_pos_cpu_saturation",
                    "alert_text": f"High p95 latency on checkout trace {tid_cpu}",
                    "incident_timestamp": now_iso(),
                    "target_service": "checkout-service",
                    "trace_id": tid_cpu,
                    "mock_telemetry": None,
                },
                expected_status="SUPPORTED_DIAGNOSIS",
                expected_svc="pricing-service",
            )

            print("\nALL LIVE SANDBOX POSITIVE & NEGATIVE CONTROLS PASSED!")
            return 0
        finally:
            try:
                recover_all(client)
            except Exception:
                pass


if __name__ == "__main__":
    sys.exit(main())
