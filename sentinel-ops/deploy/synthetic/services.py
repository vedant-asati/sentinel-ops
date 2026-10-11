import asyncio
import json
import os
import secrets
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse

app = FastAPI(title="Synthetic Microservices & Telemetry Sandbox")

SERVICE_NAME = os.getenv("SERVICE_NAME", "checkout-service")
PORT = int(os.getenv("PORT", "8001"))
TEMPO_OTLP_URL = os.getenv("TEMPO_OTLP_URL", "http://tempo:4318/v1/traces")

DOWNSTREAM_URLS = {
    "cart-service": os.getenv("CART_URL", "http://cart-service:8002"),
    "pricing-service": os.getenv("PRICING_URL", "http://pricing-service:8003"),
    "payment-service": os.getenv("PAYMENT_URL", "http://payment-service:8004"),
}

HISTOGRAM_BUCKETS = (0.1, 0.5, 1.0, 5.0)

FAULT_STATE: Dict[str, Any] = {
    "db_pool_active": 1.0,
    "db_pool_size": 100.0,
    "db_pool_acquire_timeouts_total": 0,
    "upstream_connect_timeouts_total": 0,
    "cpu_saturation": 0.15,
    "memory_usage": 0.35,
    "container_restarts": 0,
    "latency_p95": 0.025,
    "error_rate": 0.01,
    "active_fault": None,
    "duration_buckets": {0.1: 0, 0.5: 0, 1.0: 0, 5.0: 0, "+Inf": 0},
    "duration_sum": 0.0,
    "duration_count": 0,
}

_POOL_SEMAPHORE = asyncio.Semaphore(100)


def record_duration_observation(duration_sec: float) -> None:
    """Records a request latency observation into cumulative Prometheus histogram buckets."""
    FAULT_STATE["duration_sum"] += duration_sec
    FAULT_STATE["duration_count"] += 1
    for le in HISTOGRAM_BUCKETS:
        if duration_sec <= le:
            FAULT_STATE["duration_buckets"][le] += 1
    FAULT_STATE["duration_buckets"]["+Inf"] += 1


def build_otlp_span_payload(
    trace_id: str,
    span_id: str,
    parent_span_id: Optional[str],
    service_name: str,
    operation_name: str,
    start_ns: int,
    end_ns: int,
    error_message: Optional[str] = None,
) -> Dict[str, Any]:
    """Constructs a lightweight OTLP/HTTP JSON trace span payload without heavy SDK dependencies."""
    span_obj: Dict[str, Any] = {
        "traceId": trace_id,
        "spanId": span_id,
        "name": operation_name,
        "kind": 2 if parent_span_id else 1,
        "startTimeUnixNano": str(start_ns),
        "endTimeUnixNano": str(end_ns),
        "attributes": [
            {"key": "operation", "value": {"stringValue": operation_name}},
        ],
        "status": {"code": 2 if error_message else 1, "message": error_message or ""},
    }
    if parent_span_id:
        span_obj["parentSpanId"] = parent_span_id

    return {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [{"key": "service.name", "value": {"stringValue": service_name}}]
                },
                "scopeSpans": [
                    {
                        "scope": {"name": "sentinel-ops-synthetic"},
                        "spans": [span_obj],
                    }
                ],
            }
        ]
    }


def _post_otlp_sync(payload: Dict[str, Any]) -> bool:
    if not TEMPO_OTLP_URL:
        return False
    req = urllib.request.Request(
        TEMPO_OTLP_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=0.8) as resp:
            return 200 <= resp.status < 300
    except Exception:
        return False


def _http_get_sync(url: str, headers: Dict[str, str], timeout: float = 1.5) -> tuple[int, Dict[str, Any]]:
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            return resp.status, body
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode("utf-8"))
        except Exception:
            body = {"error": str(e)}
        return e.code, body
    except Exception as e:
        return 504, {"error": str(e)}


@app.get("/health")
def health():
    return {"status": "ok", "service": SERVICE_NAME}


@app.post("/fault/inject")
def inject_fault(fault_type: str):
    """Chaos fault injection for reproducible scenarios."""
    global _POOL_SEMAPHORE
    if fault_type == "db_pool_exhaustion":
        FAULT_STATE["db_pool_active"] = 2.0
        FAULT_STATE["db_pool_size"] = 2.0
        FAULT_STATE["error_rate"] = 0.28
        FAULT_STATE["active_fault"] = "db_pool_exhaustion"
        _POOL_SEMAPHORE = asyncio.Semaphore(0)
    elif fault_type == "cpu_saturation":
        FAULT_STATE["cpu_saturation"] = 0.98
        FAULT_STATE["latency_p95"] = 3.92
        FAULT_STATE["active_fault"] = "cpu_saturation"
    elif fault_type == "upstream_connect_timeout":
        FAULT_STATE["error_rate"] = 0.65
        FAULT_STATE["active_fault"] = "upstream_connect_timeout"
    elif fault_type == "memory_leak":
        FAULT_STATE["memory_usage"] = 0.95
        FAULT_STATE["container_restarts"] = 4
        FAULT_STATE["active_fault"] = "memory_leak"
    elif fault_type == "recover":
        FAULT_STATE["db_pool_active"] = 1.0
        FAULT_STATE["db_pool_size"] = 100.0
        FAULT_STATE["db_pool_acquire_timeouts_total"] = 0
        FAULT_STATE["upstream_connect_timeouts_total"] = 0
        FAULT_STATE["cpu_saturation"] = 0.15
        FAULT_STATE["memory_usage"] = 0.35
        FAULT_STATE["container_restarts"] = 0
        FAULT_STATE["latency_p95"] = 0.025
        FAULT_STATE["error_rate"] = 0.01
        FAULT_STATE["active_fault"] = None
        _POOL_SEMAPHORE = asyncio.Semaphore(100)
    else:
        raise HTTPException(status_code=400, detail=f"Unknown fault type: {fault_type}")
    return {"status": "injected", "state": {k: v for k, v in FAULT_STATE.items() if k != "duration_buckets"}}


@app.get("/work")
async def downstream_work(
    request: Request,
    response: Response,
    x_trace_id: Optional[str] = Header(default=None),
    x_parent_span_id: Optional[str] = Header(default=None),
):
    """Handles downstream dependency work with pool acquisition timing & span emission."""
    trace_id = x_trace_id or secrets.token_hex(16)
    span_id = secrets.token_hex(8)
    start_ns = time.time_ns()
    t0 = time.perf_counter()

    error_msg: Optional[str] = None
    op_name = f"{SERVICE_NAME}.process"
    status_code = 200

    fault = FAULT_STATE.get("active_fault")
    if fault == "db_pool_exhaustion":
        op_name = "db.connection.acquire"
        try:
            await asyncio.wait_for(_POOL_SEMAPHORE.acquire(), timeout=0.05)
        except asyncio.TimeoutError:
            FAULT_STATE["db_pool_acquire_timeouts_total"] += 1
            error_msg = "TimeoutError"
            status_code = 504
    elif fault == "upstream_connect_timeout":
        op_name = "rpc.connect"
        await asyncio.sleep(0.05)
        FAULT_STATE["upstream_connect_timeouts_total"] += 1
        error_msg = "TimeoutError"
        status_code = 502
    elif fault == "cpu_saturation":
        op_name = "pricing.compute_discount"
        await asyncio.sleep(0.08)
    else:
        await asyncio.sleep(0.01)

    elapsed_sec = time.perf_counter() - t0
    record_duration_observation(max(elapsed_sec, FAULT_STATE["latency_p95"] if fault == "cpu_saturation" else elapsed_sec))
    end_ns = max(start_ns + 1_000_000, time.time_ns())

    otlp_payload = build_otlp_span_payload(
        trace_id=trace_id,
        span_id=span_id,
        parent_span_id=x_parent_span_id,
        service_name=SERVICE_NAME,
        operation_name=op_name,
        start_ns=start_ns,
        end_ns=end_ns,
        error_message=error_msg,
    )
    await asyncio.to_thread(_post_otlp_sync, otlp_payload)

    if status_code != 200:
        return JSONResponse(
            status_code=status_code,
            headers={"X-Trace-Id": trace_id},
            content={
                "status": "error",
                "service": SERVICE_NAME,
                "trace_id": trace_id,
                "operation": op_name,
                "error": error_msg,
            },
        )
    response.headers["X-Trace-Id"] = trace_id
    return {"status": "ok", "service": SERVICE_NAME, "trace_id": trace_id, "span_id": span_id}


@app.get("/checkout")
async def checkout_endpoint(x_trace_id: Optional[str] = Header(default=None)):
    """Simulates a checkout-service transaction calling cart, pricing, and payment downstream."""
    trace_id = x_trace_id or secrets.token_hex(16)
    root_span_id = secrets.token_hex(8)
    start_ns = time.time_ns()
    t0 = time.perf_counter()

    downstream_headers = {"X-Trace-Id": trace_id, "X-Parent-Span-Id": root_span_id}
    calls: Dict[str, Any] = {}
    overall_status = 200
    fault_err: Optional[str] = None

    for dep_name, base_url in DOWNSTREAM_URLS.items():
        code, body = await asyncio.to_thread(_http_get_sync, f"{base_url}/work", downstream_headers)
        calls[dep_name] = {"status_code": code, "body": body}
        if code >= 500:
            overall_status = code
            fault_err = f"Downstream {dep_name} returned HTTP {code}"

    elapsed_sec = time.perf_counter() - t0
    record_duration_observation(elapsed_sec)
    end_ns = max(start_ns + 1_000_000, time.time_ns())

    otlp_payload = build_otlp_span_payload(
        trace_id=trace_id,
        span_id=root_span_id,
        parent_span_id=None,
        service_name=SERVICE_NAME,
        operation_name="GET /checkout",
        start_ns=start_ns,
        end_ns=end_ns,
        error_message=fault_err,
    )
    await asyncio.to_thread(_post_otlp_sync, otlp_payload)

    return JSONResponse(
        status_code=overall_status,
        headers={"X-Trace-Id": trace_id},
        content={"trace_id": trace_id, "service": SERVICE_NAME, "calls": calls},
    )


@app.get("/metrics", response_class=PlainTextResponse)
def get_metrics():
    """Emits Prometheus text format metrics including gauges, timeout counters, and cumulative histograms."""
    lines = [
        "# HELP payment_db_pool_active Active DB connections in pool",
        "# TYPE payment_db_pool_active gauge",
        f'payment_db_pool_active{{service="{SERVICE_NAME}"}} {FAULT_STATE["db_pool_active"]}',
        "# HELP payment_db_pool_size Total DB connection pool capacity",
        "# TYPE payment_db_pool_size gauge",
        f'payment_db_pool_size{{service="{SERVICE_NAME}"}} {FAULT_STATE["db_pool_size"]}',
        "# HELP payment_db_pool_acquire_timeouts_total Total DB connection pool acquisition timeouts",
        "# TYPE payment_db_pool_acquire_timeouts_total counter",
        f'payment_db_pool_acquire_timeouts_total{{service="{SERVICE_NAME}"}} {FAULT_STATE["db_pool_acquire_timeouts_total"]}',
        "# HELP upstream_connect_timeouts_total Total upstream RPC connect timeouts",
        "# TYPE upstream_connect_timeouts_total counter",
        f'upstream_connect_timeouts_total{{service="{SERVICE_NAME}"}} {FAULT_STATE["upstream_connect_timeouts_total"]}',
        "# HELP payment_error_rate Service request error rate ratio",
        "# TYPE payment_error_rate gauge",
        f'payment_error_rate{{service="{SERVICE_NAME}"}} {FAULT_STATE["error_rate"]}',
        "# HELP container_cpu_usage_seconds_total Container CPU saturation",
        "# TYPE container_cpu_usage_seconds_total gauge",
        f'container_cpu_usage_seconds_total{{container="{SERVICE_NAME}"}} {FAULT_STATE["cpu_saturation"]}',
        "# HELP container_memory_usage_ratio Container memory saturation ratio",
        "# TYPE container_memory_usage_ratio gauge",
        f'container_memory_usage_ratio{{container="{SERVICE_NAME}"}} {FAULT_STATE["memory_usage"]}',
        "# HELP container_restart_count Total container restarts",
        "# TYPE container_restart_count counter",
        f'container_restart_count{{container="{SERVICE_NAME}"}} {FAULT_STATE["container_restarts"]}',
        "# HELP http_request_duration_seconds Request latency histogram",
        "# TYPE http_request_duration_seconds histogram",
    ]
    for le, count in FAULT_STATE["duration_buckets"].items():
        lines.append(f'http_request_duration_seconds_bucket{{service="{SERVICE_NAME}",le="{le}"}} {count}')
    lines.append(f'http_request_duration_seconds_sum{{service="{SERVICE_NAME}"}} {FAULT_STATE["duration_sum"]:.6f}')
    lines.append(f'http_request_duration_seconds_count{{service="{SERVICE_NAME}"}} {FAULT_STATE["duration_count"]}')
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT)
