import os
import time
from typing import Dict, Any
from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse

app = FastAPI(title="Synthetic Microservices & Telemetry Sandbox")

SERVICE_NAME = os.getenv("SERVICE_NAME", "checkout-service")
PORT = int(os.getenv("PORT", "8001"))

FAULT_STATE: Dict[str, Any] = {
    "db_pool_active": 1.0,
    "db_pool_size": 100.0,
    "cpu_saturation": 0.15,
    "latency_p95": 0.025,
    "error_rate": 0.01,
    "active_fault": None,
}


@app.get("/health")
def health():
    return {"status": "ok", "service": SERVICE_NAME}


@app.post("/fault/inject")
def inject_fault(fault_type: str):
    """Chaos fault injection for reproducible scenarios."""
    if fault_type == "db_pool_exhaustion":
        FAULT_STATE["db_pool_active"] = 2.0
        FAULT_STATE["db_pool_size"] = 2.0
        FAULT_STATE["error_rate"] = 0.28
        FAULT_STATE["active_fault"] = "db_pool_exhaustion"
    elif fault_type == "cpu_saturation":
        FAULT_STATE["cpu_saturation"] = 0.98
        FAULT_STATE["latency_p95"] = 3.92
        FAULT_STATE["active_fault"] = "cpu_saturation"
    elif fault_type == "recover":
        FAULT_STATE["db_pool_active"] = 1.0
        FAULT_STATE["db_pool_size"] = 100.0
        FAULT_STATE["cpu_saturation"] = 0.15
        FAULT_STATE["latency_p95"] = 0.025
        FAULT_STATE["error_rate"] = 0.01
        FAULT_STATE["active_fault"] = None
    else:
        raise HTTPException(status_code=400, detail=f"Unknown fault type: {fault_type}")
    return {"status": "injected", "state": FAULT_STATE}


@app.get("/metrics", response_class=PlainTextResponse)
def get_metrics():
    """Emits Prometheus text format metrics."""
    now = time.time()
    lines = [
        f'# HELP payment_db_pool_active Active DB connections in pool',
        f'# TYPE payment_db_pool_active gauge',
        f'payment_db_pool_active{{service="{SERVICE_NAME}"}} {FAULT_STATE["db_pool_active"]}',
        f'# HELP payment_db_pool_size Total DB connection pool capacity',
        f'# TYPE payment_db_pool_size gauge',
        f'payment_db_pool_size{{service="{SERVICE_NAME}"}} {FAULT_STATE["db_pool_size"]}',
        f'# HELP container_cpu_usage_seconds_total Container CPU saturation',
        f'# TYPE container_cpu_usage_seconds_total gauge',
        f'container_cpu_usage_seconds_total{{container="{SERVICE_NAME}"}} {FAULT_STATE["cpu_saturation"]}',
        f'# HELP http_request_duration_seconds_bucket P95 request duration',
        f'# TYPE http_request_duration_seconds_bucket gauge',
        f'http_request_duration_seconds_bucket{{service="{SERVICE_NAME}",le="0.95"}} {FAULT_STATE["latency_p95"]}',
    ]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT)
