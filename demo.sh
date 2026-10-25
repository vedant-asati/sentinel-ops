#!/usr/bin/env bash
# ==============================================================================
# Sentinel-Ops Platform: One-Command Live Showcase & Chaos Verification
# ==============================================================================
set -e

# Export uv path if installed in ~/.local/bin
export PATH="$HOME/.local/bin:$PATH"

# Colors for terminal output
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Determine repository root and sentinel-ops directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -d "$SCRIPT_DIR/sentinel-ops" ]; then
    SENTINEL_DIR="$SCRIPT_DIR/sentinel-ops"
else
    SENTINEL_DIR="$SCRIPT_DIR"
fi

# Ensure sandbox ALWAYS recovers even if CLI exits non-zero (abstention / operational failure)
cleanup() {
    echo -e "\n${YELLOW}[Cleanup] Recovering Telemetry Sandbox to Healthy Baseline...${NC}"
    (cd "$SENTINEL_DIR" && uv run python -m sentinel_ops.chaos recover >/dev/null 2>&1) || true
}
trap cleanup EXIT

cd "$SENTINEL_DIR"

echo -e "${CYAN}${BOLD}════════════════════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}Sentinel-Ops Platform: Autonomous AI SRE Live Demonstration${NC}"
echo -e "${CYAN}${BOLD}════════════════════════════════════════════════════════════════════════════${NC}\n"

# Step 1: Verify Sandbox Telemetry Services
echo -e "${YELLOW}[Step 1/6] Inspecting Local Docker Telemetry Sandbox Health...${NC}"
if ! curl -s "http://localhost:8001/health" > /dev/null 2>&1; then
    echo -e "${YELLOW}Notice: Docker telemetry sandbox services are starting or offline.${NC}"
    echo -e "Attempting to bring up sandbox via docker compose..."
    (cd deploy && docker compose up -d) || true
    sleep 3
fi

uv run python -m sentinel_ops.chaos status
echo ""

# Step 2: Inject Live Fault (Payment DB Pool Exhaustion) & Exercise Real /checkout Traffic
echo -e "${YELLOW}[Step 2/6] Injecting Chaos Fault: 'db_pool_exhaustion' into payment-service & driving live /checkout traffic...${NC}"
uv run python -m sentinel_ops.chaos inject payment-service db_pool_exhaustion
TRACE_OUT=$(uv run python -m sentinel_ops.chaos traffic --count 3 || true)
echo "$TRACE_OUT"
CAPTURED_TRACE_ID=$(echo "$TRACE_OUT" | grep -oE '[0-9a-f]{32}' | tail -n 1 || true)
echo ""

# Step 3: Wait for Prometheus Scrape & Tempo Ingestion
echo -e "${YELLOW}[Step 3/6] Awaiting Prometheus Scrape (10s for 2x scrape delta) and Querying Live Metric Pipeline...${NC}"
sleep 10

if curl -s "http://localhost:59090/-/healthy" > /dev/null 2>&1; then
    echo -e "${GREEN}✔ Prometheus Scrape Target Healthy on :59090. Querying 'payment_db_pool_active' & timeouts:${NC}"
    curl -s "http://localhost:59090/api/v1/query?query=payment_db_pool_active" | jq '.data.result[] | {service: .metric.service, value: .value[1]}' 2>/dev/null || true
    curl -s "http://localhost:59090/api/v1/query?query=payment_db_pool_acquire_timeouts_total" | jq '.data.result[] | {service: .metric.service, timeouts: .value[1]}' 2>/dev/null || true
else
    echo -e "${YELLOW}Prometheus offline; live sandbox checks skipped cleanly.${NC}"
fi
echo ""

# Step 4: Run Sentinel-Ops Investigation Triage (Live Telemetry Probing)
echo -e "${YELLOW}[Step 4/6] Executing Sentinel-Ops Multi-Agent LangGraph Triage against Live Telemetry...${NC}"
if [ -n "$CAPTURED_TRACE_ID" ]; then
    uv run sentinel-ops --live --target-service checkout-service --trace-id "$CAPTURED_TRACE_ID" --auto-approve
else
    uv run sentinel-ops --live --target-service checkout-service --auto-approve
fi
echo ""

# Step 5: DORA Operational Impact Report
echo -e "${YELLOW}[Step 5/6] Generating DORA Operational Impact & MTTR Acceleration Report...${NC}"
uv run python -m sentinel_ops.analytics.dora
echo ""

# Step 6: Sandbox Recovery
echo -e "${YELLOW}[Step 6/6] Recovering Telemetry Sandbox to Healthy Baseline...${NC}"
uv run python -m sentinel_ops.chaos recover
echo ""

echo -e "${GREEN}${BOLD}✔ Sentinel-Ops Live Demonstration completed successfully!${NC}"
echo -e "To launch the Web Cyber Command Center, run:"
echo -e "  ${CYAN}cd sentinel-ops && uv run uvicorn sentinel_ops.server.app:app --host 0.0.0.0 --port 8000${NC}"
echo -e "Then open ${BOLD}http://localhost:8000${NC} in your browser.\n"
