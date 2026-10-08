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

# Step 2: Inject Live Fault (Payment DB Pool Exhaustion)
echo -e "${YELLOW}[Step 2/6] Injecting Chaos Fault: 'db_pool_exhaustion' into payment-service...${NC}"
uv run python -m sentinel_ops.chaos inject payment-service db_pool_exhaustion
echo ""

# Step 3: Wait for Prometheus Scrape and Verify Metric Telemetry
echo -e "${YELLOW}[Step 3/6] Awaiting Prometheus Scrape (3s) and Querying Live Metric Pipeline...${NC}"
sleep 3

if curl -s "http://localhost:59090/-/healthy" > /dev/null 2>&1; then
    echo -e "${GREEN}✔ Prometheus Scrape Target Healthy on :59090. Querying 'payment_db_pool_active':${NC}"
    curl -s "http://localhost:59090/api/v1/query?query=payment_db_pool_active" | jq '.data.result[] | {service: .metric.service, value: .value[1]}' 2>/dev/null || true
else
    echo -e "${YELLOW}Prometheus query skipped (using simulated telemetry adapter).${NC}"
fi
echo ""

# Step 4: Run Sentinel-Ops Investigation Triage
echo -e "${YELLOW}[Step 4/6] Executing Sentinel-Ops Multi-Agent LangGraph Triage (Case 01)...${NC}"
uv run sentinel-ops --case-id case_01 --auto-approve
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
