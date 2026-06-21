#!/usr/bin/env bash
# run.sh — build, start, test, and tear down the Project Tycho acceptance suite.
#
# Prerequisites:
#   - Docker Desktop running
#   - uv installed (https://github.com/astral-sh/uv)
#
# Usage:
#   cd acceptance-tests
#   ./run.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Tear down on exit (success or failure).
cleanup() {
    echo ""
    echo "==> Tearing down services..."
    docker compose down --remove-orphans
}
trap cleanup EXIT

# -------------------------------------------------------------------------
# 1. Build image and start the Visualiser service.
# -------------------------------------------------------------------------
echo "==> Building and starting the Visualiser service..."
docker compose up -d --build

# -------------------------------------------------------------------------
# 2. Wait for the Visualiser health check (up to 60 s).
# -------------------------------------------------------------------------
echo "==> Waiting for the Visualiser to become healthy..."
ATTEMPTS=0
MAX_ATTEMPTS=20
until curl -sf http://localhost:8765/health > /dev/null 2>&1; do
    ATTEMPTS=$((ATTEMPTS + 1))
    if [ "$ATTEMPTS" -ge "$MAX_ATTEMPTS" ]; then
        echo "ERROR: Visualiser did not become healthy within $((MAX_ATTEMPTS * 3)) seconds."
        echo "--- Docker Compose logs ---"
        docker compose logs
        exit 1
    fi
    echo "  waiting... ($ATTEMPTS/$MAX_ATTEMPTS)"
    sleep 3
done
echo "  Visualiser is healthy."

# -------------------------------------------------------------------------
# 3. Install test dependencies (cached after first run).
# -------------------------------------------------------------------------
echo "==> Installing test dependencies..."
uv sync --quiet

# -------------------------------------------------------------------------
# 4. Run the acceptance tests.
# -------------------------------------------------------------------------
echo "==> Running acceptance tests..."
echo ""
uv run pytest test_acceptance.py -v
