#!/usr/bin/env bash
# ==============================================================================
# SENTINEL-X Unified Local Shutdown Script (Linux/macOS)
# Cleanly terminates FastAPI backend (port 8000), Vite dev server (port 5173), and agents
# ==============================================================================

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "=========================================================="
echo "  SENTINEL-X SOC Platform — Graceful Shutdown"
echo "=========================================================="

if [ -f "${ROOT_DIR}/.venv/bin/python" ]; then
    "${ROOT_DIR}/.venv/bin/python" "${ROOT_DIR}/launcher.py" stop
else
    python3 "${ROOT_DIR}/launcher.py" stop
fi

echo "[+] All services successfully stopped."
