#!/usr/bin/env bash
# ==============================================================================
# SENTINEL-X Unified Local Startup Script (Linux/macOS)
# Starts FastAPI backend (port 8000) and Vite frontend dev server (port 5173)
# ==============================================================================

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "=========================================================="
echo "  SENTINEL-X SOC Platform — Local Developer Launcher"
echo "=========================================================="

# Check Python environment
if [ ! -d "${ROOT_DIR}/.venv" ]; then
  echo "[*] Creating Python virtual environment..."
  python3 -m venv "${ROOT_DIR}/.venv"
  "${ROOT_DIR}/.venv/bin/pip" install -r "${ROOT_DIR}/backend/requirements.txt"
fi

# Ensure data directories exist
mkdir -p "${ROOT_DIR}/data/uploads" "${ROOT_DIR}/data/evidence" "${ROOT_DIR}/data/reports"

echo "[+] Starting FastAPI Central Backend on http://127.0.0.1:8000 ..."
"${ROOT_DIR}/.venv/bin/python" -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload &
BACKEND_PID=$!

echo "[+] Starting Vite React SOC Dashboard on http://127.0.0.1:5173 ..."
(cd "${ROOT_DIR}/frontend" && npm run dev) &
FRONTEND_PID=$!

cleanup() {
  echo ""
  echo "[*] Stopping SENTINEL-X platform services..."
  kill $BACKEND_PID 2>/dev/null || true
  kill $FRONTEND_PID 2>/dev/null || true
  exit 0
}

trap cleanup INT TERM

echo ""
echo "=========================================================="
echo "  SENTINEL-X SOC Services Online:"
echo "    - Dashboard UI: http://127.0.0.1:5173"
echo "    - API Docs:     http://127.0.0.1:8000/docs"
echo "    - Credentials:  admin / SentinelX@2026!"
echo "=========================================================="
echo "Press Ctrl+C to terminate all services."

wait
