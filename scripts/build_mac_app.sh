#!/bin/bash
# ==============================================================================
# SENTINEL-X macOS App Build Script
# ==============================================================================
set -e
DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$DIR"

if [ -f ".venv/bin/python" ]; then
    .venv/bin/python scripts/build_mac_app.py
else
    python3 scripts/build_mac_app.py
fi
