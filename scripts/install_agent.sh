#!/usr/bin/env bash
# ==============================================================================
# SENTINEL-X Linux Endpoint Monitoring Agent Installer
# Cross-Distribution: Ubuntu, Debian, Kali Linux, Parrot Security, Fedora
# ==============================================================================

set -euo pipefail

echo "=========================================================="
echo "  SENTINEL-X Linux Endpoint Agent Installer"
echo "=========================================================="

if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run as root (or with sudo) to install systemd collector service."
  exit 1
fi

SERVER_URL="${1:-http://127.0.0.1:8000}"
AGENT_KEY="${2:-sx_dev_agent_key_default}"

echo "[*] Target Central Backend: ${SERVER_URL}"
echo "[*] Using Agent API Key prefix: ${AGENT_KEY:0:10}..."

# 1. Detect Linux distribution
if [ -f /etc/os-release ]; then
  . /etc/os-release
  DISTRO="${ID:-linux}"
  VERSION="${VERSION_ID:-unknown}"
else
  DISTRO="generic"
  VERSION="unknown"
fi

echo "[+] Detected Linux Environment: ${DISTRO} ${VERSION}"

# 2. Install required package dependencies
echo "[*] Installing Python 3 and systemd development packages..."
if command -v apt-get >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -y -qq python3 python3-pip python3-venv auditd
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y -q python3 python3-pip audit
elif command -v yum >/dev/null 2>&1; then
  yum install -y -q python3 python3-pip audit
fi

# 3. Create target directory
INSTALL_DIR="/opt/sentinel-agent"
mkdir -p "${INSTALL_DIR}"

# 4. Copy agent source
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cp -r "${SCRIPT_DIR}/agent/sentinel_agent" "${INSTALL_DIR}/"

# 5. Set up virtual environment
echo "[*] Setting up isolated agent virtualenv..."
python3 -m venv "${INSTALL_DIR}/venv"
"${INSTALL_DIR}/venv/bin/pip" install --quiet --upgrade pip
"${INSTALL_DIR}/venv/bin/pip" install --quiet requests pyyaml inotify-simple

# 6. Install systemd service unit
echo "[*] Configuring systemd service..."
cat <<EOF > /etc/systemd/system/sentinel-agent.service
[Unit]
Description=SENTINEL-X Endpoint Security Telemetry Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/venv/bin/python -m sentinel_agent.agent --server ${SERVER_URL} --api-key ${AGENT_KEY}
Restart=always
RestartSec=5s

# Resource and security limits
CPUQuota=10%
MemoryLimit=128M

[Install]
WantedBy=multi-user.target
EOF

# 7. Reload and enable
systemctl daemon-reload
systemctl enable sentinel-agent.service
systemctl restart sentinel-agent.service

echo "=========================================================="
echo "[+] SENTINEL-X Agent installed and started successfully!"
echo "[+] Status: systemctl status sentinel-agent"
echo "=========================================================="
