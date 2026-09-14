#!/bin/bash
# BlackShield — start everything with one command
# Usage: ./start.sh

set -e

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║         BlackShield Platform             ║"
echo "║  Starting all services...                ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Check Python
if ! command -v python3 &>/dev/null; then
  echo "[ERROR] python3 not found. Please install Python 3."
  exit 1
fi

# Check Node / npm
if ! command -v npm &>/dev/null; then
  echo "[ERROR] npm not found. Please install Node.js."
  exit 1
fi

# Install Python deps if needed
echo "[*] Checking Python dependencies..."
pip install cryptography fastapi uvicorn groq pydantic --quiet --break-system-packages 2>/dev/null || \
pip install cryptography fastapi uvicorn groq pydantic --quiet 2>/dev/null || true

# Install npm deps if node_modules missing
if [ ! -d "node_modules" ]; then
  echo "[*] Installing npm dependencies..."
  npm install --silent
fi

echo "[*] Launching services..."
echo ""

# Delegate to the "dev" script in package.json rather than duplicating the
# service list here — this file previously hardcoded its own concurrently
# invocation with only 8 of the 23 backend services (network, nmap, cve,
# ddos, port scanner, password auditor, hashcat, metasploit, ids, ssl
# inspector, firewall, activity log, ctf, assistant, and scenarios were all
# missing), which is why several tools silently never had a backend running
# when started via this script. package.json's "dev" script is the complete,
# up-to-date list, so keep it as the single source of truth.
npm run dev