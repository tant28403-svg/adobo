#!/usr/bin/env bash
# One-shot installer for ADOBO on Termux (Android).
# Usage: bash scripts/install_termux.sh
set -e

echo "[*] Updating Termux packages..."
pkg update -y && pkg upgrade -y

echo "[*] Installing build/runtime dependencies..."
pkg install -y python git clang make pkg-config

echo "[*] Installing Python dependencies..."
pip install --upgrade pip
pip install pydantic pyyaml httpx h2

# psutil: try pip first, fall back to the Termux package.
if ! pip install psutil; then
    echo "[*] pip psutil build failed; trying pkg..."
    pkg install -y python-psutil || true
fi

# cryptography: optional; needed only for --encrypt-proxies and TLS cert generation.
pip install cryptography || echo "[!] cryptography install failed (optional)."

# pyfiglet: optional banner rendering.
pip install pyfiglet || echo "[!] pyfiglet install failed (optional)."

# Optional raw/HTTP3 extras (will not send raw packets without root).
read -r -p "Install optional raw/HTTP3 extras (scapy, aioquic)? [y/N] " ans
if [[ "$ans" =~ ^[Yy]$ ]]; then
    pip install scapy aioquic || echo "[!] Optional extras failed (non-fatal)."
fi

echo "[*] Done. Clone and run:"
echo "    git clone https://github.com/tant28403-svg/adobo.git"
echo "    cd adobo"
echo "    python -m adobo --help"