#!/usr/bin/env bash
# run.sh - Runner for Proxmox Container / Linux
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "$DIR"

# Ensure python3 is available
if ! command -v python3 &> /dev/null; then
    echo "[!] python3 could not be found. Please install python3 and python3-venv:"
    echo "    apt update && apt install -y python3 python3-venv python3-pip"
    exit 1
fi

python3 start.py "$@"
