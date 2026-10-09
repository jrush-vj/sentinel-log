#!/usr/bin/env python3
"""
start.py -- Unified Bootstrap & Runner for SentinelLog Banking & Audit System

Features:
  1. Automatically creates Python virtual environment (.venv) if not present.
  2. Automatically installs dependencies from requirements.txt into .venv.
  3. Seamlessly initializes and starts ngrok HTTPS tunnels on any system.
  4. Generates direct links for Friend 1 (/user) and Friend 2 (/admin).
  5. Serves self-hosted backend, bank webapp, and admin dashboard.

Usage:
    python start.py                 # Auto-bootstrap and start with ngrok
    python start.py --no-ngrok      # Run locally without ngrok
    python start.py --ngrok-token <TOKEN> # Provide ngrok auth token directly
    python start.py --port 8000     # Custom port
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time

# Reconfigure stdout for utf-8
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
VENV_DIR = os.path.join(PROJECT_ROOT, ".venv")
REQ_PATH = os.path.join(PROJECT_ROOT, "requirements.txt")
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")
TUNNELS_JSON = os.path.join(LOGS_DIR, "public_urls.json")
TUNNELS_TXT = os.path.join(LOGS_DIR, "public_urls.txt")


def is_running_in_venv() -> bool:
    """Check if current Python process is running inside a virtual environment."""
    return getattr(sys, "base_prefix", sys.prefix) != sys.prefix or hasattr(sys, "real_prefix")


def get_venv_python() -> str:
    """Return the absolute path to Python executable inside .venv."""
    if sys.platform == "win32":
        return os.path.join(VENV_DIR, "Scripts", "python.exe")
    return os.path.join(VENV_DIR, "bin", "python")


def ensure_virtualenv_and_deps() -> str:
    """Ensure .venv exists and requirements are installed, then return venv python path."""
    venv_python = get_venv_python()

    # 1. Create .venv if missing
    if not os.path.exists(venv_python):
        print("=" * 72)
        print(" [*] Creating Python virtual environment in .venv...")
        print("=" * 72)
        subprocess.run([sys.executable, "-m", "venv", VENV_DIR], check=True)
        print("[+] Virtual environment created successfully.")

    # 2. Check dependencies
    print("[*] Verifying project dependencies in .venv...")
    test_deps_cmd = [
        venv_python,
        "-c",
        "import fastapi, uvicorn, pydantic, pyngrok, requests; print('OK')",
    ]
    check = subprocess.run(test_deps_cmd, capture_output=True, text=True)
    if check.returncode != 0:
        print("[*] Installing dependencies from requirements.txt (this may take a moment)...")
        subprocess.run([venv_python, "-m", "pip", "install", "--upgrade", "pip"], check=False)
        subprocess.run([venv_python, "-m", "pip", "install", "-r", REQ_PATH], check=True)
        print("[+] All dependencies installed successfully!")

    return venv_python


def setup_ngrok_tunnel(port: int, token: str | None = None) -> tuple[str | None, str | None]:
    """Start ngrok tunnel and return (public_https_url, error_message)."""
    try:
        from pyngrok import conf, ngrok
    except ImportError:
        return None, "pyngrok package not available"

    # Set auth token if provided
    authtoken = token or os.environ.get("NGROK_AUTHTOKEN")
    if authtoken:
        try:
            ngrok.set_auth_token(authtoken)
            print("[+] Ngrok authtoken configured.")
        except Exception as e:
            print(f"[-] Warning: Failed to set ngrok authtoken: {e}")

    # Check if a tunnel is already running on port
    try:
        tunnels = ngrok.get_tunnels()
        for t in tunnels:
            if f":{port}" in t.config.get("addr", ""):
                url = t.public_url
                if url.startswith("http://"):
                    url = url.replace("http://", "https://")
                return url, None
    except Exception:
        pass

    try:
        print(f"[*] Starting ngrok HTTPS tunnel on port {port}...")
        tunnel = ngrok.connect(port, "http")
        url = tunnel.public_url
        if url.startswith("http://"):
            url = url.replace("http://", "https://")
        return url, None
    except Exception as e:
        err_msg = str(e)
        return None, err_msg


def save_tunnel_info(public_url: str | None, local_port: int) -> None:
    """Save public URLs to disk for frontend and CLI inspection."""
    os.makedirs(LOGS_DIR, exist_ok=True)
    if public_url:
        info = {
            "ngrok_url": public_url,
            "user_url": f"{public_url}/user",
            "admin_url": f"{public_url}/admin",
            "local_url": f"http://localhost:{local_port}",
            "status": "online",
            "timestamp": time.time(),
        }
    else:
        info = {
            "ngrok_url": None,
            "user_url": f"http://localhost:{local_port}/user",
            "admin_url": f"http://localhost:{local_port}/admin",
            "local_url": f"http://localhost:{local_port}",
            "status": "local_only",
            "timestamp": time.time(),
        }

    with open(TUNNELS_JSON, "w", encoding="utf-8") as f:
        json.dump(info, f, indent=2)

    with open(TUNNELS_TXT, "w", encoding="utf-8") as f:
        f.write(f"USER_PORTAL={info['user_url']}\n")
        f.write(f"ADMIN_DASHBOARD={info['admin_url']}\n")


def print_banner(user_url: str, admin_url: str, local_port: int, ngrok_url: str | None) -> None:
    print("\n" + "=" * 76)
    print(" 🚀  SENTINELLOG BANK & AUDIT INFRASTRUCTURE ONLINE")
    print("=" * 76)
    if ngrok_url:
        print(f"  Public Tunnel Base : {ngrok_url}")
    print(f"  Local Access       : http://localhost:{local_port}")
    print(f"  On-Disk Audit Log  : logs/app_audit.json (Adversary SSH target)")
    print("-" * 76)
    print("  SIMULATION LINKS TO SHARE WITH YOUR FRIENDS:")
    print("")
    print(f"  👤 FRIEND 1 (User Bank)     : {user_url}")
    print("     👉 Gives access to deposit, withdraw cash, and wire funds.")
    print("")
    print(f"  🛡️ FRIEND 2 (Admin SOC)     : {admin_url}")
    print("     👉 Real-time audit dashboard to monitor chain integrity.")
    print("=" * 76 + "\n")


def main() -> None:
    # 1. Check if running inside virtual environment
    if not is_running_in_venv():
        venv_python = ensure_virtualenv_and_deps()
        print(f"[*] Switching execution into virtualenv: {venv_python}...\n")
        args = [venv_python, os.path.abspath(__file__)] + sys.argv[1:]
        try:
            # On Windows, subprocess.run is cleaner than execv
            sys.exit(subprocess.run(args).returncode)
        except KeyboardInterrupt:
            sys.exit(0)

    # 2. Inside .venv: Parse arguments
    parser = argparse.ArgumentParser(description="SentinelLog Server & Ngrok Runner")
    parser.add_argument("--host", default="0.0.0.0", help="Host interface (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="Server port (default: 8000)")
    parser.add_argument("--no-ngrok", action="store_true", help="Disable ngrok public tunnel")
    parser.add_argument("--ngrok-token", default=None, help="Ngrok authtoken")
    parser.add_argument("--reset", action="store_true", help="Reset audit chain before starting")
    args = parser.parse_args()

    # 3. Add backend directory to sys.path
    backend_path = os.path.join(PROJECT_ROOT, "backend")
    if backend_path not in sys.path:
        sys.path.insert(0, backend_path)

    # 4. Optional reset
    if args.reset:
        try:
            from crypto_engine import SentinelLogEngine
            from main import _demo_payloads
            eng = SentinelLogEngine(
                log_path=os.path.join(LOGS_DIR, "app_audit.json"),
                state_path=os.path.join(LOGS_DIR, "state.json"),
            )
            eng.reset()
            eng.seed_demo_entries(_demo_payloads())
            print("[+] Audit chain reset and reseeded with initial capital.")
        except Exception as e:
            print(f"[-] Warning: Reset failed: {e}")

    # 5. Ngrok Tunnel handling
    ngrok_url = None
    if not args.no_ngrok:
        ngrok_url, err = setup_ngrok_tunnel(args.port, args.ngrok_token)
        if not ngrok_url:
            print("-" * 72)
            print(" [!] Note: Ngrok tunnel could not be started:")
            print(f"     {err}")
            print("     To activate ngrok links, pass your token once:")
            print(f"       python start.py --ngrok-token <YOUR_NGROK_AUTHTOKEN>")
            print("     Or set the NGROK_AUTHTOKEN environment variable.")
            print("     Continuing in local self-hosted mode...")
            print("-" * 72)

    save_tunnel_info(ngrok_url, args.port)

    if ngrok_url:
        user_url = f"{ngrok_url}/user"
        admin_url = f"{ngrok_url}/admin"
    else:
        user_url = f"http://localhost:{args.port}/user"
        admin_url = f"http://localhost:{args.port}/admin"

    print_banner(user_url, admin_url, args.port, ngrok_url)

    # 6. Start Uvicorn Server
    import uvicorn
    from main import app

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
