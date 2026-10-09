#!/usr/bin/env python3
"""
attack_sim.py -- SentinelLog Adversary & Hacker CLI Simulation Tool

Use this when you SSH into the Proxmox container (or run locally from terminal)
to tamper with on-disk audit logs and observe the Admin SOC reacting in real-time.

Usage:
    python cli_hacker/attack_sim.py status
    python cli_hacker/attack_sim.py payload [--search 50000] [--replace 50]
    python cli_hacker/attack_sim.py delete [--index 1]
    python cli_hacker/attack_sim.py truncate [--keep 2]
    python cli_hacker/attack_sim.py wipe
    python cli_hacker/attack_sim.py reorder
    python cli_hacker/attack_sim.py reset
"""

from __future__ import annotations

import argparse
import os
import sys

# Windows terminal UTF-8 support
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

# Add backend to path
CLI_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CLI_DIR)
BACKEND_DIR = os.path.join(PROJECT_ROOT, "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from crypto_engine import SentinelLogEngine  # noqa: E402
from attack_vectors import apply_attack  # noqa: E402
from main import _demo_payloads  # noqa: E402

LOG_PATH = os.path.join(PROJECT_ROOT, "logs", "app_audit.json")
STATE_PATH = os.path.join(PROJECT_ROOT, "logs", "state.json")


def get_engine() -> SentinelLogEngine:
    return SentinelLogEngine(log_path=LOG_PATH, state_path=STATE_PATH)


def cmd_status(args: argparse.Namespace) -> None:
    engine = get_engine()
    report = engine.verify_chain()
    entries = engine.read_log()
    print("=" * 68)
    print(" 🛡️  SENTINELLOG CHAIN STATUS CHECK")
    print("=" * 68)
    print(f" Target File       : {LOG_PATH}")
    print(f" Committed Entries : {len(entries)}")
    print(f" Verification State: {report['status']}")
    print(f" Verifier Category : {report.get('category', 'OK')}")
    print(f" Reason / Headline : {report.get('reason', report.get('headline', 'Chain Valid'))}")
    if report["status"] != "VALID":
        print(f" Corrupted Index   : Record #{report.get('corrupted_index', 'Unknown')}")
        print(f" Diagnostic Detail : {report.get('detail', 'MAC mismatch')}")
    print("=" * 68)


def cmd_payload(args: argparse.Namespace) -> None:
    engine = get_engine()
    print(f"[*] Tampering with payload on disk (Search: {args.search} -> Replace: {args.replace})...")
    kwargs = {"search": args.search, "replacement": args.replace}
    if args.index is not None:
        kwargs["index"] = args.index
    res = apply_attack(engine, "payload", **kwargs)
    print("[+] Attack executed successfully!")
    print(f"    Target: {res['target']}")
    print(f"    Changes: {', '.join(res['changed_fields'])}")
    print("\n[*] Running cryptographic verifier...")
    report = engine.verify_chain()
    print(f"    Status: {report['status']} ({report.get('category')})")
    print("    --> Check your Admin Dashboard; it should have triggered a RED ALERT!")


def cmd_delete(args: argparse.Namespace) -> None:
    engine = get_engine()
    print(f"[*] Deleting entry on disk...")
    kwargs = {}
    if args.index is not None:
        kwargs["index"] = args.index
    res = apply_attack(engine, "delete", **kwargs)
    print(f"[+] Deleted entry: {res.get('deleted_record', {}).get('index', 'N/A')}")
    report = engine.verify_chain()
    print(f"[*] Verification Status: {report['status']} ({report.get('category')})")


def cmd_truncate(args: argparse.Namespace) -> None:
    engine = get_engine()
    print(f"[*] Truncating tail of audit log on disk...")
    res = apply_attack(engine, "tail_truncate", keep=args.keep)
    print(f"[+] Truncation complete. Kept {res.get('entries_kept', args.keep)} entries.")
    report = engine.verify_chain()
    print(f"[*] Verification Status: {report['status']} ({report.get('category')})")


def cmd_wipe(args: argparse.Namespace) -> None:
    engine = get_engine()
    print(f"[*] Wiping logs/app_audit.json to 0 bytes (cat /dev/null > log)...")
    apply_attack(engine, "wipe")
    print("[+] File wiped!")
    report = engine.verify_chain()
    print(f"[*] Verification Status: {report['status']} ({report.get('category')})")


def cmd_reorder(args: argparse.Namespace) -> None:
    engine = get_engine()
    print(f"[*] Swapping row order in logs/app_audit.json...")
    res = apply_attack(engine, "reorder")
    print(f"[+] Reordered rows: {res.get('swapped_positions', 'adjacent rows')}")
    report = engine.verify_chain()
    print(f"[*] Verification Status: {report['status']} ({report.get('category')})")


def cmd_reset(args: argparse.Namespace) -> None:
    engine = get_engine()
    print("[*] Resetting chain and restoring verified baseline seed...")
    engine.reset()
    engine.seed_demo_entries(_demo_payloads())
    report = engine.verify_chain()
    print(f"[+] Reset successful! Current chain status: {report['status']}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SentinelLog Adversary & Hacker CLI Simulation Tool"
    )
    subparsers = parser.add_subparsers(dest="command", help="Adversary action")

    # Status
    subparsers.add_parser("status", help="Check verification status of on-disk log")

    # Payload
    p_pay = subparsers.add_parser("payload", help="Modify an amount in a committed payload")
    p_pay.add_argument("--index", type=int, default=None, help="Target entry index")
    p_pay.add_argument("--search", type=str, default="50000", help="Value to search")
    p_pay.add_argument("--replace", type=str, default="50", help="Replacement value")

    # Delete
    p_del = subparsers.add_parser("delete", help="Delete a single committed JSON row")
    p_del.add_argument("--index", type=int, default=None, help="Index of entry to erase")

    # Truncate
    p_tr = subparsers.add_parser("truncate", help="Truncate newest entries from log tail")
    p_tr.add_argument("--keep", type=int, default=2, help="Number of entries to preserve")

    # Wipe
    subparsers.add_parser("wipe", help="Truncate entire audit log to 0 bytes")

    # Reorder
    subparsers.add_parser("reorder", help="Swap entry positions to break sequence")

    # Reset
    subparsers.add_parser("reset", help="Restore valid baseline and reseed data")

    args = parser.parse_args()

    commands = {
        "status": cmd_status,
        "payload": cmd_payload,
        "delete": cmd_delete,
        "truncate": cmd_truncate,
        "wipe": cmd_wipe,
        "reorder": cmd_reorder,
        "reset": cmd_reset,
    }

    if not args.command:
        parser.print_help()
        sys.exit(0)

    handler = commands.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
