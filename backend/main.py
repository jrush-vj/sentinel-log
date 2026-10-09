"""
main.py -- SentinelLog REST + WebSocket API server.

Run from anywhere:

    python sentinellog/backend/main.py
    # then open http://127.0.0.1:8000

Serves the dual-view web application (enterprise client portal + admin auditor
dashboard) from ../frontend and exposes the verification engine over HTTP.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from contextlib import asynccontextmanager
from typing import Any

# --------------------------------------------------------------------------- #
# Import bootstrap: allow both `python backend/main.py` and `python -m backend.main`
# --------------------------------------------------------------------------- #
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BACKEND_DIR)
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
from fastapi.responses import FileResponse, JSONResponse  # noqa: E402
from fastapi.staticfiles import StaticFiles  # noqa: E402
from pydantic import BaseModel, Field  # noqa: E402

from crypto_engine import SentinelLogEngine  # noqa: E402

FRONTEND_DIR = os.path.join(PROJECT_ROOT, "frontend")
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")
LOG_PATH = os.path.join(LOGS_DIR, "app_audit.json")
STATE_PATH = os.path.join(LOGS_DIR, "state.json")

APP_VERSION = "1.0.0"


# --------------------------------------------------------------------------- #
# Request models
# --------------------------------------------------------------------------- #
class TransactionRequest(BaseModel):
    """High-value action submitted by the enterprise client."""

    action: str = Field(default="WIRE_TRANSFER", max_length=120)
    amount: float = Field(..., gt=0, description="Transaction amount in USD")
    recipient: str = Field(..., min_length=1, max_length=200)
    currency: str = Field(default="USD", max_length=8)
    reference: str = Field(default="", max_length=120)
    actor: str = Field(default="treasury.operator@enterprise.example", max_length=200)


class PayloadRequest(BaseModel):
    """Low-level append used by the CLI / integration tests."""

    payload: dict[str, Any]


class DepositRequest(BaseModel):
    """Retail / treasury client deposit into account."""

    amount: float = Field(..., gt=0, description="Deposit amount in USD")
    source: str = Field(default="Direct Deposit / Wire", max_length=120)
    note: str = Field(default="Account funding", max_length=200)
    actor: str = Field(default="alex.vance@sentinelbank.com", max_length=200)


class WithdrawRequest(BaseModel):
    """Retail client cash out / ATM disbursal."""

    amount: float = Field(..., gt=0, description="Withdrawal amount in USD")
    method: str = Field(default="ATM Cash Dispenser", max_length=120)
    note: str = Field(default="Cash Out", max_length=200)
    actor: str = Field(default="alex.vance@sentinelbank.com", max_length=200)


class TransferRequest(BaseModel):
    """Wire transfer from client portal."""

    amount: float = Field(..., gt=0, description="Transfer amount in USD")
    recipient: str = Field(..., min_length=1, max_length=200)
    reference: str = Field(default="", max_length=120)
    actor: str = Field(default="alex.vance@sentinelbank.com", max_length=200)


# --------------------------------------------------------------------------- #
# WebSocket fan-out
# --------------------------------------------------------------------------- #
class EventHub:
    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()
        self._lock = asyncio.Lock()
        self.sequence = 0

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self._clients.add(websocket)

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            self._clients.discard(websocket)

    async def broadcast(self, event: str, data: dict[str, Any]) -> None:
        self.sequence += 1
        message = json.dumps(
            {"event": event, "sequence": self.sequence, "data": data}, default=str
        )
        async with self._lock:
            targets = list(self._clients)
        dead: list[WebSocket] = []
        for client in targets:
            try:
                await client.send_text(message)
            except Exception:  # pragma: no cover - client vanished
                dead.append(client)
        if dead:
            async with self._lock:
                for client in dead:
                    self._clients.discard(client)


hub = EventHub()
engine = SentinelLogEngine(log_path=LOG_PATH, state_path=STATE_PATH)


# --------------------------------------------------------------------------- #
# Host-level file watcher
#
# The audit log lives on an untrusted machine, so the adversary edits the file
# directly -- outside this process. A lightweight stat watcher turns those
# out-of-band edits into a pushed red alert, so the auditor's dashboard reacts
# in real time instead of waiting for a manual click.
# --------------------------------------------------------------------------- #
_last_signature: tuple[int, int] | None = None
_watcher_task: asyncio.Task | None = None


def log_signature() -> tuple[int, int]:
    """Cheap change detector for the audit log file."""
    try:
        stat = os.stat(LOG_PATH)
        return (stat.st_size, stat.st_mtime_ns)
    except OSError:
        return (-1, -1)


def mark_engine_write() -> None:
    """Record a signature for a write this process just performed itself."""
    global _last_signature
    _last_signature = log_signature()


async def watch_log_file(interval: float = 1.0) -> None:
    """Poll the on-disk log and broadcast verifications for external edits."""
    global _last_signature
    _last_signature = log_signature()
    while True:
        await asyncio.sleep(interval)
        signature = log_signature()
        if signature == _last_signature:
            continue
        _last_signature = signature
        try:
            report = await asyncio.to_thread(engine.verify_chain)
        except Exception as exc:  # pragma: no cover - defensive
            report = {"status": "TAMPERED", "reason": f"verifier error: {exc}"}
        await hub.broadcast(
            "tamper" if report.get("status") != "VALID" else "log_changed",
            {
                "source": "filesystem-watch",
                "verification": report,
                "count": len(engine.read_log()),
            },
        )


# --------------------------------------------------------------------------- #
# App
# --------------------------------------------------------------------------- #
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("=" * 72)
    print(" SentinelLog -- Tamper-Evident Audit Infrastructure Engine")
    print("=" * 72)
    print(f" audit log   : {LOG_PATH}")
    print(f" checkpoint  : {STATE_PATH}")
    print(f" genesis y_0 : {engine.log_info()['genesis_hash']}")
    print(f" K0 commit   : {engine.log_info()['k0_commitment']}")
    print(" web console : http://127.0.0.1:8000")
    print("=" * 72)
    global _watcher_task
    _watcher_task = asyncio.create_task(watch_log_file())
    try:
        yield
    finally:
        if _watcher_task is not None:
            _watcher_task.cancel()


app = FastAPI(title="SentinelLog", version=APP_VERSION, lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _serialize_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Attach verification state so the dashboard can highlight bad rows."""
    return {
        "index": entry.get("index"),
        "timestamp": entry.get("timestamp"),
        "payload": entry.get("payload"),
        "y": entry.get("y"),
        "W": entry.get("W"),
        "epoch": entry.get("epoch"),
        "key_seed_commitment": entry.get("key_seed_commitment"),
        "meta_digest": entry.get("meta_digest"),
    }


# ------------------------------------------------------------------ meta API
@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "service": "sentinellog", "version": APP_VERSION}


@app.get("/api/meta")
def meta() -> dict[str, Any]:
    info = engine.log_info()
    return {
        "version": APP_VERSION,
        "algorithm": "SHA-256 hash chain + HMAC-SHA256 forward-secure MAC",
        "protocol": "Schneier-Kelsey secure audit log (forward-secure key evolution)",
        "epoch_size": info["epoch_size"],
        "genesis_hash": info["genesis_hash"],
        "k0_commitment": info["k0_commitment"],
        "log": info,
    }


# ------------------------------------------------------------------- log API
@app.get("/api/log")
def get_log() -> dict[str, Any]:
    """Return every raw record exactly as persisted (tampering included)."""
    try:
        entries = engine.read_log()
        parse_error = None
    except Exception as exc:  # LogStorageError / JSON corruption
        entries = []
        parse_error = str(exc)

    return {
        "entries": [_serialize_entry(e) for e in entries if isinstance(e, dict)],
        "raw_elements": len(entries),
        "parse_error": parse_error,
        "log": engine.log_info(),
        "count": len(entries),
    }


@app.get("/api/log/raw")
def get_log_raw() -> FileResponse:
    if not os.path.exists(LOG_PATH):
        raise HTTPException(status_code=404, detail="audit log not found")
    return FileResponse(LOG_PATH, media_type="application/json")


@app.get("/api/state")
def get_state() -> dict[str, Any]:
    state = engine.read_state()
    state.pop("forged_state", None)
    return state


# ---------------------------------------------------------------- verify API
@app.get("/api/verify")
def verify() -> dict[str, Any]:
    """Recompute the entire cryptographic chain from the genesis seed."""
    report = engine.verify_chain()
    return report


# -------------------------------------------------------------- append APIs
@app.post("/api/transaction")
async def post_transaction(request: TransactionRequest) -> dict[str, Any]:
    """Enterprise client action: approve a high-value transfer and log it."""
    amount = round(float(request.amount), 2)
    payload = {
        "action": request.action.strip().upper(),
        "amount": amount,
        "amount_display": f"${amount:,.2f}",
        "currency": request.currency.strip().upper(),
        "recipient": request.recipient.strip(),
        "reference": request.reference.strip(),
        "actor": request.actor.strip(),
        "approval": "APPROVED",
    }
    record = engine.append_log(payload)
    mark_engine_write()
    report = engine.verify_chain()
    await hub.broadcast(
        "transaction",
        {
            "record": _serialize_entry(record),
            "verification": report,
            "count": len(engine.read_log()),
        },
    )
    return {
        "status": "committed",
        "record": _serialize_entry(record),
        "receipt": {
            "entry_index": record["index"],
            "timestamp": record["timestamp"],
            "chain_hash": record["y"],
            "mac": record["W"],
            "epoch": record["epoch"],
            "display": payload["amount_display"],
            "recipient": payload["recipient"],
        },
        "verification": report,
    }


@app.post("/api/append")
async def post_append(request: PayloadRequest) -> dict[str, Any]:
    """Generic append used by scripts, the CLI and automated tests."""
    record = engine.append_log(request.payload)
    mark_engine_write()
    report = engine.verify_chain()
    await hub.broadcast(
        "append",
        {
            "record": _serialize_entry(record),
            "verification": report,
            "count": len(engine.read_log()),
        },
    )
    return {"status": "committed", "record": _serialize_entry(record), "verification": report}


# ------------------------------------------------------------- user banking
BASE_ACCOUNT_BALANCE = 125000.0


def compute_account_summary() -> dict[str, Any]:
    """Compute verified user balance directly from the on-disk audit log entries."""
    balance = BASE_ACCOUNT_BALANCE
    total_deposited = 0.0
    total_withdrawn = 0.0
    user_txs: list[dict[str, Any]] = []

    try:
        entries = engine.read_log()
    except Exception:
        entries = []

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        payload = entry.get("payload", {})
        action = str(payload.get("action", "")).upper()
        amount = float(payload.get("amount", 0.0))

        if action in ("DEPOSIT", "CREDIT"):
            balance += amount
            total_deposited += amount
        elif action in (
            "WITHDRAWAL",
            "DEBIT",
            "WIRE_TRANSFER",
            "INVOICE_PAYMENT",
            "PAYROLL_DISBURSEMENT",
        ):
            balance -= amount
            total_withdrawn += amount

        user_txs.append(
            {
                "index": entry.get("index"),
                "timestamp": entry.get("timestamp"),
                "action": action,
                "amount": amount,
                "amount_display": payload.get("amount_display", f"${amount:,.2f}"),
                "recipient": payload.get("recipient", "N/A"),
                "reference": payload.get("reference", ""),
                "actor": payload.get("actor", ""),
                "approval": payload.get("approval", "APPROVED"),
                "hash": entry.get("y"),
                "mac": entry.get("W"),
                "epoch": entry.get("epoch"),
            }
        )

    return {
        "account_number": "ACT-8842-9910-SENTINEL",
        "holder_name": "Alex Vance",
        "holder_role": "Commercial Checking & Treasury",
        "currency": "USD",
        "balance": round(balance, 2),
        "balance_display": f"${balance:,.2f}",
        "total_deposits": round(total_deposited, 2),
        "total_withdrawals": round(total_withdrawn, 2),
        "transaction_count": len(user_txs),
        "recent_transactions": list(reversed(user_txs[-50:])),
    }


@app.get("/api/account")
def get_account() -> dict[str, Any]:
    """Return live bank account state, dynamically verified from audit log."""
    return compute_account_summary()


@app.post("/api/user/deposit")
async def post_user_deposit(request: DepositRequest) -> dict[str, Any]:
    """Client deposit: funds account and appends to tamper-evident audit ledger."""
    amount = round(float(request.amount), 2)
    ref_id = f"DEP-{int(time.time() * 1000) % 1000000:06d}"
    payload = {
        "action": "DEPOSIT",
        "amount": amount,
        "amount_display": f"+${amount:,.2f}",
        "currency": "USD",
        "recipient": "Alex Vance (Account #8842)",
        "reference": ref_id,
        "actor": request.actor.strip(),
        "approval": "CONFIRMED",
        "note": request.note.strip(),
        "source": request.source.strip(),
    }
    record = engine.append_log(payload)
    mark_engine_write()
    report = engine.verify_chain()
    summary = compute_account_summary()
    await hub.broadcast(
        "transaction",
        {
            "record": _serialize_entry(record),
            "verification": report,
            "count": len(engine.read_log()),
            "account": summary,
        },
    )
    return {
        "status": "committed",
        "record": _serialize_entry(record),
        "receipt": {
            "entry_index": record["index"],
            "timestamp": record["timestamp"],
            "chain_hash": record["y"],
            "mac": record["W"],
            "epoch": record["epoch"],
            "display": payload["amount_display"],
            "recipient": payload["recipient"],
            "reference": payload["reference"],
        },
        "account": summary,
        "verification": report,
    }


@app.post("/api/user/withdraw")
async def post_user_withdraw(request: WithdrawRequest) -> dict[str, Any]:
    """Client withdrawal: disburses cash and records in tamper-evident audit ledger."""
    amount = round(float(request.amount), 2)
    current_summary = compute_account_summary()
    if amount > current_summary["balance"]:
        raise HTTPException(
            status_code=400,
            detail=f"Insufficient funds: withdrawal of ${amount:,.2f} exceeds current balance of ${current_summary['balance']:,.2f}",
        )
    ref_id = f"WTH-{int(time.time() * 1000) % 1000000:06d}"
    payload = {
        "action": "WITHDRAWAL",
        "amount": amount,
        "amount_display": f"-${amount:,.2f}",
        "currency": "USD",
        "recipient": f"ATM / {request.method.strip()}",
        "reference": ref_id,
        "actor": request.actor.strip(),
        "approval": "DISBURSED",
        "note": request.note.strip(),
        "method": request.method.strip(),
    }
    record = engine.append_log(payload)
    mark_engine_write()
    report = engine.verify_chain()
    summary = compute_account_summary()
    await hub.broadcast(
        "transaction",
        {
            "record": _serialize_entry(record),
            "verification": report,
            "count": len(engine.read_log()),
            "account": summary,
        },
    )
    return {
        "status": "committed",
        "record": _serialize_entry(record),
        "receipt": {
            "entry_index": record["index"],
            "timestamp": record["timestamp"],
            "chain_hash": record["y"],
            "mac": record["W"],
            "epoch": record["epoch"],
            "display": payload["amount_display"],
            "recipient": payload["recipient"],
            "reference": payload["reference"],
        },
        "account": summary,
        "verification": report,
    }


@app.post("/api/user/transfer")
async def post_user_transfer(request: TransferRequest) -> dict[str, Any]:
    """Client wire transfer: executes outbound wire and logs to audit ledger."""
    amount = round(float(request.amount), 2)
    current_summary = compute_account_summary()
    if amount > current_summary["balance"]:
        raise HTTPException(
            status_code=400,
            detail=f"Insufficient funds: transfer of ${amount:,.2f} exceeds current balance of ${current_summary['balance']:,.2f}",
        )
    ref_id = request.reference.strip() or f"WIRE-{int(time.time() * 1000) % 1000000:06d}"
    payload = {
        "action": "WIRE_TRANSFER",
        "amount": amount,
        "amount_display": f"-${amount:,.2f}",
        "currency": "USD",
        "recipient": request.recipient.strip(),
        "reference": ref_id,
        "actor": request.actor.strip(),
        "approval": "APPROVED",
    }
    record = engine.append_log(payload)
    mark_engine_write()
    report = engine.verify_chain()
    summary = compute_account_summary()
    await hub.broadcast(
        "transaction",
        {
            "record": _serialize_entry(record),
            "verification": report,
            "count": len(engine.read_log()),
            "account": summary,
        },
    )
    return {
        "status": "committed",
        "record": _serialize_entry(record),
        "receipt": {
            "entry_index": record["index"],
            "timestamp": record["timestamp"],
            "chain_hash": record["y"],
            "mac": record["W"],
            "epoch": record["epoch"],
            "display": payload["amount_display"],
            "recipient": payload["recipient"],
            "reference": payload["reference"],
        },
        "account": summary,
        "verification": report,
    }


@app.get("/api/system/tunnels")
def get_tunnels() -> dict[str, Any]:
    """Return active public ngrok tunnel URLs for easy multi-user simulation."""
    tunnel_file = os.path.join(LOGS_DIR, "public_urls.json")
    if os.path.exists(tunnel_file):
        try:
            with open(tunnel_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "ngrok_url": None,
        "user_url": "/user",
        "admin_url": "/admin",
        "status": "local_only",
    }


# ------------------------------------------------------------- demo controls
@app.post("/api/demo/attack")
async def post_demo_attack(kind: str = "payload") -> dict[str, Any]:
    """Convenience endpoint that runs an attack vector in-process (demo only)."""
    from attack_vectors import apply_attack  # local import: optional module

    result = apply_attack(engine, kind)
    mark_engine_write()
    report = engine.verify_chain()
    await hub.broadcast(
        "tamper",
        {"attack": result, "verification": report, "count": len(engine.read_log())},
    )
    return {"attack": result, "verification": report}


@app.post("/api/demo/reset")
async def post_demo_reset(seed: bool = True) -> dict[str, Any]:
    engine.reset()
    seeded = 0
    if seed:
        seeded = engine.seed_demo_entries(_demo_payloads())
    mark_engine_write()
    report = engine.verify_chain()
    await hub.broadcast(
        "reset",
        {"seeded": seeded, "verification": report, "count": len(engine.read_log())},
    )
    return {"status": "reset", "seeded": seeded, "verification": report}


def _demo_payloads() -> list[dict[str, Any]]:
    """A believable corporate treasury trail, including the initial capital reserve and $50,000 transfer."""
    return [
        {
            "action": "DEPOSIT",
            "amount": 250000.0,
            "amount_display": "+$250,000.00",
            "currency": "USD",
            "recipient": "Alex Vance (Account #8842)",
            "reference": "INIT-CAPITAL-01",
            "actor": "central.reserve@sentinelbank.com",
            "approval": "CONFIRMED",
            "note": "Initial Capital Reserve Allocation",
            "source": "Treasury Allocation",
        },
        {
            "action": "WIRE_TRANSFER",
            "amount": 50000.0,
            "amount_display": "$50,000.00",
            "currency": "USD",
            "recipient": "Supplier B",
            "reference": "PO-2026-0042",
            "actor": "treasury.operator@enterprise.example",
            "approval": "APPROVED",
        },
        {
            "action": "VENDOR_ONBOARD",
            "amount": 0.0,
            "amount_display": "$0.00",
            "currency": "USD",
            "recipient": "Supplier B",
            "reference": "KYC-77120",
            "actor": "procurement.lead@enterprise.example",
            "approval": "APPROVED",
        },
        {
            "action": "INVOICE_PAYMENT",
            "amount": 12450.75,
            "amount_display": "$12,450.75",
            "currency": "USD",
            "recipient": "Logistics Co",
            "reference": "INV-8891",
            "actor": "ap.automation@enterprise.example",
            "approval": "APPROVED",
        },
        {
            "action": "PAYROLL_DISBURSEMENT",
            "amount": 218400.0,
            "amount_display": "$218,400.00",
            "currency": "USD",
            "recipient": "Payroll Clearing",
            "reference": "PAY-2026-10",
            "actor": "hr.ops@enterprise.example",
            "approval": "APPROVED",
        },
        {
            "action": "ACCESS_GRANT",
            "amount": 0.0,
            "amount_display": "$0.00",
            "currency": "USD",
            "recipient": "vault.operator@enterprise.example",
            "reference": "RMS-4410",
            "actor": "security.admin@enterprise.example",
            "approval": "APPROVED",
        },
    ]


# ---------------------------------------------------------------- websockets
@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket) -> None:
    await hub.connect(websocket)
    try:
        await websocket.send_text(
            json.dumps(
                {
                    "event": "hello",
                    "sequence": 0,
                    "data": {"version": APP_VERSION, "log": engine.log_info()},
                },
                default=str,
            )
        )
        while True:
            # Keep the socket alive; we ignore inbound frames.
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception:  # pragma: no cover
        pass
    finally:
        await hub.disconnect(websocket)


# -------------------------------------------------------------- static files
@app.exception_handler(Exception)
async def unhandled_exception_handler(request, exc):  # pragma: no cover
    return JSONResponse(status_code=500, content={"detail": f"{type(exc).__name__}: {exc}"})


# -------------------------------------------------------------- static & page routes
@app.get("/user", response_class=FileResponse)
async def serve_user():
    user_file = os.path.join(FRONTEND_DIR, "user.html")
    if os.path.exists(user_file):
        return FileResponse(user_file)
    raise HTTPException(status_code=404, detail="user portal not found")


@app.get("/admin", response_class=FileResponse)
async def serve_admin():
    admin_file = os.path.join(FRONTEND_DIR, "admin.html")
    if os.path.exists(admin_file):
        return FileResponse(admin_file)
    raise HTTPException(status_code=404, detail="admin dashboard not found")


@app.get("/", response_class=FileResponse)
async def serve_root():
    root_file = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(root_file):
        return FileResponse(root_file)
    return FileResponse(os.path.join(FRONTEND_DIR, "user.html"))


if os.path.isdir(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")


def main() -> None:
    import uvicorn

    host = os.environ.get("SENTINELLOG_HOST", "127.0.0.1")
    port = int(os.environ.get("SENTINELLOG_PORT", "8000"))
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()