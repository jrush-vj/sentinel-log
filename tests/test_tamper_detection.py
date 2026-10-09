"""
test_tamper_detection.py -- Automated unit & integration tests for SentinelLog
tamper-evident audit chain and banking operations.
"""

import copy
import json
import os
import sys
import tempfile
import pytest

# Ensure backend in path
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(TEST_DIR)
BACKEND_DIR = os.path.join(PROJECT_ROOT, "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from crypto_engine import SentinelLogEngine
from attack_vectors import apply_attack
from main import _demo_payloads


@pytest.fixture
def test_engine(tmp_path):
    log_file = str(tmp_path / "app_audit.json")
    state_file = str(tmp_path / "state.json")
    engine = SentinelLogEngine(log_path=log_file, state_path=state_file)
    engine.reset()
    engine.seed_demo_entries(_demo_payloads())
    return engine


def test_initial_chain_valid(test_engine):
    report = test_engine.verify_chain()
    assert report["status"] == "VALID"
    assert report["entries_verified"] == 6
    assert len(report["flagged_indices"]) == 0


def test_append_deposit_and_withdraw(test_engine):
    # Deposit
    dep_payload = {
        "action": "DEPOSIT",
        "amount": 1500.0,
        "amount_display": "+$1,500.00",
        "currency": "USD",
        "recipient": "Alex Vance (Account #8842)",
        "reference": "DEP-999001",
        "actor": "alex.vance@sentinelbank.com",
        "approval": "CONFIRMED",
    }
    rec1 = test_engine.append_log(dep_payload)
    assert rec1["index"] == 6

    # Withdraw
    wth_payload = {
        "action": "WITHDRAWAL",
        "amount": 250.0,
        "amount_display": "-$250.00",
        "currency": "USD",
        "recipient": "ATM Cash Dispenser",
        "reference": "WTH-999002",
        "actor": "alex.vance@sentinelbank.com",
        "approval": "DISBURSED",
    }
    rec2 = test_engine.append_log(wth_payload)
    assert rec2["index"] == 7

    # Verification must remain VALID
    report = test_engine.verify_chain()
    assert report["status"] == "VALID"
    assert report["entries_verified"] == 8


def test_payload_tamper_detection(test_engine):
    # Tamper with the $50,000 transfer by rewriting to $50
    res = apply_attack(test_engine, "payload")
    assert "target" in res

    report = test_engine.verify_chain()
    assert report["status"] == "TAMPERED"
    assert report["category"] == "PAYLOAD_TAMPERING"


def test_delete_entry_detection(test_engine):
    # Delete entry index 1
    apply_attack(test_engine, "delete", index=1)

    report = test_engine.verify_chain()
    assert report["status"] == "TAMPERED"


def test_truncate_log_detection(test_engine):
    # Keep only first 2 entries
    apply_attack(test_engine, "tail_truncate", keep=2)

    report = test_engine.verify_chain()
    assert report["status"] == "TAMPERED"


def test_wipe_log_detection(test_engine):
    # Wipe to 0 bytes
    apply_attack(test_engine, "wipe")

    report = test_engine.verify_chain()
    assert report["status"] == "TAMPERED"
    assert report["category"] == "LOG_WIPED"


def test_reset_and_reseed_recovers_valid_state(test_engine):
    # Break it first
    apply_attack(test_engine, "wipe")
    assert test_engine.verify_chain()["status"] == "TAMPERED"

    # Reset
    test_engine.reset()
    test_engine.seed_demo_entries(_demo_payloads())

    # Check recovered
    report = test_engine.verify_chain()
    assert report["status"] == "VALID"
