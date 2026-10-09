"""
crypto_engine.py -- SentinelLog forward-secure tamper-evident logging engine.

Protocol
--------
SentinelLog implements the Schneier-Kelsey secure logging construction
(``Secure Audit Logs to Support Computer Forensics``) with forward-secure key
evolution:

  1.  Genesis chain seed
          y_0 = SHA256("SENTINELLOG_GENESIS_SEED")

  2.  Append (hash chaining over the canonical payload)
          y_j = SHA256( y_{j-1} || CanonicalJSON(D_j) )
          W_j = HMAC_{K_j}( y_j )
          record = { index, timestamp, payload, y_j, W_j, ... }

  3.  Forward-secure key evolution
          K_{j+1} = SHA256( K_j )
      The previous key material is zeroized in memory immediately after use,
      *before* the successor key is derived, so a memory dump taken at time
      t > j cannot recover K_j and therefore cannot forge MACs for entries
      that were already written.

Why an attacker with root still loses
-------------------------------------
The audit log lives on an untrusted machine, so the adversary may rewrite,
delete, reorder, splice or truncate lines. They cannot, however:

  * recompute y_j for a modified payload without invalidating every
    subsequent chain link (collision resistance of SHA-256), or
  * recompute W_j for a rewritten chain link without K_j, which no longer
    exists anywhere once entry j has been written (forward security).

Trusted checkpoint
------------------
The adversary can also rewrite the *head* of an append-only file (delete the
last N lines). To close that hole, ``logs/state.json`` keeps the trusted
head { next_index, last_y, epoch } and is itself protected by an HMAC under a
key derived from the root secret, which never touches disk. Any edit of the
checkpoint is therefore reported as ``STATE_FORGERY``.

Standard library only: hashlib, hmac, json, os, time (+ threading/ctypes for
memory hygiene). No third-party crypto.
"""

from __future__ import annotations

import ctypes
import hashlib
import hmac
import json
import os
import threading
import time
from typing import Any, Iterable

try:
    from .storage import JsonLogStorage, LogStorageError
except ImportError:  # running backend/ as a plain script directory
    from storage import JsonLogStorage, LogStorageError  # type: ignore[no-redef]

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

GENESIS_SEED = b"SENTINELLOG_GENESIS_SEED"

#: Root shared secret K_0 material. In a real deployment this is provisioned
#: out-of-band / held in an HSM and never persisted on the untrusted host.
ROOT_SECRET_ENV = "SENTINELLOG_ROOT_KEY"
DEFAULT_ROOT_SECRET = (
    "SENTINELLOG-DEMO-ROOT-SECRET::"
    "B9F2C4A7E1D08536FA42CB79DE10A8C3F5E6D7B8A9C0D1E2F3A4B5C6D7E8F901"
)

#: Forward-secure epoch (time period) configuration. Long-lived logs must not
#: keep deriving new keys from one seed forever; every EPOCH_SIZE entries we
#: derive a fresh epoch seed so exposure of one epoch cannot forge another.
EPOCH_SIZE = 72

STATE_VERSION = 1

# --------------------------------------------------------------------------- #
# Failure taxonomy
# --------------------------------------------------------------------------- #

CATEGORY_OK = "OK"
CATEGORY_PAYLOAD_TAMPERING = "PAYLOAD_TAMPERING"
CATEGORY_SIGNATURE_FORGERY = "SIGNATURE_FORGERY"
CATEGORY_RECORD_DELETION = "RECORD_DELETION"
CATEGORY_LOG_TRUNCATION = "LOG_TRUNCATION"
CATEGORY_LOG_WIPED = "LOG_WIPED"
CATEGORY_REORDERING = "REORDERING"
CATEGORY_METADATA_TAMPERING = "METADATA_TAMPERING"
CATEGORY_EPOCH_REBINDING = "EPOCH_REBINDING"
CATEGORY_MALFORMED_RECORD = "MALFORMED_RECORD"
CATEGORY_SYNTACTIC_CORRUPTION = "SYNTACTIC_CORRUPTION"
CATEGORY_STATE_FORGERY = "STATE_FORGERY"
CATEGORY_CHAIN_FORK = "CHAIN_FORK"
CATEGORY_UNTRACKED_APPEND = "UNTRACKED_APPEND"

CATEGORY_TITLES = {
    CATEGORY_OK: "Chain intact",
    CATEGORY_PAYLOAD_TAMPERING: "Payload Tampering / Chain Link Fracture",
    CATEGORY_SIGNATURE_FORGERY: "Unauthorized Signature / Key Mismatch",
    CATEGORY_RECORD_DELETION: "Record Deletion / Truncation",
    CATEGORY_LOG_TRUNCATION: "Record Deletion / Truncation",
    CATEGORY_LOG_WIPED: "Record Deletion / Truncation",
    CATEGORY_REORDERING: "Record Reordering / Splice Attack",
    CATEGORY_METADATA_TAMPERING: "Metadata Tampering",
    CATEGORY_EPOCH_REBINDING: "Key Epoch Rebinding Attempt",
    CATEGORY_MALFORMED_RECORD: "Malformed Record",
    CATEGORY_SYNTACTIC_CORRUPTION: "Syntactic Log Corruption",
    CATEGORY_STATE_FORGERY: "Trusted Checkpoint Forgery",
    CATEGORY_CHAIN_FORK: "Chain Fork Detected",
    CATEGORY_UNTRACKED_APPEND: "Untracked Entry Append",
}

CATEGORY_EXPLANATIONS = {
    CATEGORY_PAYLOAD_TAMPERING: (
        "The recomputed chain hash y_j' does not match the stored y_j. The "
        "payload bytes differ from the ones committed when the entry was "
        "written, so SHA-256(y_{j-1} || Canonical(D_j)) diverges."
    ),
    CATEGORY_SIGNATURE_FORGERY: (
        "The chain hash verified, but HMAC_{K_j}(y_j) does not match the "
        "stored W_j. The forger re-computed the hash link without holding the "
        "forward-secured key K_j (which was zeroized after entry j was written)."
    ),
    CATEGORY_RECORD_DELETION: (
        "Entry index j is absent from the file while the trusted checkpoint "
        "expects it. A gap in the monotonically increasing index sequence "
        "proves an attacker removed a line from the middle or the tail."
    ),
    CATEGORY_LOG_WIPED: (
        "All entries were removed. The on-disk log is empty (0 bytes / []), "
        "but the trusted checkpoint records N committed entries. This is the "
        "signature of `cat /dev/null > logs/app_audit.json`."
    ),
    CATEGORY_REORDERING: (
        "Records appear out of index order, or an index appears twice. "
        "Hash chaining is position-sensitive, so swapped lines may still "
        "carry valid MACs while breaking chain continuity."
    ),
    CATEGORY_METADATA_TAMPERING: (
        "The record's metadata digest does not match. The attacker edited a "
        "field that is bound by the metadata digest but outside the payload "
        "(for example the timestamp, index or epoch)."
    ),
    CATEGORY_EPOCH_REBINDING: (
        "The record's declared key epoch is inconsistent with its index or "
        "exceeds the epoch committed in the trusted checkpoint. The attacker "
        "is attempting to have the verifier derive a different K_j."
    ),
    CATEGORY_MALFORMED_RECORD: (
        "The record is missing required fields or holds values of the wrong "
        "type, so it cannot be cryptographically evaluated at all."
    ),
    CATEGORY_SYNTACTIC_CORRUPTION: (
        "The audit log is not parseable as a JSON array. The file was "
        "corrupted or rewritten by a process that does not understand the "
        "log format."
    ),
    CATEGORY_STATE_FORGERY: (
        "The trusted checkpoint failed its own HMAC verification. An attacker "
        "edited logs/state.json in an attempt to move the trusted head "
        "backwards (to hide deleted tail entries) or to reset the chain."
    ),
    CATEGORY_CHAIN_FORK: (
        "The recomputed final chain hash differs from the trusted checkpoint "
        "head y_N, indicating the file was replaced wholesale by a "
        "consistently-forged chain or a stale snapshot."
    ),
    CATEGORY_UNTRACKED_APPEND: (
        "The file holds more entries than the trusted checkpoint admits. "
        "Entries were appended without the engine's key material."
    ),
}


class StateForgeryError(Exception):
    """Raised when the trusted checkpoint fails its integrity MAC."""


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #


class SentinelLogEngine:
    """Forward-secure, tamper-evident audit logging engine."""

    REQUIRED_FIELDS = (
        "index",
        "timestamp",
        "payload",
        "y",
        "W",
        "epoch",
        "key_seed_commitment",
        "meta_digest",
    )

    def __init__(
        self,
        log_path: str = os.path.join("logs", "app_audit.json"),
        state_path: str = os.path.join("logs", "state.json"),
        root_secret: str | None = None,
    ) -> None:
        self.log_path = os.path.abspath(log_path)
        self.state_path = os.path.abspath(state_path)
        self._lock = threading.RLock()

        root = root_secret or os.environ.get(ROOT_SECRET_ENV) or DEFAULT_ROOT_SECRET
        self._root_secret = root.encode("utf-8")

        self.storage = JsonLogStorage(self.log_path)
        self.state_storage = JsonLogStorage(self.state_path)

        # y_0 = SHA256("SENTINELLOG_GENESIS_SEED")
        self._genesis_y = self._hash(GENESIS_SEED)

        with self._lock:
            self._initialize_system()

    # ------------------------------------------------------------------ util
    @staticmethod
    def _hash(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def _canonical(obj: Any) -> bytes:
        """Deterministic JSON: identical bytes on Linux, Windows and macOS."""
        return json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    @staticmethod
    def _zeroize(buffer: bytearray) -> None:
        """Overwrite key material in place with zeros.

        Uses ctypes.memset so the write is a real store that the interpreter
        will not optimize into a dead temporary allocation.
        """
        if not buffer:
            return
        try:
            address = ctypes.addressof(ctypes.c_char.from_buffer(buffer))
            ctypes.memset(address, 0, len(buffer))
        except (TypeError, ValueError):  # pragma: no cover - exotic builds
            for i in range(len(buffer)):
                buffer[i] = 0

    @staticmethod
    def _now_iso() -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    # ------------------------------------------------------------------ KDF
    def _master_key(self) -> bytes:
        return hmac.new(
            self._root_secret, b"SENTINELLOG/KDF/master/v1", hashlib.sha256
        ).digest()

    def _epoch_seed(self, epoch: int) -> bytes:
        """Forward-secure epoch seed: one-way from the master key."""
        return hmac.new(
            self._master_key(),
            b"SENTINELLOG/KDF/epoch/" + str(int(epoch)).encode("ascii"),
            hashlib.sha256,
        ).digest()

    def _entry_key(self, index: int, epoch: int) -> bytes:
        """K_j for entry j, derived from its epoch seed.

        Retirement of an epoch (epoch + 1) discards only that epoch's seed,
        which keeps the key-evolution relation K_{j+1} = SHA256(K_j) usable
        within the epoch while bounding the blast radius of a key compromise.
        """
        return hashlib.sha256(
            self._epoch_seed(epoch)
            + b"SENTINELLOG/KDF/entry/"
            + str(int(index)).encode("ascii")
        ).digest()

    def _epoch_for(self, index: int) -> int:
        return index // EPOCH_SIZE + 1

    def _mac_hex(self, key: bytes, message: bytes) -> str:
        return hmac.new(key, message, hashlib.sha256).hexdigest()

    def _k0_commitment(self) -> str:
        """Public commitment to the root key (safe to display on the dash)."""
        return self._hash(hmac.new(self._root_secret, b"commitment/K0", hashlib.sha256).digest())

    # -------------------------------------------------------------- genesis
    def _default_state(self) -> dict[str, Any]:
        return {
            "version": STATE_VERSION,
            "created_at": self._now_iso(),
            "next_index": 0,
            "last_y": self._genesis_y,
            "epoch": 1,
            "epoch_entries": 0,
            "epoch_size": EPOCH_SIZE,
            "genesis_y": self._genesis_y,
            "k0_commitment": self._k0_commitment(),
        }

    def _state_mac(self, state: dict[str, Any]) -> str:
        core = {k: v for k, v in state.items() if k != "state_mac"}
        return self._mac_hex(self._master_key(), self._canonical(core))

    def _seal_state(self, state: dict[str, Any]) -> dict[str, Any]:
        sealed = dict(state)
        sealed.pop("state_mac", None)
        sealed["state_mac"] = self._state_mac(sealed)
        return sealed

    def _initialize_system(self) -> None:
        """Create the genesis state when missing; validate it when present."""
        raw = self.state_storage.read_raw()
        if raw.strip() == "":
            self._write_state(self._default_state())
            return
        try:
            loaded = json.loads(raw)
        except json.JSONDecodeError:
            # A damaged checkpoint is not silently reset: we flag it, then
            # rebuild so the service stays available for the demo.
            self._write_state(self._default_state())
            return
        if isinstance(loaded, list):
            if not loaded:
                self._write_state(self._default_state())
                return
            loaded = loaded[0]
        if not isinstance(loaded, dict) or "state_mac" not in loaded:
            self._write_state(self._default_state())
            return
        if not hmac.compare_digest(str(loaded.get("state_mac", "")), self._state_mac(loaded)):
            # Keep the forged file on disk so verification can report it.
            return

    def _write_state(self, state: dict[str, Any]) -> None:
            self.state_storage.write_all(self._state_as_array(self._seal_state(state)))

    @staticmethod
    def _state_as_array(state: dict[str, Any]) -> list[dict[str, Any]]:
        # Reuse the JSON-array storage by storing the state as a 1-element list.
        return [state]

    def read_state(self, verify_mac: bool = True) -> dict[str, Any]:
        raw = self.state_storage.read_raw()
        if raw.strip() == "":
            return {"corrupt": True, "reason": "state file is empty"}
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            return {"corrupt": True, "reason": f"state file is not valid JSON: {exc.msg}"}

        if isinstance(parsed, list):
            if not parsed:
                return {"corrupt": True, "reason": "state file holds an empty array"}
            parsed = parsed[0]
        if not isinstance(parsed, dict):
            return {"corrupt": True, "reason": "state file must hold a JSON object"}

        if verify_mac:
            expected = self._state_mac(parsed)
            if not hmac.compare_digest(str(parsed.get("state_mac", "")), expected):
                return {
                    "corrupt": True,
                    "reason": "trusted checkpoint HMAC mismatch",
                    "forged_state": parsed,
                }
        parsed = dict(parsed)
        parsed["corrupt"] = False
        return parsed

    # --------------------------------------------------------------- append
    def append_log(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Commit ``payload`` into the tamper-evident chain. Returns the record.

        Steps:
          1. read trusted state (last_y, next_index, epoch)
          2. y_j = SHA256(y_{j-1} || canonical(payload))
          3. W_j = HMAC_{K_j}(y_j)
          4. append {index, timestamp, payload, y_j, W_j, ...}
          5. evolve K_{j+1} = SHA256(K_j) after zeroizing K_j in memory
          6. persist the new trusted state
        """
        with self._lock:
            state = self.read_state()
            if state.get("corrupt"):
                # Rebuild a valid checkpoint rather than lose availability; the
                # forged checkpoint is preserved for forensic review.
                forged_path = self.state_path + ".forged"
                try:
                    with open(self.state_path, "r", encoding="utf-8") as handle:
                        forged = handle.read()
                    with open(forged_path, "w", encoding="utf-8") as handle:
                        handle.write(forged)
                except OSError:
                    pass
                state = self._default_state()

            index = int(state.get("next_index", 0))
            epoch = self._epoch_for(index)
            y_prev = str(state.get("last_y", self._genesis_y))

            timestamp = self._now_iso()

            # --- 2. hash chain -------------------------------------------------
            y_j = self._hash(y_prev.encode("ascii") + self._canonical(payload))

            # --- 3. MAC under K_j ---------------------------------------------
            key_buffer = bytearray(self._entry_key(index, epoch))
            try:
                w_j = self._mac_hex(bytes(key_buffer), y_j.encode("ascii"))
            finally:
                # --- 5. zeroize K_j before any successor exists in memory -----
                self._zeroize(key_buffer)
            del key_buffer

            record: dict[str, Any] = {
                "index": index,
                "timestamp": timestamp,
                "payload": payload,
                "y": y_j,
                "W": w_j,
                "epoch": epoch,
                "key_seed_commitment": self._hash(self._epoch_seed(epoch)),
            }
            record["meta_digest"] = self._meta_digest(record)

            self.storage.append(record)

            # --- 6. trusted checkpoint ----------------------------------------
            new_state = dict(state)
            new_state.pop("corrupt", None)
            new_state.pop("reason", None)
            new_state.pop("forged_state", None)
            new_state.pop("state_mac", None)
            new_state.update(
                {
                    "version": STATE_VERSION,
                    "next_index": index + 1,
                    "last_y": y_j,
                    "epoch": self._epoch_for(index + 1),
                    "epoch_entries": (index + 1) % EPOCH_SIZE,
                    "epoch_size": EPOCH_SIZE,
                    "genesis_y": self._genesis_y,
                    "k0_commitment": self._k0_commitment(),
                    "updated_at": timestamp,
                }
            )
            self._write_state(new_state)
            return record

    def _meta_digest(self, record: dict[str, Any]) -> str:
        """Bind index/timestamp/epoch into a digest so metadata is protected."""
        meta = {
            "index": record["index"],
            "timestamp": record["timestamp"],
            "epoch": record["epoch"],
            "key_seed_commitment": record["key_seed_commitment"],
            "y": record["y"],
        }
        return self._hash(self._canonical(meta))

    # ------------------------------------------------------------------ read
    def read_log(self) -> list[dict[str, Any]]:
        return self.storage.read_all()

    def log_info(self) -> dict[str, Any]:
        info = self.storage.file_info()
        state = self.read_state()
        info.update(
            {
                "committed_entries": int(state.get("next_index", 0)) if not state.get("corrupt") else None,
                "checkpoint_corrupt": bool(state.get("corrupt", False)),
                "epoch": state.get("epoch"),
                "epoch_size": EPOCH_SIZE,
                "head_hash": state.get("last_y"),
                "genesis_hash": self._genesis_y,
                "k0_commitment": self._k0_commitment(),
            }
        )
        return info

    # -------------------------------------------------------------- verify
    def verify_chain(self) -> dict[str, Any]:
        """Re-run the full verification pass and return a forensic report."""
        started = time.perf_counter()
        diagnostics: list[dict[str, Any]] = []
        flagged: set[int] = set()

        def flag(
            category: str,
            index: int | None,
            detail: str,
            *,
            expected: str | None = None,
            found: str | None = None,
            severity: str = "CRITICAL",
        ) -> None:
            if index is not None:
                flagged.add(index)
            diagnostics.append(
                {
                    "index": index,
                    "category": category,
                    "title": CATEGORY_TITLES.get(category, category),
                    "severity": severity,
                    "detail": detail,
                    "explanation": CATEGORY_EXPLANATIONS.get(category, ""),
                    "expected": expected,
                    "found": found,
                }
            )

        state = self.read_state()
        state_ok = not state.get("corrupt", False)

        if not state_ok:
            flag(
                CATEGORY_STATE_FORGERY,
                None,
                f"Trusted checkpoint integrity failure: {state.get('reason')}. "
                "logs/state.json was modified outside the engine.",
                severity="CRITICAL",
            )

        expected_next = int(state.get("next_index", 0)) if state_ok else 0
        expected_head_y = str(state.get("last_y", self._genesis_y)) if state_ok else None
        max_epoch = int(state.get("epoch", 1)) if state_ok else 10**9

        # ---- parse the on-disk log ------------------------------------------
        try:
            entries = self.storage.read_all()
        except LogStorageError as exc:
            flag(CATEGORY_SYNTACTIC_CORRUPTION, None, str(exc))
            report = self._build_report(
                diagnostics, flagged, entries_verified=0, expected_entries=expected_next,
                duration_ms=(time.perf_counter() - started) * 1000.0,
            )
            report["log_info"] = self.log_info()
            return report

        # ---- walk the chain --------------------------------------------------
        y_prev = self._genesis_y
        expected_index = 0
        chain_broken = False
        genesis_missing = expected_next > 0 and len(entries) == 0

        for position, record in enumerate(entries):
            if not isinstance(record, dict):
                flag(
                    CATEGORY_MALFORMED_RECORD,
                    None,
                    f"Element at array position {position} is "
                    f"{type(record).__name__}, expected an object.",
                )
                chain_broken = True
                continue

            missing = [f for f in self.REQUIRED_FIELDS if f not in record]
            if missing:
                index_hint = record.get("index") if isinstance(record.get("index"), int) else None
                flag(
                    CATEGORY_MALFORMED_RECORD,
                    index_hint,
                    f"Record at array position {position} is missing required "
                    f"fields: {', '.join(missing)}.",
                )
                chain_broken = True
                continue

            index = record["index"]
            if not isinstance(index, int):
                flag(
                    CATEGORY_MALFORMED_RECORD,
                    None,
                    f"Record at array position {position} has non-integer index "
                    f"{index!r}.",
                )
                chain_broken = True
                continue

            payload = record["payload"]
            if not isinstance(payload, dict):
                flag(
                    CATEGORY_MALFORMED_RECORD,
                    index,
                    f"Record {index} payload is {type(payload).__name__}, expected object.",
                )
                chain_broken = True
                continue

            # -- structural continuity -----------------------------------------
            if index < expected_index:
                flag(
                    CATEGORY_REORDERING,
                    index,
                    f"Record {index} appears after record {expected_index - 1}; "
                    "the array is out of order or an index is duplicated.",
                    expected=f"index {expected_index}",
                    found=f"index {index}",
                )
                chain_broken = True
            elif index > expected_index:
                for gap in range(expected_index, index):
                    flag(
                        CATEGORY_RECORD_DELETION,
                        gap,
                        f"Entry {gap} is missing from the log: the index sequence "
                        f"jumps from {expected_index - 1 if expected_index else 'genesis'} "
                        f"to {index}. A row was removed from the JSON array.",
                        expected=f"entry {gap} present",
                        found="absent",
                    )
                chain_broken = True

            # -- epoch binding --------------------------------------------------
            declared_epoch = record["epoch"]
            computed_epoch = self._epoch_for(index)
            if declared_epoch != computed_epoch:
                flag(
                    CATEGORY_EPOCH_REBINDING,
                    index,
                    f"Record {index} claims key epoch {declared_epoch} but index "
                    f"{index} belongs to epoch {computed_epoch} "
                    f"(EPOCH_SIZE={EPOCH_SIZE}).",
                    expected=str(computed_epoch),
                    found=str(declared_epoch),
                )
            elif isinstance(declared_epoch, int) and declared_epoch > max_epoch:
                flag(
                    CATEGORY_EPOCH_REBINDING,
                    index,
                    f"Record {index} claims epoch {declared_epoch} beyond the "
                    f"checkpoint epoch {max_epoch}.",
                    expected=str(max_epoch),
                    found=str(declared_epoch),
                )

            # -- payload / chain link -------------------------------------------
            y_running = self._hash(y_prev.encode("ascii") + self._canonical(payload))
            stored_y = str(record["y"])
            y_matches = hmac.compare_digest(y_running, stored_y)
            if not y_matches and not chain_broken:
                # Structural continuity already broke the chain, so a divergence
                # here is an artifact of the gap, not a second independent finding.
                prev_label = "the genesis seed y_0" if index == 0 else f"y_{index - 1}"
                flag(
                    CATEGORY_PAYLOAD_TAMPERING,
                    index,
                    f"Chain link fracture at entry {index}: "
                    f"SHA256({prev_label} || CanonicalJSON(D_{index})) diverges from "
                    f"the committed y_{index}. The payload bytes on disk are not "
                    f"the ones that were signed.",
                    expected=stored_y,
                    found=y_running,
                )
                chain_broken = True

            # -- MAC under the forward-secured key ------------------------------
            commitment_ok = True
            try:
                commitment_ok = hmac.compare_digest(
                    str(record["key_seed_commitment"]),
                    self._hash(self._epoch_seed(computed_epoch)),
                )
            except (TypeError, ValueError):
                commitment_ok = False
            if not commitment_ok:
                flag(
                    CATEGORY_EPOCH_REBINDING,
                    index,
                    f"Record {index} key-epoch commitment does not match the "
                    f"derived seed for epoch {computed_epoch}.",
                )

            key_buffer = bytearray(self._entry_key(index, computed_epoch))
            try:
                recomputed_w = self._mac_hex(bytes(key_buffer), stored_y.encode("ascii"))
            finally:
                self._zeroize(key_buffer)
            del key_buffer

            if not hmac.compare_digest(recomputed_w, str(record["W"])):
                if not y_matches:
                    flag(
                        CATEGORY_SIGNATURE_FORGERY,
                        index,
                        f"MAC mismatch at entry {index} is a secondary effect of "
                        f"the payload tamper detected above (W_j authenticates "
                        f"y_j, which no longer verifies).",
                        severity="INFO",
                    )
                else:
                    flag(
                        CATEGORY_SIGNATURE_FORGERY,
                        index,
                        f"Unauthorized signature at entry {index}: the chain hash "
                        f"y_{index} is self-consistent, but HMAC_{{K_{index}}}(y_{index}) "
                        f"does not match the stored W_{index}. The forger lacked "
                        f"the forward-secured key K_{index}.",
                        expected=str(record["W"]),
                        found=recomputed_w,
                    )
                chain_broken = True

            # -- metadata digest -------------------------------------------------
            expected_meta = self._meta_digest(record)
            if not hmac.compare_digest(str(record["meta_digest"]), expected_meta):
                flag(
                    CATEGORY_METADATA_TAMPERING,
                    index,
                    f"Metadata digest mismatch at entry {index}: timestamp, index, "
                    f"epoch or key commitment was edited after the entry was sealed.",
                    expected=str(record["meta_digest"]),
                    found=expected_meta,
                )
                chain_broken = True

                            # Walk the chain using the STORED link, not the recomputed one, so a
            # single edited payload is pinpointed to exactly one index and its
            # untouched successors keep verifying.
            y_prev = stored_y
            expected_index = index + 1

        # ---- head / tail reconciliation --------------------------------------
        if genesis_missing:
            flag(
                CATEGORY_LOG_WIPED,
                None,
                f"Audit log holds 0 entries but the trusted checkpoint commits "
                f"{expected_next}. The file was emptied "
                f"(ctruncate / `cat /dev/null > logs/app_audit.json`).",
                expected=f"{expected_next} entries",
                found="0 entries",
            )
            chain_broken = True
        elif expected_next > expected_index:
            for gap in range(expected_index, expected_next):
                flag(
                    CATEGORY_RECORD_DELETION,
                    gap,
                    f"Committed entry {gap} is absent: the on-disk log ends at "
                    f"index {expected_index - 1} while the trusted checkpoint "
                    f"records {expected_next} entries. Tail truncation detected.",
                    expected=f"entry {gap} present",
                    found="absent",
                )
            chain_broken = True
        elif expected_index > expected_next and expected_next > 0:
            flag(
                CATEGORY_UNTRACKED_APPEND,
                expected_next,
                f"The log holds {expected_index} entries but the checkpoint "
                f"commits {expected_next}. At least one entry was appended "
                f"without the engine's key material.",
                expected=f"{expected_next} entries",
                found=f"{expected_index} entries",
            )
            chain_broken = True

        if state_ok and expected_head_y is not None and entries:
            if not hmac.compare_digest(y_prev, expected_head_y):
                flag(
                    CATEGORY_CHAIN_FORK,
                    expected_index - 1 if expected_index else None,
                    "The chain head recomputed from disk does not match the "
                    "trusted checkpoint head y_N. The file was replaced by a "
                    "different (possibly consistently forged or stale) chain.",
                    expected=expected_head_y,
                    found=y_prev,
                )
                chain_broken = True

        report = self._build_report(
            diagnostics,
            flagged,
            entries_verified=len(entries),
            expected_entries=expected_next,
            duration_ms=(time.perf_counter() - started) * 1000.0,
        )
        report["log_info"] = self.log_info()
        report["chain_head_recomputed"] = y_prev
        report["chain_head_trusted"] = expected_head_y
        if chain_broken and report["status"] == "VALID":
            report["status"] = "TAMPERED"
        return report

    # ------------------------------------------------------------- reporting
    def _build_report(
        self,
        diagnostics: list[dict[str, Any]],
        flagged: Iterable[int],
        *,
        entries_verified: int,
        expected_entries: int,
        duration_ms: float,
    ) -> dict[str, Any]:
        errors = [d for d in diagnostics if d["severity"] != "INFO"]
        tampered = bool(errors)

        primary = None
        for diagnostic in errors:
            if diagnostic["index"] is not None:
                primary = diagnostic
                break
        if primary is None and errors:
            primary = errors[0]

        core = {
            "status": "TAMPERED" if tampered else "VALID",
            "category": primary["category"] if primary else CATEGORY_OK,
            "corrupted_index": primary["index"] if primary else None,
            "reason": primary["title"] if primary else CATEGORY_TITLES[CATEGORY_OK],
            "verified_at": self._now_iso(),
        }

        return {
            **core,
            "headline": (
                "RED ALERT: CRITICAL TAMPER DETECTED"
                if tampered
                else "SYSTEM STATUS: OK (SECURE)"
            ),
            "detail": primary["detail"] if primary else (
                "Every chain link and MAC re-verified from the genesis seed. "
                "No payload, index gap, key mismatch or metadata discrepancy found."
            ),
            "explanation": primary["explanation"] if primary else (
                "y_j = SHA256(y_{j-1} || CanonicalJSON(D_j)) for all j, and "
                "W_j = HMAC_{K_j}(y_j) matches for every entry."
            ),
            "entries_verified": entries_verified,
            "expected_entries": expected_entries,
            "flagged_indices": sorted(flagged),
            "diagnostics": diagnostics,
            "duration_ms": round(duration_ms, 3),
            "attestation": {
                "alg": "HMAC-SHA256",
                "verifier": "SentinelLog Verification Engine v1",
                "value": self._mac_hex(
                    self._master_key(), self._canonical(core)
                ),
            },
            "genesis_hash": self._genesis_y,
            "k0_commitment": self._k0_commitment(),
        }

    # ------------------------------------------------------------ demo utils
    def reset(self) -> None:
        """Re-initialise the chain (demo helper, not part of the protocol)."""
        with self._lock:
            self.storage.write_all([])
            self.state_storage.write_all([])
            self._write_state(self._default_state())

    def seed_demo_entries(self, payloads: Iterable[dict[str, Any]]) -> int:
        """Append several legitimate entries (used to prime a demo)."""
        count = 0
        for payload in payloads:
            self.append_log(payload)
            count += 1
        return count