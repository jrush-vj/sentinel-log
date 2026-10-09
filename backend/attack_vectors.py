"""
attack_vectors.py -- Anti-forensic attack vectors executed against the on-disk
audit log, exactly as a root-level adversary would run them on the untrusted
host.

Everything here edits ``logs/app_audit.json`` directly (and, for the advanced
vectors, ``logs/state.json``). Nothing in this module holds key material, so
it doubles as the proof of the threat model: the adversary can rewrite bytes
but cannot forge MACs without K_j.

Vectors
-------
  payload            modify a payload field  ($50,000 -> $50)
  delete             erase a single JSON entry row
  wipe               truncate the file to 0 bytes ([] / cat /dev/null >)
  tail_truncate      drop the newest N entries (append-only header attack)
  reorder            swap two rows / splice a row elsewhere
  forge              rewrite y_j links and re-chain the payload attempt
  checkpoint_forge   rewrite logs/state.json to hide deleted entries
  max                run every vector in sequence for a full red-alert demo
"""

from __future__ import annotations

import copy
import json
from typing import Any

from crypto_engine import SentinelLogEngine

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _read_entries(engine: SentinelLogEngine) -> list[dict[str, Any]]:
    entries = engine.storage.read_all()
    return [e for e in entries if isinstance(e, dict)]


def _find_position(entries: list[dict[str, Any]], index: int) -> int:
    """Locate the array position of the record whose ``index`` matches."""
    for position, record in enumerate(entries):
        if record.get("index") == index:
            return position
    raise ValueError(f"entry {index} not found in logs/app_audit.json")


def _number_formats(value: float) -> list[str]:
    """All plausible on-disk renderings of a numeric amount."""
    rendered: list[str] = []
    if float(value).is_integer():
        rendered.append(str(int(value)))
    rendered.extend(
        [
            str(value),
            f"{value:g}",
            f"{value:.2f}",
            f"{value:,.2f}",
            f"{value:,.0f}",
            f"${value:,.2f}",
            f"${value:,.0f}",
        ]
    )
    return rendered


def _matches_number(value: Any, search: str) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    needle = search.strip().lstrip("$").replace(",", "")
    for candidate in _number_formats(float(value)):
        if search.strip() == candidate or needle == candidate.lstrip("$").replace(",", ""):
            return True
    return False


def _cast_number(replacement: str) -> float | int:
    cleaned = replacement.strip().lstrip("$").replace(",", "")
    number = float(cleaned)
    return int(number) if number.is_integer() else number


def _rewrite_payload_value(payload: dict[str, Any], search: str, replacement: str) -> list[str]:
    """Apply the search/replacement to every payload field. Returns a change log.

    Numeric fields are matched on their value; string fields (for example the
    human-readable ``amount_display``) are rewritten too, including the
    currency/comma-formatted variants, so the attack looks like a real
    anti-forensic edit rather than a byte-level find-and-replace.
    """
    changes: list[str] = []

    # --- 1. numeric fields ---------------------------------------------------
    numeric_pairs: list[tuple[str, float, float]] = []
    for key, value in list(payload.items()):
        if _matches_number(value, search):
            new_value = _cast_number(replacement)
            numeric_pairs.append((key, float(value), float(new_value)))
            payload[key] = new_value
            changes.append(f"payload.{key}: {value!r} -> {new_value!r}")

    # --- 2. formatted companions --------------------------------------------
    for key, old_number, new_number in numeric_pairs:
        old_variants = _number_formats(old_number)
        new_variants = _number_formats(new_number)
        for other_key, other_value in list(payload.items()):
            if other_key == key or not isinstance(other_value, str):
                continue
            updated = other_value
            for old_variant, new_variant in zip(old_variants, new_variants):
                if old_variant and old_variant in updated:
                    updated = updated.replace(old_variant, new_variant)
            if updated != other_value:
                payload[other_key] = updated
                changes.append(f"payload.{other_key}: {other_value!r} -> {updated!r}")

    # --- 3. plain string replacement ----------------------------------------
    for key, value in list(payload.items()):
        if isinstance(value, str) and search in value:
            updated = value.replace(search, replacement)
            payload[key] = updated
            changes.append(f"payload.{key}: {value!r} -> {updated!r}")

    return changes


# --------------------------------------------------------------------------- #
# Attack vectors
# --------------------------------------------------------------------------- #


def attack_payload(engine: SentinelLogEngine, index: int, search: str, replacement: str) -> dict[str, Any]:
    """Vector 1 -- edit a payload field in place (e.g. $50,000 -> $50)."""
    entries = _read_entries(engine)
    position = _find_position(entries, index)
    record = copy.deepcopy(entries[position])

    changes = _rewrite_payload_value(record["payload"], search, replacement)
    if not changes:
        raise ValueError(
            f"nothing matched {search!r} in entry {index}; available payload: "
            f"{json.dumps(record['payload'], sort_keys=True)}"
        )

    entries[position] = record
    engine.storage.write_all(entries)
    return {
        "vector": "payload_edit",
        "title": "Payload edit (in-place value substitution)",
        "target": f"logs/app_audit.json[entry {index}]",
        "changed_fields": changes,
        "note": (
            "The stored y_j and W_j were left untouched, exactly as a root "
            "adversary editing the JSON by hand would do."
        ),
        "expect": "PAYLOAD_TAMPERING at entry %d" % index,
    }


def attack_delete(engine: SentinelLogEngine, index: int) -> dict[str, Any]:
    """Vector 2 -- erase a single JSON entry row."""
    entries = _read_entries(engine)
    position = _find_position(entries, index)
    removed = entries.pop(position)
    engine.storage.write_all(entries)
    return {
        "vector": "record_deletion",
        "title": "Single record deletion",
        "target": f"logs/app_audit.json[entry {index}]",
        "changed_fields": [f"removed record index {removed.get('index')}"],
        "note": (
            "The MAC of the removed row is gone, but the surviving rows keep "
            "their valid MACs -- an index gap is what betrays the deletion."
        ),
        "expect": "RECORD_DELETION at entry %d" % index,
    }


def attack_wipe(engine: SentinelLogEngine) -> dict[str, Any]:
    """Vector 3 -- truncate the audit log to zero bytes."""
    size_before = engine.storage.file_info()["size_bytes"]
    engine.storage.truncate()
    return {
        "vector": "log_wiping",
        "title": "Log file wiping (cat /dev/null > logs/app_audit.json)",
        "target": "logs/app_audit.json",
        "changed_fields": [f"file size {size_before} -> 0 bytes", "contents -> []"],
        "note": "The whole forensic record was destroyed.",
        "expect": "LOG_WIPED (trusted checkpoint still holds the committed head)",
    }


def attack_tail_truncate(engine: SentinelLogEngine, keep: int) -> dict[str, Any]:
    """Vector 4 -- drop the newest N entries from an append-only file."""
    entries = _read_entries(engine)
    if keep >= len(entries):
        raise ValueError(f"log holds {len(entries)} entries; --keep must be lower")
    dropped = [e.get("index") for e in entries[keep:]]
    engine.storage.write_all(entries[:keep])
    return {
        "vector": "tail_truncation",
        "title": "Tail truncation (roll back the newest entries)",
        "target": "logs/app_audit.json",
        "changed_fields": [f"removed entries {dropped}"],
        "note": (
            "Every surviving row still verifies, so a naive 'verify each row in "
            "isolation' checker would pass. The trusted checkpoint head catches it."
        ),
        "expect": "RECORD_DELETION for the removed tail indices",
    }


def attack_reorder(engine: SentinelLogEngine, index_a: int, index_b: int) -> dict[str, Any]:
    """Vector 5 -- swap two rows (splice/relocation tampering)."""
    entries = _read_entries(engine)
    pos_a = _find_position(entries, index_a)
    pos_b = _find_position(entries, index_b)
    entries[pos_a], entries[pos_b] = entries[pos_b], entries[pos_a]
    engine.storage.write_all(entries)
    return {
        "vector": "reordering",
        "title": "Record reordering / splice",
        "target": "logs/app_audit.json",
        "changed_fields": [f"swapped positions of entries {index_a} and {index_b}"],
        "note": "Both rows carry authentic MACs, yet the chain is no longer continuous.",
        "expect": "REORDERING / CHAIN_FORK",
    }


def attack_forge(engine: SentinelLogEngine, index: int, search: str, replacement: str) -> dict[str, Any]:
    """Vector 6 -- edit a payload AND regenerate the hash links.

    This is the strongest attack a root adversary can mount without key
    material: because y_j is unkeyed, they can re-derive it for every entry
    after the edit. The MACs, however, remain those of the original entries,
    which the verifier exposes as an unauthorized signature at the tampered
    index and a knock-on mismatch afterwards.
    """
    entries = _read_entries(engine)
    position = _find_position(entries, index)
    changes = _rewrite_payload_value(entries[position]["payload"], search, replacement)
    if not changes:
        raise ValueError(f"nothing matched {search!r} in entry {index}")

    y_prev = entries[position - 1]["y"] if position > 0 else engine._genesis_y  # noqa: SLF001
    re_derived = []
    for record in entries[position:]:
        y_j = engine._hash(y_prev.encode("ascii") + engine._canonical(record["payload"]))  # noqa: SLF001
        re_derived.append({"index": record["index"], "y_old": record["y"], "y_new": y_j})
        record["y"] = y_j
        record["meta_digest"] = engine._meta_digest(record)  # noqa: SLF001
        y_prev = y_j

    engine.storage.write_all(entries)
    return {
        "vector": "chain_forgery",
        "title": "Payload edit + hash-chain re-derivation (no key material)",
        "target": "logs/app_audit.json",
        "changed_fields": changes + [f"re-derived y_{r['index']}" for r in re_derived],
        "note": (
            "y_j is an unkeyed SHA-256 chain, so the adversary can rebuild it. "
            "W_j = HMAC_{K_j}(y_j) cannot be rebuilt because K_j was zeroized "
            "immediately after entry j was written (forward security)."
        ),
        "expect": "SIGNATURE_FORGERY at entry %d and CHAIN_FORK at the head" % index,
    }


def attack_checkpoint_forge(engine: SentinelLogEngine, keep: int) -> dict[str, Any]:
    """Vector 7 -- roll back the trusted checkpoint to hide a tail deletion."""
    entries = _read_entries(engine)
    keep = min(keep, len(entries))
    if keep == 0:
        raise ValueError("--keep must be >= 1")
    trimmed = entries[:keep]
    engine.storage.write_all(trimmed)

    raw = engine.state_storage.read_raw()
    try:
        state = json.loads(raw)[0]
    except (json.JSONDecodeError, IndexError, TypeError):
        raise ValueError("trusted checkpoint is not readable")

    state["next_index"] = keep
    state["last_y"] = trimmed[-1]["y"]
    # Deliberately keep the old state_mac: the adversary does not hold the
    # checkpoint key, which is exactly why the forgery is detectable.
    engine.state_storage.write_all([state])

    return {
        "vector": "checkpoint_forgery",
        "title": "Trusted checkpoint rollback (hide the deleted tail)",
        "target": "logs/state.json",
        "changed_fields": [
            f"next_index -> {keep}",
            "last_y -> trimmed head",
            "state_mac left stale (key not held by adversary)",
        ],
        "note": (
            "Without the checkpoint HMAC key the forgery is detectable; if the "
            "attacker held it they would control the trusted head entirely, "
            "which is why it is derived from the root secret and never stored "
            "on the untrusted host."
        ),
        "expect": "STATE_FORGERY",
    }


def attack_max(engine: SentinelLogEngine) -> list[dict[str, Any]]:
    """Run the primary vectors in sequence (full demo sweep)."""
    results: list[dict[str, Any]] = []
    entries = _read_entries(engine)
    if not entries:
        return [attack_wipe(engine)]

    # 1. payload edit on the highest-value transfer
    target = max(
        entries,
        key=lambda r: float(r.get("payload", {}).get("amount", 0) or 0),
    )
    amount = float(target["payload"].get("amount", 0) or 0)
    if amount:
        results.append(
            attack_payload(
                engine,
                int(target["index"]),
                str(int(amount)),
                str(int(amount / 1000)) or "1",
            )
        )

    # 2. delete the second entry, if present
    entries = _read_entries(engine)
    if len(entries) > 1:
        results.append(attack_delete(engine, int(entries[1]["index"])))

    # 3. wipe everything
    results.append(attack_wipe(engine))
    return results


VECTORS = {
    "payload": "1",
    "delete": "2",
    "wipe": "3",
    "tail_truncate": "4",
    "reorder": "5",
    "forge": "6",
    "checkpoint_forge": "7",
    "max": "8",
}


def apply_attack(engine: SentinelLogEngine, kind: str, **kwargs: Any) -> dict[str, Any]:
    """Dispatch used by ``/api/demo/attack`` and the automated tests."""
    entries = _read_entries(engine)
    first_index = int(entries[0]["index"]) if entries else 0
    last_index = int(entries[-1]["index"]) if entries else 0

    if kind in ("payload", "forge"):
        search = str(kwargs.get("search", "50000"))
        replacement = str(kwargs.get("replacement", "50"))
        target = kwargs.get("index")
        if target is None:
            for e in entries:
                p = e.get("payload", {})
                if _matches_number(p.get("amount", 0), search):
                    target = e.get("index")
                    break
            if target is None:
                for e in entries:
                    if float(e.get("payload", {}).get("amount", 0)) > 0:
                        target = e.get("index")
                        search = str(e.get("payload", {}).get("amount", 0))
                        replacement = "10.0"
                        break
            if target is None:
                target = last_index
        function = attack_payload if kind == "payload" else attack_forge
        return function(engine, int(target), search, replacement)

    if kind == "delete":
        return attack_delete(engine, int(kwargs.get("index", first_index)))

    if kind == "wipe":
        return attack_wipe(engine)

    if kind == "tail_truncate":
        keep = int(kwargs.get("keep", max(1, len(entries) - 1)))
        return attack_tail_truncate(engine, keep)

    if kind == "reorder":
        return attack_reorder(
            engine,
            int(kwargs.get("index_a", first_index)),
            int(kwargs.get("index_b", last_index)),
        )

    if kind == "checkpoint_forge":
        keep = int(kwargs.get("keep", max(1, len(entries) - 1)))
        return attack_checkpoint_forge(engine, keep)

    if kind == "max":
        return {
            "vector": "max",
            "title": "Full anti-forensic sweep",
            "results": attack_max(engine),
            "expect": "multiple CRITICAL findings",
        }

    raise ValueError(f"unknown attack vector {kind!r}; known: {sorted(VECTORS)}")
