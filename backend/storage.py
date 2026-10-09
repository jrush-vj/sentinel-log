"""
storage.py -- Atomic, append-only JSON array storage for SentinelLog.

The log file on the untrusted host is a single JSON array. Every mutation is
performed as a full-file atomic rewrite: data is written to a temporary file
in the same directory, flushed, fsync'd, and then atomically swapped into
place with os.replace(). A crash therefore leaves either the old file or the
new file -- never a half-written one.

Nothing in this module is trusted. An attacker with root will happily edit the
file underneath us; that is precisely what the crypto engine detects.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from typing import Any, Iterable

DEFAULT_ENCODING = "utf-8"


class LogStorageError(Exception):
    """Raised when the on-disk audit log cannot be read or written."""


def _ensure_parent_directory(path: str) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)


class JsonLogStorage:
    """A tiny atomic JSON-array store used for the tamper-evident audit log."""

    def __init__(self, path: str) -> None:
        self.path = os.path.abspath(path)
        _ensure_parent_directory(self.path)
        if not os.path.exists(self.path):
            self.write_all([])

    # ------------------------------------------------------------------ read
    def read_raw(self) -> str:
        """Return the raw contents of the log file as text (for forensics)."""
        try:
            with open(self.path, "r", encoding=DEFAULT_ENCODING) as handle:
                return handle.read()
        except FileNotFoundError:
            # A root adversary deleted the file outright (or wiped the dir).
            return ""
        except OSError as exc:  # pragma: no cover - platform dependent
            raise LogStorageError(f"cannot read {self.path}: {exc}") from exc

    def read_all(self) -> list[dict[str, Any]]:
        """Return the parsed log array.

        Raises LogStorageError when the file is not valid JSON. The verifier
        converts that into a RED ALERT with an explicit diagnostic rather than
        crashing the API server.
        """
        raw = self.read_raw()
        if raw.strip() == "":
            # Truncated to zero bytes OR wiped to an empty file. Both are
            # indistinguishable from "no entries" at the storage layer, so the
            # verifier decides using the trusted state checkpoint.
            return []
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise LogStorageError(
                f"audit log at {self.path} is not valid JSON: {exc.msg} "
                f"(line {exc.lineno}, column {exc.colno})"
            ) from exc

        if not isinstance(parsed, list):
            raise LogStorageError(
                f"audit log at {self.path} must be a JSON array, "
                f"found {type(parsed).__name__}"
            )
        return parsed

    def file_info(self) -> dict[str, Any]:
        try:
            stat = os.stat(self.path)
        except OSError:
            return {
                "path": self.path,
                "size_bytes": 0,
                "modified_at": None,
                "exists": False,
            }
        return {
            "path": self.path,
            "size_bytes": stat.st_size,
            "modified_at": stat.st_mtime,
            "exists": True,
        }

    # ----------------------------------------------------------------- write
    def write_all(self, entries: Iterable[dict[str, Any]]) -> None:
        """Atomically replace the whole log file with ``entries``."""
        serialized = json.dumps(list(entries), indent=2)
        _ensure_parent_directory(self.path)

        directory = os.path.dirname(self.path) or "."
        fd, temp_path = tempfile.mkstemp(
            prefix=".app_audit.", suffix=".tmp", dir=directory
        )
        try:
            with os.fdopen(fd, "w", encoding=DEFAULT_ENCODING, newline="\n") as handle:
                handle.write(serialized)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, self.path)
        except BaseException:
            # Never leave temp files behind on failure.
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass
            raise

    def append(self, entry: dict[str, Any]) -> None:
        """Read-modify-write a single entry onto the end of the array."""
        entries = self.read_all()
        entries.append(entry)
        self.write_all(entries)

    def backup_to(self, backup_path: str) -> None:
        """Copy the current log aside (used by ``--reset`` / demo seeding)."""
        _ensure_parent_directory(backup_path)
        shutil.copyfile(self.path, backup_path)

    def truncate(self) -> None:
        """Simulate the adversary's ``cat /dev/null > logs/app_audit.json``."""
        self.write_all([])