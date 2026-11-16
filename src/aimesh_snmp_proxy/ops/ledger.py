"""``state_dir/onboarded.json``: the devices ``onboard`` created, and nothing else.

``onboard --remove`` deletes only what this file lists, so an entry is written
right after LibreNMS confirms a create. Writes are atomic (temp file, fsync,
rename, directory fsync); an unreadable file fails closed and stays untouched.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

LEDGER_FILE = "onboarded.json"
FORMAT_VERSION = 1
_FIELDS = {"device_id": int, "port": int, "origin": str, "added": str}


class LedgerError(RuntimeError):
    """onboarded.json cannot be read or written."""


@dataclass(frozen=True)
class Entry:
    """One device onboard created, keyed by its LibreNMS hostname."""

    hostname: str
    device_id: int
    port: int
    origin: str  # scheme://host:port of the LibreNMS that holds it
    added: str  # UTC, ISO 8601


class Ledger:
    """In-memory entries mirrored to the file after every change."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._entries: dict[str, Entry] = {}

    @classmethod
    def load(cls, path: Path) -> Ledger:
        ledger = cls(path)
        try:
            raw = ledger.path.read_bytes()
        except FileNotFoundError:
            return ledger
        except OSError as exc:
            raise LedgerError(f"{ledger.path}: cannot read: {exc.strerror}") from None
        ledger._entries = ledger._parse(raw)
        return ledger

    def entries(self) -> list[Entry]:
        """Every entry, ordered by port, then hostname."""
        return sorted(self._entries.values(), key=lambda e: (e.port, e.hostname))

    def get(self, hostname: str) -> Entry | None:
        return self._entries.get(hostname)

    def record(self, entry: Entry) -> None:
        self._entries[entry.hostname] = entry
        self.save()

    def forget(self, hostname: str) -> None:
        self._entries.pop(hostname, None)
        self.save()

    def save(self) -> None:
        devices = {
            e.hostname: {k: v for k, v in asdict(e).items() if k != "hostname"}
            for e in self.entries()
        }
        doc = {"version": FORMAT_VERSION, "devices": devices}
        data = (json.dumps(doc, indent=2) + "\n").encode()
        directory = self.path.parent
        try:
            # mkstemp creates the file 0600; the state directory must already exist.
            fd, tmp = tempfile.mkstemp(
                prefix=f".{self.path.name}.", suffix=".tmp", dir=directory
            )
            try:
                with os.fdopen(fd, "wb") as fh:
                    fh.write(data)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp, self.path)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(tmp)
                raise
            dir_fd = os.open(directory, os.O_RDONLY)
            try:
                with contextlib.suppress(OSError):  # some filesystems refuse dir fsync
                    os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError as exc:
            raise LedgerError(
                f"{self.path}: cannot write: {exc.strerror or exc}"
            ) from None

    def _fail(self, problem: str) -> LedgerError:
        return LedgerError(f"{self.path}: {problem}; fix it or move it aside")

    def _parse(self, raw: bytes) -> dict[str, Entry]:
        try:
            doc: Any = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise self._fail("not valid JSON") from None
        if not isinstance(doc, dict) or doc.get("version") != FORMAT_VERSION:
            raise self._fail(f"unsupported format (want version {FORMAT_VERSION})")
        devices = doc.get("devices")
        if set(doc) != {"version", "devices"} or not isinstance(devices, dict):
            raise self._fail("expected only version and a devices object")
        entries = {}
        for hostname, item in devices.items():
            # type(), not isinstance(): a JSON true must not pass as a device id.
            valid = (
                hostname
                and isinstance(item, dict)
                and set(item) == set(_FIELDS)
                and all(type(item[key]) is kind for key, kind in _FIELDS.items())
            )
            if not valid:
                raise self._fail("an entry is malformed")
            entries[hostname] = Entry(hostname, **item)
        return entries
