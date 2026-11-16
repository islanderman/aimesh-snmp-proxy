"""Stable SNMP port per AiMesh node: ``port_base + index``, pinned by MAC.

Index 0 is the root router. Indexes 1..N are reserved, in order, for the N
expected IPs; any other node takes the next free index above N. ``ports.json``
pins each MAC to its index forever, so a node that vanishes or changes IP never
moves another device's port. An override port wins over the pin.
"""

from __future__ import annotations

import contextlib
import ipaddress
import json
import os
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from aimesh_snmp_proxy.model import normalize_mac

PORTS_FILE = "ports.json"
FORMAT_VERSION = 1
MAX_INDEX = 255
_KEYS = frozenset({"version", "next_index", "nodes"})
_FIX_HINT = "fix it or move it aside (nodes outside the expected range may move)"


class PortMapError(RuntimeError):
    """ports.json is unusable or the index space is full."""


def _ipv4(text: str) -> str:
    try:
        return str(ipaddress.IPv4Address(text))
    except ValueError:
        raise ValueError("not an IPv4 address") from None


def _mac(text: str) -> str:
    mac = normalize_mac(text)
    if mac is None:
        raise ValueError("not a MAC address")
    return mac


class PortMap:
    """MAC-to-index pins backed by an atomically rewritten JSON file.

    A ``read_only`` map never creates, writes, or deletes a file: ``assign``
    then works in memory only, a preview of what the service would pin.
    """

    def __init__(
        self,
        path: Path,
        port_base: int,
        expected: Sequence[str] = (),
        *,
        root_ip: str | None = None,
        read_only: bool = False,
    ) -> None:
        if not 1 <= port_base <= 65535 - MAX_INDEX:
            raise ValueError(f"port_base must be between 1 and {65535 - MAX_INDEX}")
        ips = [_ipv4(ip) for ip in expected]
        if len(set(ips)) != len(ips):
            raise ValueError("duplicate expected IP")
        if len(ips) > MAX_INDEX:
            raise ValueError(f"at most {MAX_INDEX} expected IPs")
        self.path = Path(path)
        self.port_base = port_base
        self._expected = {ip: index for index, ip in enumerate(ips, start=1)}
        self._nodes: dict[str, int] = {}
        self._next = len(ips) + 1
        self._root_ip = self._ip_or_none(root_ip)
        self.read_only = read_only

    @classmethod
    def load(
        cls,
        path: Path,
        port_base: int,
        expected: Sequence[str] = (),
        *,
        root_ip: str | None = None,
        clean_temp: bool = True,
        read_only: bool = False,
    ) -> PortMap:
        """Read ``path`` if it exists; a corrupt file fails closed, untouched.

        Tools that only look, such as check-config and onboard, pass
        ``read_only=True``: no temp-file cleanup, so a daemon's write in flight
        survives, and no file or directory is ever created.
        """
        pm = cls(path, port_base, expected, root_ip=root_ip, read_only=read_only)
        if clean_temp and not read_only:
            pm._remove_stale_temp_files()
        try:
            raw = pm.path.read_bytes()
        except FileNotFoundError:
            return pm
        except OSError as exc:
            raise PortMapError(f"{pm.path}: cannot read: {exc.strerror}") from None
        pm._nodes, stored_next = pm._parse(raw)
        pm._next = max(stored_next, pm._next)
        return pm

    @property
    def root_port(self) -> int:
        return self.port_base

    def port(self, mac: str) -> int | None:
        """The pinned port of ``mac``, or None if it has none yet."""
        index = self._nodes.get(_mac(mac))
        return None if index is None else self.port_base + index

    def expected_port(self, ip: str) -> int | None:
        """The port reserved for an expected IP, or None."""
        index = self._expected.get(self._ip_or_none(ip))
        return None if index is None else self.port_base + index

    def pinned(self) -> dict[str, int]:
        """Every pinned MAC and its port, sorted by MAC."""
        return {mac: self.port_base + i for mac, i in sorted(self._nodes.items())}

    def assign(
        self,
        mac: str,
        *,
        ip: str | None = None,
        root: bool = False,
        pin: int | None = None,
    ) -> int:
        """Return the node's port, pinning and saving a new index when needed.

        The root (``root=True``, or ``ip`` equal to ``root_ip``) always serves
        ``port_base``. ``pin`` is an override port: it wins, and a node already
        holding that index moves to the next free one. A read-only map saves
        nothing.
        """
        key = _mac(mac)
        if root or (
            self._root_ip is not None and self._ip_or_none(ip) == self._root_ip
        ):
            return self.port_base
        nodes = dict(self._nodes)
        next_index = self._next
        if pin is not None:
            index = pin - self.port_base
            if not 1 <= index <= MAX_INDEX:
                raise ValueError(
                    f"override port {pin} is outside "
                    f"{self.port_base + 1}-{self.port_base + MAX_INDEX}"
                )
            if nodes.get(key) == index:
                return pin
            holder = next((m for m, i in nodes.items() if i == index), None)
            nodes[key] = index
            if holder is not None:
                nodes[holder], next_index = self._next_free(nodes, next_index)
        elif key in nodes:
            return self.port_base + nodes[key]
        else:
            index = self._expected.get(self._ip_or_none(ip), 0)
            if not index or index in nodes.values():
                index, next_index = self._next_free(nodes, next_index)
            nodes[key] = index
        if not self.read_only:
            self._write(nodes, next_index)
        self._nodes, self._next = nodes, next_index
        return self.port_base + nodes[key]

    # --- internals -----------------------------------------------------------

    @staticmethod
    def _ip_or_none(ip: str | None) -> str | None:
        """Router data is untrusted: an unparsable IP just matches no reservation."""
        if ip is None:
            return None
        try:
            return _ipv4(ip)
        except ValueError:
            return None

    def _next_free(self, nodes: dict[str, int], start: int) -> tuple[int, int]:
        owned = set(nodes.values())
        index = start
        while index in owned:
            index += 1
        if index > MAX_INDEX:
            raise PortMapError(f"{self.path}: no free port index (max {MAX_INDEX})")
        return index, index + 1

    def _fail(self, problem: str) -> PortMapError:
        return PortMapError(f"{self.path}: {problem}; {_FIX_HINT}")

    def _parse(self, raw: bytes) -> tuple[dict[str, int], int]:
        try:
            doc: Any = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise self._fail("not valid JSON") from None
        if not isinstance(doc, dict) or doc.get("version") != FORMAT_VERSION:
            raise self._fail(f"unsupported format (want version {FORMAT_VERSION})")
        if set(doc) - _KEYS:
            raise self._fail("unknown key at top level")
        stored_next = doc.get("next_index")
        if (
            isinstance(stored_next, bool)
            or not isinstance(stored_next, int)
            or not 1 <= stored_next <= MAX_INDEX + 1
        ):
            raise self._fail("next_index is invalid")
        entries = doc.get("nodes")
        if not isinstance(entries, dict):
            raise self._fail("nodes must be an object")
        nodes: dict[str, int] = {}
        owners: set[int] = set()
        for key, index in entries.items():
            if normalize_mac(key) != key:
                raise self._fail("invalid MAC key")
            if (
                isinstance(index, bool)
                or not isinstance(index, int)
                or not 1 <= index <= MAX_INDEX
            ):
                raise self._fail(f"an index is out of range 1-{MAX_INDEX}")
            if index in owners:
                raise self._fail(f"index {index} is pinned to two nodes")
            owners.add(index)
            nodes[key] = index
        return nodes, stored_next

    def _remove_stale_temp_files(self) -> None:
        """Drop temp files a crash left between write and rename."""
        if self.path.parent.is_dir():
            for leftover in self.path.parent.glob(f".{self.path.name}.*.tmp"):
                with contextlib.suppress(OSError):
                    leftover.unlink()

    def _write(self, nodes: dict[str, int], next_index: int) -> None:
        """Write a temp file, fsync, rename over ports.json, fsync the directory."""
        doc = {
            "version": FORMAT_VERSION,
            "next_index": next_index,
            "nodes": dict(sorted(nodes.items())),
        }
        data = (json.dumps(doc, indent=2) + "\n").encode()
        directory = self.path.parent
        try:
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
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
            raise PortMapError(
                f"{self.path}: cannot write: {exc.strerror or exc}"
            ) from None
