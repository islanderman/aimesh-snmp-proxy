"""Immutable per-node snapshot shared by the collector, profiles, and SNMP layers.

Units follow design section 2: percent, bytes, seconds, Celsius, MHz, dBm, bit/s.
A null field means "unknown"; profiles omit the OID instead of inventing a value.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from itertools import pairwise

_MAC = re.compile(
    r"([0-9a-f]{2})([:-]?)([0-9a-f]{2})\2([0-9a-f]{2})\2([0-9a-f]{2})\2"
    r"([0-9a-f]{2})\2([0-9a-f]{2})\Z"
)
# Router Ethernet port IDs that map to a stable ifIndex (EthPort.if_index)
PORT_ID = re.compile(r"W[0-9]|L[1-9][0-9]?")


def normalize_mac(text: str) -> str | None:
    """``aa:bb:cc:dd:ee:ff`` for colon, hyphen, or bare-hex input; else None."""
    match = _MAC.match(text.strip().lower())
    if match is None:
        return None
    return ":".join(match.group(i) for i in (1, 3, 4, 5, 6, 7))


@dataclass(frozen=True, slots=True)
class Stat:
    """Minimum, mean, and maximum of one sample set."""

    min: float
    avg: float
    max: float

    @classmethod
    def of(cls, values: Iterable[float | None]) -> Stat | None:
        """Summarize the non-null values; None when there are none."""
        known = [v for v in values if v is not None]
        if not known:
            return None
        return cls(min(known), sum(known) / len(known), max(known))


@dataclass(frozen=True, slots=True)
class Temperature:
    """One temperature sensor reading."""

    sensor: str
    celsius: float


@dataclass(frozen=True, slots=True)
class Radio:
    """A fronthaul radio, keyed by its wl unit.

    ``band`` is the asusrouter ``ARWiFiBand`` value, for example ``2g1``,
    ``5g1``, ``5g2``, or ``6g1``. Client figures cover clients on this radio.
    """

    unit: int
    band: str
    mac: str
    state: bool
    clients: int = 0
    freq_mhz: int | None = None
    client_rssi_dbm: Stat | None = None
    client_tx_bps: Stat | None = None
    client_rx_bps: Stat | None = None


@dataclass(frozen=True, slots=True)
class Backhaul:
    """The uplink from a node to its AiMesh parent.

    ``port`` is a wired uplink's port number in the AiMesh list (re_path 1 is
    port 1, the WAN port; 16, 32, 64 are 2-4).
    """

    medium: str | None = None
    band: str | None = None
    rssi_dbm: int | None = None
    link_bps: int | None = None
    parent_mac: str | None = None
    port: int | None = None


@dataclass(frozen=True, slots=True)
class Link:
    """Traffic on one interface: ``wl<unit>``, ``wired``, or ``backhaul``.

    The octet counters are derived (sum of rate times interval, or of the byte
    deltas a standalone device's own counters report), not the router's own;
    the collector keeps them monotonic across restarts.
    """

    name: str
    rx_bps: int | None = None
    tx_bps: int | None = None
    in_octets: int | None = None
    out_octets: int | None = None


@dataclass(frozen=True, slots=True)
class Neighbor:
    """A radio link to another node, served as one LLDP remote entry.

    ``local_port`` and ``port`` are served ifNames (``backhaul``, ``wl<unit>``)
    on this node and on the peer; ``ip`` is the peer's LAN IPv4 address.
    """

    local_port: str
    mac: str
    port: str
    ip: str | None = None
    band: str | None = None


@dataclass(frozen=True, slots=True)
class EthPort:
    """One physical Ethernet port as the router reports it.

    ``native`` is the router's port ID (``W0``, ``L1``) and ``name`` the served
    ifName (``WAN``, ``LAN1``); ``label`` is the router's own display text.
    """

    native: str
    name: str
    up: bool | None = None
    speed_mbps: int | None = None
    label: str | None = None

    def __post_init__(self) -> None:
        if not PORT_ID.fullmatch(self.native):
            raise ValueError(f"port ID {self.native!r}: expected W0-W9 or L1-L99")

    @property
    def if_index(self) -> int:
        """Stable per port ID: 100-109 for W0-W9, 111-209 for L1-L99."""
        base = 100 if self.native.startswith("W") else 110
        return base + int(self.native[1:])


@dataclass(frozen=True, slots=True)
class NodeSnapshot:
    """Everything known about one AiMesh node at ``collected_at``.

    ``collected_at`` and the ``now`` given to :meth:`is_fresh` must come from
    the same clock; the daemon uses ``time.monotonic()``.
    """

    node_id: str
    sys_name: str
    mac: str
    online: bool
    role: str
    level: int
    collected_at: float
    location: str | None = None
    ip: str | None = None
    model: str | None = None
    firmware: str | None = None
    cpu_pct: float | None = None
    mem_pct: float | None = None
    cpu_core_pct: tuple[float, ...] | None = None
    mem_total_b: int | None = None
    mem_used_b: int | None = None
    uptime_s: int | None = None
    temps_c: tuple[Temperature, ...] | None = None
    backhaul: Backhaul | None = None
    radios: tuple[Radio, ...] = ()
    links: tuple[Link, ...] = ()
    neighbors: tuple[Neighbor, ...] = ()
    ports: tuple[EthPort, ...] = ()

    def __post_init__(self) -> None:
        radios = tuple(sorted(self.radios, key=lambda r: r.unit))
        for prev, cur in pairwise(radios):
            if prev.unit == cur.unit:
                raise ValueError(f"duplicate radio unit {cur.unit}")
        links = tuple(self.links)
        seen: set[str] = set()
        for link in links:
            if link.name in seen:
                raise ValueError(f"duplicate link {link.name!r}")
            seen.add(link.name)
        ports = tuple(self.ports)
        natives: set[str] = set()
        for port in ports:
            if port.native in natives:  # its ifIndex comes from the port ID
                raise ValueError(f"duplicate port {port.native!r}")
            natives.add(port.native)
        object.__setattr__(self, "radios", radios)
        object.__setattr__(self, "links", links)
        object.__setattr__(self, "neighbors", tuple(self.neighbors))
        object.__setattr__(self, "ports", ports)
        if self.cpu_core_pct is not None:
            object.__setattr__(self, "cpu_core_pct", tuple(self.cpu_core_pct))
        if self.temps_c is not None:
            object.__setattr__(self, "temps_c", tuple(self.temps_c))

    def is_fresh(self, now: float, stale_after_s: float) -> bool:
        """True while the snapshot is at most ``stale_after_s`` old.

        A future or NaN timestamp counts as stale: stale data must never be served.
        """
        age = now - self.collected_at
        return 0 <= age <= stale_after_s

    def radio(self, unit: int) -> Radio | None:
        """The radio with wl unit ``unit``, if present."""
        return next((r for r in self.radios if r.unit == unit), None)

    def link(self, name: str) -> Link | None:
        """The link named ``name``, if present."""
        return next((link for link in self.links if link.name == name), None)
