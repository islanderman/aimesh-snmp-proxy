"""Turn asusrouter data into NodeSnapshots (design section 2).

The library reads ASUS rates as binary units (traffic as Kibit/s, link rates
as Mibit/s); the router UI shows decimal kbit/s and Mbit/s, so this module
restores decimal values (raw unit unverified on a live device). Octet
counters are derived: the sum of rate times interval, kept in
``state_dir/counters.json`` so they stay monotonic across restarts.
"""

from __future__ import annotations

import ipaddress
import logging
import math
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from asusrouter.modules.aimesh import ARAiMeshMedium, ARAiMeshRole, ARAiMeshTopology
from asusrouter.modules.aimesh.topology import ARAiMeshBackhaul, ARAiMeshNode
from asusrouter.modules.clients.model import ARClient
from asusrouter.modules.clock import ARClockField
from asusrouter.modules.common.connection import ARConnectionType
from asusrouter.modules.common.metrics import ARMetricType
from asusrouter.modules.ports.enums import ARPortProperty, ARPortSpeed
from asusrouter.modules.system_status import ARSystemType, legacy
from asusrouter.modules.traffic.enums import ARTrafficType
from asusrouter.modules.wifi import ARWiFiBand, ARWiFiField, ARWiFiFrequency
from asusrouter.tools.identifiers import IpAddress, MacAddress

from aimesh_snmp_proxy.collector import statefile
from aimesh_snmp_proxy.model import (
    PORT_ID,
    Backhaul,
    EthPort,
    Link,
    Neighbor,
    NodeSnapshot,
    Radio,
    Stat,
    Temperature,
)

_LOG = logging.getLogger(__name__)

COUNTERS_FORMAT = 1
COUNTER_MAX = 2**64
DETAIL_MAX_AGE_S = 600.0  # two 300 s detail polls; a missed one keeps the fields
MAX_TEXT = 64
_KIBI = 2**10
_MEBI = 2**20
_WIRELESS_MEDIA = frozenset({ARAiMeshMedium.WIRELESS, ARAiMeshMedium.MLO})
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_WAN_PORT = "W0"  # a Link named by its port ID is that Ethernet row's counter
_WAN_UPLINK = 1  # Backhaul.port of re_path 1: the wired uplink is the WAN port
_OWN_WIRED = "eth"  # a node's own netdev WIRED, every wired port; never a row


# --- small converters -----------------------------------------------------------


def mac_text(mac: Any) -> str | None:
    """``aa:bb:cc:dd:ee:ff`` of a library MacAddress, read from its bytes."""
    if not isinstance(mac, MacAddress):
        return None
    return mac.to_bytes().hex(":")


def ip_text(ip: Any) -> str | None:
    if not isinstance(ip, IpAddress):
        return None
    return str(ipaddress.ip_address(ip.to_bytes()))


def _finite(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value) if math.isfinite(value) else None


def restore_kbps(value: Any) -> int | None:
    """Library bit/s, read as Kibit/s, back to decimal kbit/s in bit/s."""
    number = _finite(value)
    return None if number is None else round(number / _KIBI * 1_000)


def restore_mbps(value: Any) -> int | None:
    """Library bit/s, read as Mibit/s, back to decimal Mbit/s in bit/s."""
    number = _finite(value)
    return None if number is None else round(number / _MEBI * 1_000_000)


def _percent(value: Any) -> float | None:
    number = _finite(value)
    return number if number is not None and 0 <= number <= 100 else None


def _text(value: Any) -> str | None:
    """Router-supplied text for sysDescr: no control characters, bounded."""
    if not isinstance(value, str):
        return None
    cleaned = _CONTROL.sub("", value).strip()[:MAX_TEXT]
    return cleaned or None


def channel_to_mhz(band: str, channel: Any) -> int | None:
    """Centre frequency of a Wi-Fi channel (IEEE 802.11 channel numbering)."""
    if isinstance(channel, bool) or not isinstance(channel, int) or channel <= 0:
        return None
    match band[:2]:
        case "2g":
            if channel == 14:
                return 2484
            return 2407 + 5 * channel if channel <= 13 else None
        case "5g":
            return 5000 + 5 * channel
        case "6g":
            return 5935 if channel == 2 else 5950 + 5 * channel
    return None


# --- topology -------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class MeshRadio:
    unit: int
    band: str
    mac: str
    state: bool
    dwb: bool = False  # the node's dedicated wireless backhaul radio


@dataclass(frozen=True, slots=True)
class MeshNode:
    """One entry of the AiMesh list, in plain types the collector owns."""

    mac: str
    online: bool
    role: str
    level: int
    ip: str | None = None
    model: str | None = None
    firmware: str | None = None
    backhaul: Backhaul | None = None
    radios: tuple[MeshRadio, ...] = ()
    neighbors: tuple[Neighbor, ...] = ()


def _radios(node: ARAiMeshNode) -> tuple[MeshRadio, ...]:
    radios: dict[int, MeshRadio] = {}
    for band, radio in node.radios.items():
        if radio.unit is None or radio.unit in radios:
            continue
        mac = mac_text(radio.mac_fh) or mac_text(radio.mac_ap) or ""
        # No wlN_radio flag: a radio with a BSSID is taken as up
        state = radio.state if radio.state is not None else bool(mac)
        radios[radio.unit] = MeshRadio(
            radio.unit, band.value, mac, state, dwb=bool(radio.dwb)
        )
    return tuple(radios[unit] for unit in sorted(radios))


def _backhaul(backhaul: ARAiMeshBackhaul | None) -> Backhaul | None:
    if backhaul is None:
        return None
    link_bps = None
    speed = backhaul.link_rate
    if backhaul.medium not in _WIRELESS_MEDIA and speed not in (
        ARPortSpeed.UNKNOWN,
        ARPortSpeed.DOWN,
    ):
        link_bps = int(speed) * 1_000_000
    band = backhaul.band
    return Backhaul(
        medium=None
        if backhaul.medium is ARAiMeshMedium.UNKNOWN
        else backhaul.medium.value,
        band=None if band in (None, ARWiFiBand.UNKNOWN) else band.value,
        rssi_dbm=backhaul.rssi,
        link_bps=link_bps,
        parent_mac=mac_text(backhaul.mac_parent),
        port=backhaul.port,
    )


def mesh_nodes(topology: ARAiMeshTopology) -> dict[str, MeshNode]:
    """Every node of the AiMesh list, keyed and sorted by normalized MAC."""
    nodes: dict[str, MeshNode] = {}
    for node in topology.nodes.values():
        mac = mac_text(node.mac)
        if mac is None:
            continue
        firmware = node.firmware
        nodes[mac] = MeshNode(
            mac=mac,
            online=bool(node.online),
            role="router" if node.role is ARAiMeshRole.ROUTER else "node",
            level=int(node.level),
            ip=ip_text(node.ip),
            model=_text(node.model or node.model_display or node.model_original),
            firmware=_text(str(firmware)) if firmware.major is not None else None,
            backhaul=_backhaul(node.backhaul),
            radios=_radios(node),
        )
    links = _radio_links(nodes)
    return {
        mac: replace(node, neighbors=tuple(links[mac]))
        for mac, node in sorted(nodes.items())
    }


def standalone_node(
    identity: Any, wifi: Mapping[Any, Any], *, ip: str | None
) -> MeshNode | None:
    """The logged-in device as the only node, for an empty AiMesh list.

    ``identity`` is the library's ``ARDeviceIdentity`` and ``wifi`` an
    ``ARWiFiSource`` result; a radio without a state flag counts as off.
    """
    mac = mac_text(getattr(identity, "mac", None))
    if mac is None:
        return None
    radios = []
    for band, unit in (getattr(identity, "wifi", None) or {}).items():
        fields = wifi.get(band)
        fields = fields if isinstance(fields, Mapping) else {}
        state = fields.get(ARWiFiField.STATE)
        radio_mac = mac_text(fields.get(ARWiFiField.MAC)) or ""
        radios.append(
            MeshRadio(
                unit, band.value, radio_mac, state if isinstance(state, bool) else False
            )
        )
    firmware = getattr(identity, "firmware", None)
    known = firmware is not None and firmware.major is not None
    return MeshNode(
        mac=mac,
        online=True,
        role="router",
        level=0,
        ip=ip,
        model=_text(getattr(identity, "model", None)),
        firmware=_text(str(firmware)) if known else None,
        radios=tuple(sorted(radios, key=lambda radio: radio.unit)),
    )


def _parent_radio(parent: MeshNode, band: str | None) -> MeshRadio | None:
    """The parent radio a wireless backhaul in ``band`` attaches to, if certain.

    asusrouter drops the parent BSSID the child names (pap*), so two parent
    radios in one band are told apart only by the dedicated backhaul radio.
    """
    if not band:
        return None
    same = [radio for radio in parent.radios if radio.band[:2] == band[:2]]
    if len(same) == 1:
        return same[0]
    dwb = [radio for radio in same if radio.dwb]
    return dwb[0] if len(dwb) == 1 else None


def _radio_links(nodes: Mapping[str, MeshNode]) -> dict[str, list[Neighbor]]:
    """Each wireless backhaul as a neighbor of the child and of its parent."""
    links: dict[str, list[Neighbor]] = {mac: [] for mac in nodes}
    for mac, node in nodes.items():
        backhaul = node.backhaul
        # Wired uplinks get none: the switches already report those links over
        # LLDP. MLO names no single parent radio, so it gets none either.
        if backhaul is None or backhaul.medium != ARAiMeshMedium.WIRELESS.value:
            continue
        parent = nodes.get(backhaul.parent_mac or "")
        radio = _parent_radio(parent, backhaul.band) if parent else None
        if parent is None or radio is None:
            continue
        port = f"wl{radio.unit}"
        links[mac].append(Neighbor("backhaul", parent.mac, port, parent.ip, radio.band))
        links[parent.mac].append(Neighbor(port, mac, "backhaul", node.ip, radio.band))
    return links


# --- Ethernet ports -----------------------------------------------------------------


def _port_name(native: str) -> str:
    """The served ifName: ``W0`` is ``WAN``, ``W1`` ``WAN2``, ``L3`` ``LAN3``."""
    number = int(native[1:])
    if native.startswith("L"):
        return f"LAN{number}"
    return "WAN" if number == 0 else f"WAN{number + 1}"


def eth_ports(data: Any) -> dict[str, tuple[EthPort, ...]]:
    """Ethernet ports per node MAC from an ``ARPortsSource`` result.

    Only WAN and LAN ports (``W<n>``, ``L<n>``) are kept; USB and the AI board
    are not Ethernet. An unknown link rate stays None, never a guess.
    """
    result: dict[str, tuple[EthPort, ...]] = {}
    if not isinstance(data, Mapping):
        return result
    for key, entry in data.items():
        mac = mac_text(key)
        rows = getattr(entry, "ports", None)
        if mac is None or not isinstance(rows, list):
            continue
        ports = []
        natives: set[str] = set()
        for row in rows:
            native = (
                row.get(ARPortProperty.NATIVE_NAME) if isinstance(row, dict) else None
            )
            if not isinstance(native, str) or not PORT_ID.fullmatch(native):
                continue
            if native in natives:  # one row per port ID (its ifIndex)
                continue
            natives.add(native)
            state, speed = (
                row.get(ARPortProperty.STATE),
                row.get(ARPortProperty.LINK_RATE),
            )
            known = isinstance(speed, ARPortSpeed) and speed is not ARPortSpeed.UNKNOWN
            ports.append(
                EthPort(
                    native=native,
                    name=_port_name(native),
                    up=state if isinstance(state, bool) else None,
                    speed_mbps=int(speed) if known else None,
                    label=_text(row.get(ARPortProperty.UI_DISPLAY)),
                )
            )
        result[mac] = tuple(sorted(ports, key=lambda port: port.if_index))
    return result


# --- usage and detail -------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Usage:
    """CPU and memory percent from the router's diagnostics, per node."""

    cpu_pct: float | None
    mem_pct: float | None


def usage_for(status: Mapping[Any, Any], mac: str) -> Usage:
    """The node's entry of an ``ARSystemStatusSource`` result."""
    for key, metrics in status.items():
        if mac_text(key) == mac and isinstance(metrics, Mapping):
            cpu = metrics.get(ARSystemType.CPU) or {}
            ram = metrics.get(ARSystemType.RAM) or {}
            return Usage(
                _percent(cpu.get(ARMetricType.USAGE)),
                _percent(ram.get(ARMetricType.USAGE)),
            )
    return Usage(None, None)


@dataclass(frozen=True)
class DeviceDetail:
    """Extras only the logged-in device reports about itself (design section 2)."""

    collected_at: float
    cpu_pct: float | None = None
    cpu_core_pct: tuple[float, ...] | None = None
    mem_pct: float | None = None
    mem_total_b: int | None = None
    mem_used_b: int | None = None
    uptime_s: int | None = None
    temps_c: tuple[Temperature, ...] | None = None
    freq_mhz: Mapping[int, int] = field(default_factory=dict)
    cpu_counters: Any = field(default=None, compare=False, repr=False)


def _bytes(value: Any) -> int | None:
    number = _finite(value)
    return int(number) if number is not None and number >= 0 else None


def parse_detail(
    legacy_raw: Mapping[str, Any],
    extras: Mapping[str, Any],
    units: Mapping[ARWiFiBand, int],
    prev: DeviceDetail | None,
    *,
    now: float,
) -> DeviceDetail:
    """Build the detail from appGet cpu/ram, clock, temperature, and Wi-Fi data.

    CPU ticks are cumulative, so core usage appears from the second sample on.
    """
    cpu_raw = legacy_raw.get("cpu_usage")
    counters = legacy.parse_cpu(cpu_raw if isinstance(cpu_raw, dict) else {})
    aggregate, cores = legacy.translate_cpu(
        counters, prev.cpu_counters if prev is not None else None
    )
    ram_raw = legacy_raw.get("memory_usage")
    ram = legacy.parse_ram(ram_raw if isinstance(ram_raw, dict) else {})
    uptime = _finite((extras.get("clock") or {}).get(ARClockField.UPTIME))
    temps = sorted(
        (
            Temperature(sensor.value, celsius)
            for sensor, value in (extras.get("temperature") or {}).items()
            if (celsius := _finite(value)) is not None
        ),
        key=lambda t: t.sensor,
    )
    freq: dict[int, int] = {}
    for band, fields in (extras.get("wifi") or {}).items():
        unit = units.get(band)
        mhz = channel_to_mhz(band.value, fields.get(ARWiFiField.CHANNEL))
        if unit is not None and mhz is not None:
            freq[unit] = mhz
    return DeviceDetail(
        collected_at=now,
        cpu_pct=_percent(aggregate),
        cpu_core_pct=tuple(cores[core] for core in sorted(cores)) or None,
        mem_pct=_percent(ram.get(ARMetricType.USAGE)),
        mem_total_b=_bytes(ram.get(ARMetricType.TOTAL)),
        mem_used_b=_bytes(ram.get(ARMetricType.USED)),
        uptime_s=int(uptime) if uptime is not None and uptime >= 0 else None,
        temps_c=tuple(temps) or None,
        freq_mhz=freq,
        cpu_counters=counters,
    )


# --- clients and links ------------------------------------------------------------


@dataclass
class _Bucket:
    clients: set[str] = field(default_factory=set)
    rssi: list[float | None] = field(default_factory=list)
    tx: list[float | None] = field(default_factory=list)
    rx: list[float | None] = field(default_factory=list)


def _radio_for(
    radios: tuple[MeshRadio, ...],
    band: ARWiFiBand | None,
    frequency: ARWiFiFrequency,
) -> int | None:
    """The client's radio: exact band, else the lowest unit on its frequency.

    Single-link clients report only a frequency, so on a tri-band node both
    5 GHz radios match; the lower unit gets the client (an assumption).
    """
    if band is not None and band is not ARWiFiBand.UNKNOWN:
        exact = next((r.unit for r in radios if r.band == band.value), None)
        if exact is not None:
            return exact
        prefix = band.value[:2]
    else:
        prefix = frequency.value[:2]
    return next((r.unit for r in radios if r.band[:2] == prefix), None)


def _client_stats(node: MeshNode, clients: Iterable[ARClient]) -> dict[int, _Bucket]:
    buckets = {radio.unit: _Bucket() for radio in node.radios}
    for client in clients:
        conn = client.connection
        if not client.online or conn is None:
            continue
        if (
            conn.type is not ARConnectionType.WIRELESS
            or mac_text(conn.node) != node.mac
        ):
            continue
        for link in conn.links:
            unit = _radio_for(node.radios, link.band, link.frequency)
            if unit is None:
                continue
            bucket = buckets[unit]
            bucket.clients.add(mac_text(client.mac) or "")
            bucket.rssi.append(_finite(link.rssi))
            bucket.tx.append(restore_mbps(link.tx_speed))
            bucket.rx.append(restore_mbps(link.rx_speed))
    return buckets


def _link_name(key: Any, units: Mapping[str, int]) -> str | None:
    if isinstance(key, ARWiFiBand):
        unit = units.get(key.value)
        return None if unit is None else f"wl{unit}"
    if key is ARTrafficType.WIRED:
        return "wired"
    if key is ARTrafficType.BACKHAUL:
        return "backhaul"
    if key is ARTrafficType.WAN:  # netdev INTERNET; _wan_links decides if it is W0
        return _WAN_PORT
    return None


def _link_order(link: Link) -> tuple[int, str]:
    rank = {"wired": 0, "backhaul": 1}.get(link.name, 2)
    return rank, link.name.zfill(8)


def _links(
    node: MeshNode,
    traffic: Mapping[Any, Any],
    counters: CounterBank | None,
    now: float,
    link_bytes: Mapping[str, ByteDelta],
) -> tuple[Link, ...]:
    """The device's own byte counters win; AiMesh rates fill the other links.

    Live, the root's AiMesh rates stuck at 0 (wl0 in, wired) while its kernel
    counters move, so the logged-in device's own counters come first. A node's
    own WIRED covers its uplink too: kept as ``eth``, its wired row stays is_bh=0.
    """
    links = []
    for name, delta in link_bytes.items():
        if name == "wired" and node.role != "router":
            name = _OWN_WIRED
        octets = (None, None)
        if counters is not None:
            octets = counters.add(node.mac, name, delta.rx, delta.tx, now=now)
        rates = (_bit_rate(d, delta.elapsed_s) for d in (delta.rx, delta.tx))
        links.append(Link(name, *rates, *octets))
    named = {link.name for link in links}
    units = {radio.band: radio.unit for radio in node.radios}
    for key, metrics in traffic.items():
        name = _link_name(key, units)
        if name is None or name in named or not isinstance(metrics, Mapping):
            continue
        rx = restore_kbps(metrics.get(ARMetricType.RX_SPEED))
        tx = restore_kbps(metrics.get(ARMetricType.TX_SPEED))
        octets = (None, None)
        if counters is not None:
            octets = counters.update(node.mac, name, rx, tx, now=now)
        links.append(Link(name, rx, tx, *octets))
    return tuple(sorted(links, key=_link_order))


def _wan_links(
    node: MeshNode, links: tuple[Link, ...], ports: tuple[EthPort, ...]
) -> tuple[Link, ...]:
    """Counters for the WAN row only from a source that measures that port.

    The device's own WAN counter (netdev INTERNET) needs W0 up and no second
    WAN port; a wired uplink on the WAN port (re_path 1) lends its counters.
    """
    wan = [port for port in ports if port.native.startswith("W")]
    wan_up = any(port.native == _WAN_PORT and port.up is True for port in wan)
    own = wan_up and len(wan) == 1
    kept = [link for link in links if link.name != _WAN_PORT or own]
    uplink = next((link for link in kept if link.name == "backhaul"), None)
    backhaul = node.backhaul
    if (
        wan_up
        and backhaul is not None
        and backhaul.medium == ARAiMeshMedium.WIRED.value
        and backhaul.port == _WAN_UPLINK
        and uplink is not None
        and uplink.in_octets is not None
        and all(link.name != _WAN_PORT for link in kept)
    ):
        kept.append(replace(uplink, name=_WAN_PORT))
    return tuple(sorted(kept, key=_link_order))


def _lan_links(
    node: MeshNode, links: tuple[Link, ...], ports: tuple[EthPort, ...], own_wired: bool
) -> tuple[Link, ...]:
    """Ethernet rows take a wired total only where it measures that one port.

    The device's own netdev WIRED covers every wired port (W0 too, unless its
    INTERNET counts it): one up port gets it, over a backhaul copy. Otherwise a
    node's AiMesh is_bh=0 total covers its LAN ports: one up LAN port gets it.
    """
    router = node.role == "router"
    by_name = {link.name: link for link in links}
    wan_counted = own_wired and router and _WAN_PORT in by_name
    up = [
        p.native
        for p in ports
        if p.up is True and not (wan_counted and p.native == _WAN_PORT)
    ]
    own = by_name.get("wired" if router else _OWN_WIRED) if own_wired else None
    if own is not None and own.in_octets is not None and len(up) == 1:
        by_name[up[0]] = replace(own, name=up[0])
    elif not router:
        lan = by_name.get("wired")  # the node's is_bh=0 total: its client ports
        backhaul = node.backhaul
        lan_uplink = (
            backhaul is not None
            and backhaul.medium == ARAiMeshMedium.WIRED.value
            and backhaul.port != _WAN_UPLINK
        )  # one of the LAN ports is the uplink, and the data does not say which
        clients = [native for native in up if native.startswith("L")]
        if (
            not lan_uplink
            and len(clients) == 1
            and clients[0] not in by_name
            and lan is not None
            and lan.in_octets is not None
        ):
            by_name[clients[0]] = replace(lan, name=clients[0])
    return tuple(sorted(by_name.values(), key=_link_order))


def unmetered_ports(snapshot: NodeSnapshot) -> tuple[str, ...]:
    """Port IDs that are up but carry no counter: they share a total, or have none."""
    return tuple(
        p.native
        for p in snapshot.ports
        if p.up is True and snapshot.link(p.native) is None
    )


@dataclass(frozen=True, slots=True)
class ByteDelta:
    """Bytes a device's own counters moved on one link since the previous sample.

    None is unknown: the first sample, a counter that went back (a reboot, a
    32-bit wrap), or a gap over the limit. An unknown interval adds nothing.
    """

    rx: int | None
    tx: int | None
    elapsed_s: float | None = None

    def plus(self, later: ByteDelta) -> ByteDelta:
        """Both intervals as one: known bytes add up, an unknown interval adds none."""

        def add(a: Any, b: Any) -> Any:
            return b if a is None else a if b is None else a + b

        return ByteDelta(
            add(self.rx, later.rx),
            add(self.tx, later.tx),
            add(self.elapsed_s, later.elapsed_s),
        )


class InterfaceCounters:
    """Byte deltas per link from a device's own counters (update.cgi netdev).

    The logged-in device and, in per_node mode, each node report these exact
    counters; ``units`` (band to wl unit) is the device's own radio numbering.
    """

    def __init__(self, *, max_gap_s: float) -> None:
        self._max_gap_s = max_gap_s
        self._last: dict[str, tuple[float, dict[str, tuple[int, int]]]] = {}

    def update(
        self,
        node: MeshNode,
        data: Mapping[Any, Any],
        now: float,
        units: Mapping[str, int] | None = None,
    ) -> dict[str, ByteDelta]:
        """Deltas since the node's previous sample; ``now`` is monotonic seconds."""
        if units is None:
            units = {radio.band: radio.unit for radio in node.radios}
        sample: dict[str, tuple[int, int]] = {}
        for key, metrics in data.items():
            name = _link_name(key, units)
            if name is None or not isinstance(metrics, Mapping):
                continue
            rx, tx = (
                _bytes(metrics.get(ARMetricType.RX)),
                _bytes(metrics.get(ARMetricType.TX)),
            )
            if rx is not None and tx is not None:
                sample[name] = (rx, tx)
        last = self._last.get(node.mac)
        self._last[node.mac] = (now, sample)
        deltas: dict[str, ByteDelta] = {}
        for name, (rx, tx) in sample.items():
            before = last[1].get(name) if last is not None else None
            elapsed = now - last[0] if last is not None else 0.0
            if before is None or not 0 < elapsed <= self._max_gap_s:
                deltas[name] = ByteDelta(None, None)
                continue
            deltas[name] = ByteDelta(
                _forward(rx - before[0]), _forward(tx - before[1]), elapsed
            )
        return deltas


def _forward(delta: int) -> int | None:
    """A counter only grows: going back means it restarted or wrapped (unknown)."""
    return delta if delta >= 0 else None


def _bit_rate(delta_bytes: int | None, elapsed_s: float | None) -> int | None:
    if delta_bytes is None or not elapsed_s:
        return None
    return round(delta_bytes * 8 / elapsed_s)


def _wireless_link_bps(traffic: Mapping[Any, Any]) -> int | None:
    """Backhaul PHY rate; the larger direction stands for the link (assumption)."""
    metrics = traffic.get(ARTrafficType.BACKHAUL)
    if not isinstance(metrics, Mapping):
        return None
    rates = [
        rate
        for key in (ARMetricType.PHY_RX_SPEED, ARMetricType.PHY_TX_SPEED)
        if (rate := restore_mbps(metrics.get(key))) is not None
    ]
    return max(rates) if rates else None


def build_snapshot(
    node: MeshNode,
    *,
    sys_name: str,
    collected_at: float,
    usage: Usage | None = None,
    clients: Iterable[ARClient] = (),
    traffic: Mapping[Any, Any] | None = None,
    detail: DeviceDetail | None = None,
    counters: CounterBank | None = None,
    location: str | None = None,
    detail_max_age_s: float = DETAIL_MAX_AGE_S,
    ports: Iterable[EthPort] = (),
    link_bytes: Mapping[str, ByteDelta] | None = None,
) -> NodeSnapshot:
    """One node's snapshot; ``collected_at`` is monotonic, like the store's clock.

    ``link_bytes`` (from :class:`InterfaceCounters`) fill the links that
    ``traffic`` (AiMesh data) lacks.
    """
    ports = tuple(ports)
    usage = usage or Usage(None, None)
    if detail is not None and not 0 <= collected_at - detail.collected_at <= (
        detail_max_age_s
    ):
        detail = None
    extra = detail or DeviceDetail(collected_at=collected_at)
    traffic = traffic or {}
    stats = _client_stats(node, clients)
    radios = tuple(
        Radio(
            unit=radio.unit,
            band=radio.band,
            mac=radio.mac,
            state=radio.state,
            clients=len(stats[radio.unit].clients),
            freq_mhz=extra.freq_mhz.get(radio.unit),
            client_rssi_dbm=Stat.of(stats[radio.unit].rssi),
            client_tx_bps=Stat.of(stats[radio.unit].tx),
            client_rx_bps=Stat.of(stats[radio.unit].rx),
        )
        for radio in node.radios
    )
    backhaul = node.backhaul
    if backhaul is not None and backhaul.medium in {m.value for m in _WIRELESS_MEDIA}:
        backhaul = replace(backhaul, link_bps=_wireless_link_bps(traffic))
    uptime = None
    if extra.uptime_s is not None:
        uptime = extra.uptime_s + int(collected_at - extra.collected_at)
    return NodeSnapshot(
        node_id=node.mac,
        sys_name=sys_name,
        mac=node.mac,
        online=node.online,
        role=node.role,
        level=node.level,
        collected_at=collected_at,
        location=location,
        ip=node.ip,
        model=node.model,
        firmware=node.firmware,
        cpu_pct=usage.cpu_pct if usage.cpu_pct is not None else extra.cpu_pct,
        mem_pct=usage.mem_pct if usage.mem_pct is not None else extra.mem_pct,
        cpu_core_pct=extra.cpu_core_pct,
        mem_total_b=extra.mem_total_b,
        mem_used_b=extra.mem_used_b,
        uptime_s=uptime,
        temps_c=extra.temps_c,
        backhaul=backhaul,
        radios=radios,
        links=_lan_links(
            node,
            _wan_links(
                node,
                _links(node, traffic, counters, collected_at, link_bytes or {}),
                ports,
            ),
            ports,
            own_wired="wired" in (link_bytes or {}),
        ),
        neighbors=node.neighbors,
        ports=ports,
    )


# --- derived octets ---------------------------------------------------------------


def _load_counters(path: Path) -> dict[str, dict[str, list[int]]]:
    doc = statefile.read_json(path)
    raw = doc.get("counters") if isinstance(doc, dict) else None
    if not isinstance(raw, dict) or doc.get("version") != COUNTERS_FORMAT:
        return {}
    counters: dict[str, dict[str, list[int]]] = {}
    for node, links in raw.items():
        if not isinstance(links, dict):
            continue
        for link, pair in links.items():
            ok = (
                isinstance(pair, list)
                and len(pair) == 2
                and all(
                    isinstance(v, int)
                    and not isinstance(v, bool)
                    and 0 <= v < COUNTER_MAX
                    for v in pair
                )
            )
            if ok:
                counters.setdefault(str(node), {})[str(link)] = list(pair)
    return counters


class CounterBank:
    """Derived Counter64 octets per node link: rate x interval or byte deltas.

    A restart keeps the persisted values and only skips the interval it did
    not see; an interval longer than ``max_gap_s`` adds nothing, so downtime
    never invents traffic.
    """

    def __init__(self, path: Path, *, max_gap_s: float) -> None:
        self.path = path
        self._max_gap_s = max_gap_s
        self._counters = _load_counters(path)
        self._last: dict[tuple[str, str], float] = {}
        self._dirty = False

    def update(
        self, node: str, link: str, rx_bps: int | None, tx_bps: int | None, now: float
    ) -> tuple[int | None, int | None]:
        """Integrate one sample; ``now`` is monotonic seconds."""
        if rx_bps is None or tx_bps is None:
            return None, None
        pair = self._counters.setdefault(node, {}).setdefault(link, [0, 0])
        last = self._last.get((node, link))
        if last is not None and 0 < now - last <= self._max_gap_s:
            elapsed = now - last
            pair[0] = (pair[0] + int(rx_bps * elapsed / 8)) % COUNTER_MAX
            pair[1] = (pair[1] + int(tx_bps * elapsed / 8)) % COUNTER_MAX
        self._last[(node, link)] = now
        self._dirty = True
        return pair[0], pair[1]

    def add(
        self, node: str, link: str, rx: int | None, tx: int | None, now: float
    ) -> tuple[int, int]:
        """Add measured byte deltas; an unknown one (None) holds that counter."""
        pair = self._counters.setdefault(node, {}).setdefault(link, [0, 0])
        for i, delta in enumerate((rx, tx)):
            if delta is not None:
                pair[i] = (pair[i] + delta) % COUNTER_MAX
        self._last[(node, link)] = now
        self._dirty = True
        return pair[0], pair[1]

    def save(self) -> None:
        """Persist atomically if anything changed (every 60 s and on SIGTERM)."""
        if not self._dirty:
            return
        statefile.write_json(
            self.path, {"version": COUNTERS_FORMAT, "counters": self._counters}
        )
        self._dirty = False
