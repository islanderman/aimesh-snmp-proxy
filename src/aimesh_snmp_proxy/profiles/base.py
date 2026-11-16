"""Rows every profile serves: SNMPv2-MIB system, IF-MIB, HOST-RESOURCES-MIB,
ENTITY-MIB, ENTITY-SENSOR-MIB (design section 5), and LLDP-MIB. No UCD-SNMP-MIB.

Unknown data omits its OID; nothing is invented. The only stand-ins are the
standard "unknown" encodings: ifSpeed 0 and ifOperStatus unknown(4).
"""

from __future__ import annotations

import ipaddress
import math
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from pysnmp.proto.rfc1902 import (
    Counter32,
    Counter64,
    Gauge32,
    Integer32,
    ObjectIdentifier,
    OctetString,
    TimeTicks,
)

from aimesh_snmp_proxy.model import Link, NodeSnapshot, Radio, normalize_mac
from aimesh_snmp_proxy.snmp.oidtable import Oid, Row, parse_oid

NET_SNMP_LINUX = parse_oid("1.3.6.1.4.1.8072.3.2.10")
LLDP_MIB = parse_oid("1.0.8802.1.1.2")  # outside 1.3.6: SNMP views must include it

# Stable per band: LibreNMS numbers wireless sensors by interface order.
BAND_LABELS = {
    "2g1": "wl-2.4G",
    "2g2": "wl-2.4G-2",
    "5g1": "wl-5.0G",
    "5g2": "wl-5.0G-2",
    "6g1": "wl-6.0G",
    "6g2": "wl-6.0G-2",
}

_SYSTEM = parse_oid("1.3.6.1.2.1.1")
_IF_NUMBER = parse_oid("1.3.6.1.2.1.2.1.0")
_IF_ENTRY = parse_oid("1.3.6.1.2.1.2.2.1")
_IFX_ENTRY = parse_oid("1.3.6.1.2.1.31.1.1.1")
_HR_UPTIME = parse_oid("1.3.6.1.2.1.25.1.1.0")
_HR_MEMORY_SIZE = parse_oid("1.3.6.1.2.1.25.2.2.0")
_HR_STORAGE_ENTRY = parse_oid("1.3.6.1.2.1.25.2.3.1")
_HR_STORAGE_RAM = parse_oid("1.3.6.1.2.1.25.2.1.2")
_HR_DEVICE_ENTRY = parse_oid("1.3.6.1.2.1.25.3.2.1")
_HR_DEVICE_PROCESSOR = parse_oid("1.3.6.1.2.1.25.3.1.3")
_HR_PROCESSOR_LOAD = parse_oid("1.3.6.1.2.1.25.3.3.1.2")
_ENT_PHYSICAL_ENTRY = parse_oid("1.3.6.1.2.1.47.1.1.1.1")
_ENT_SENSOR_ENTRY = parse_oid("1.3.6.1.2.1.99.1.1.1")
_LLDP_LOC = (*LLDP_MIB, 1, 3)  # lldpLocalSystemData
_LLDP_LOC_PORT = (*_LLDP_LOC, 7, 1)  # lldpLocPortEntry
_LLDP_REM = (*LLDP_MIB, 1, 4, 1, 1)  # lldpRemEntry
_LLDP_REM_MAN = (*LLDP_MIB, 1, 4, 2, 1)  # lldpRemManAddrEntry

_IF_WIRED, _IF_BACKHAUL, _IF_RADIO_BASE = 1, 2, 10
_FIRST_CPU = 196608  # net-snmp's first hrDeviceIndex for processors
_BACKHAUL_RSSI, _RADIO_RSSI_BASE = 100, 200
_UP, _DOWN, _UNKNOWN = 1, 2, 4
_OTHER, _ETHERNET, _WIFI = 1, 6, 71
_BACKHAUL_TYPES = {"wireless": _WIFI, "mlo": _WIFI, "wired": _ETHERNET}
_CELSIUS, _SCALE_UNITS, _SENSOR_OK = 8, 9, 1
_SENSOR_LIMIT = 10**9  # EntitySensorValue range
_GAUGE32_MAX = 2**32 - 1
_INT32_MAX = 2**31 - 1
_CHASSIS_MAC, _PORT_IFNAME = 4, 5  # LldpChassisIdSubtype, LldpPortIdSubtype
_ADDR_IPV4, _MAN_IF_UNKNOWN = 1, 1  # AddressFamilyNumbers, LldpManAddrIfSubtype


def display_string(value: str) -> OctetString:
    """A DisplayString value, UTF-8 encoded."""
    return OctetString(value.encode())


def radio_label(radio: Radio) -> str:
    """The radio's display name, for example ``wl-5.0G``."""
    return BAND_LABELS.get(radio.band, f"wl{radio.unit}")


def base_rows(
    snapshot: NodeSnapshot,
    *,
    sys_object_id: Oid,
    now: float | None = None,
    serving_since: float | None = None,
    sys_name: str | None = None,
    peer_names: Mapping[str, str] | None = None,
) -> list[Row]:
    """Every base MIB row for ``snapshot``.

    ``now`` and ``serving_since`` use the snapshot's clock and default to
    ``collected_at``; sysUpTime counts from ``serving_since`` when the node's
    uptime is unknown. ``sys_name`` replaces the snapshot's sysName, and
    ``peer_names`` maps other nodes' MACs to the sysNames they are served as.
    """
    now = snapshot.collected_at if now is None else now
    since = now if serving_since is None else serving_since
    ticks = _uptime_ticks(snapshot, now, since)
    name = sys_name or snapshot.sys_name
    interfaces = _interface_list(snapshot)
    return [
        *_system(snapshot, sys_object_id, ticks, name),
        *_interfaces(interfaces),
        *_host_resources(snapshot, ticks),
        *_sensors(snapshot),
        *_lldp(snapshot, name, interfaces, peer_names or {}),
    ]


def _uptime_ticks(snapshot: NodeSnapshot, now: float, since: float) -> int:
    if snapshot.uptime_s is not None:
        seconds = snapshot.uptime_s + max(0.0, now - snapshot.collected_at)
    else:
        seconds = max(0.0, now - since)
    return int(seconds * 100) % 2**32


def _system(
    snapshot: NodeSnapshot, sys_object_id: Oid, ticks: int, sys_name: str
) -> list[Row]:
    firmware = f"stock {snapshot.firmware}" if snapshot.firmware else None
    parts = ("ASUS", snapshot.model, firmware, "via aimesh-snmp-proxy")
    return [
        ((*_SYSTEM, 1, 0), display_string(" ".join(p for p in parts if p))),
        ((*_SYSTEM, 2, 0), ObjectIdentifier(sys_object_id)),
        ((*_SYSTEM, 3, 0), TimeTicks(ticks)),
        ((*_SYSTEM, 4, 0), display_string("")),
        ((*_SYSTEM, 5, 0), display_string(sys_name)),
        ((*_SYSTEM, 6, 0), display_string(snapshot.location or "")),
    ]


@dataclass(frozen=True, slots=True)
class _Interface:
    index: int
    name: str
    alias: str
    if_type: int
    speed_bps: int
    mac: str | None
    admin: int
    oper: int
    link: Link | None


def _interface_list(snapshot: NodeSnapshot) -> list[_Interface]:
    out = []
    wired = snapshot.link("wired")
    if wired is not None:
        counted = wired.in_octets is not None or wired.out_octets is not None
        out.append(
            _Interface(
                _IF_WIRED,
                "wired",
                "wired",
                _ETHERNET,
                0,
                snapshot.mac,
                _UP,
                _UP if counted else _UNKNOWN,  # up while a source counts it
                wired,
            )
        )
    backhaul, backhaul_link = snapshot.backhaul, snapshot.link("backhaul")
    if backhaul is not None or backhaul_link is not None:
        medium = backhaul.medium if backhaul is not None else None
        speed = (backhaul.link_bps if backhaul is not None else None) or 0
        oper = _UNKNOWN if medium in (None, "unknown") else _UP
        if_type = _BACKHAUL_TYPES.get(medium or "", _OTHER)
        out.append(
            _Interface(
                _IF_BACKHAUL,
                "backhaul",
                "backhaul",
                if_type,
                max(speed, 0),
                None,
                _UP,
                oper,
                backhaul_link,
            )
        )
    for radio in snapshot.radios:
        name = f"wl{radio.unit}"
        status = _UP if radio.state else _DOWN
        out.append(
            _Interface(
                _IF_RADIO_BASE + radio.unit,
                name,
                radio_label(radio),
                _WIFI,
                0,
                radio.mac,
                status,
                status,
                snapshot.link(name),
            )
        )
    for port in snapshot.ports:  # ifIndex 100-209, after the fixed ones above
        oper = _UNKNOWN if port.up is None else _UP if port.up else _DOWN
        out.append(
            _Interface(
                port.if_index,
                port.name,
                port.label or port.name,
                _ETHERNET,
                max(port.speed_mbps or 0, 0) * 10**6,
                None,
                _UP,
                oper,
                snapshot.link(port.native),  # only a source that measures the port
            )
        )
    return out


def _interfaces(interfaces: Sequence[_Interface]) -> list[Row]:
    rows: list[Row] = [(_IF_NUMBER, Integer32(len(interfaces)))]
    for iface in interfaces:
        i = iface.index
        link = iface.link
        in_octets = _octets(link.in_octets) if link is not None else None
        out_octets = _octets(link.out_octets) if link is not None else None
        derived = in_octets is not None or out_octets is not None
        rows += [
            ((*_IF_ENTRY, 1, i), Integer32(i)),
            ((*_IF_ENTRY, 2, i), display_string(iface.name)),
            ((*_IF_ENTRY, 3, i), Integer32(iface.if_type)),
            ((*_IF_ENTRY, 5, i), Gauge32(min(iface.speed_bps, _GAUGE32_MAX))),
            ((*_IF_ENTRY, 7, i), Integer32(iface.admin)),
            ((*_IF_ENTRY, 8, i), Integer32(iface.oper)),
            ((*_IFX_ENTRY, 1, i), display_string(iface.name)),
            (
                (*_IFX_ENTRY, 15, i),
                Gauge32(min(iface.speed_bps // 10**6, _GAUGE32_MAX)),
            ),
            (
                (*_IFX_ENTRY, 18, i),
                display_string(f"{iface.alias} (derived)" if derived else iface.alias),
            ),
        ]
        mac = _mac_bytes(iface.mac)
        if mac is not None:
            rows.append(((*_IF_ENTRY, 6, i), OctetString(mac)))
        if in_octets is not None:
            rows.append(((*_IF_ENTRY, 10, i), Counter32(in_octets % 2**32)))
            rows.append(((*_IFX_ENTRY, 6, i), Counter64(in_octets % 2**64)))
        if out_octets is not None:
            rows.append(((*_IF_ENTRY, 16, i), Counter32(out_octets % 2**32)))
            rows.append(((*_IFX_ENTRY, 10, i), Counter64(out_octets % 2**64)))
    return rows


def _octets(value: int | None) -> int | None:
    return value if value is not None and value >= 0 else None


def _mac_bytes(mac: str | None) -> bytes | None:
    normal = normalize_mac(mac) if mac else None
    return bytes.fromhex(normal.replace(":", "")) if normal else None


def _pct(value: float | None) -> int | None:
    """A percentage rounded and clamped to 0-100; None when unknown or not finite."""
    if value is None or not math.isfinite(value):
        return None
    return min(max(round(value), 0), 100)


def _host_resources(snapshot: NodeSnapshot, ticks: int) -> list[Row]:
    rows: list[Row] = []
    if snapshot.uptime_s is not None:
        rows.append((_HR_UPTIME, TimeTicks(ticks)))
    total = snapshot.mem_total_b
    total_kb = total // 1024 if total is not None and total > 0 else None
    if total_kb is not None and total_kb > _INT32_MAX:
        total_kb = None
    if total_kb is not None:
        rows.append((_HR_MEMORY_SIZE, Integer32(total_kb)))
    used = snapshot.mem_used_b
    pct = _pct(snapshot.mem_pct)
    if total_kb is not None and used is not None and 0 <= used <= total:
        ram = ("Physical memory", 1024, total_kb, used // 1024)
    elif pct is not None:
        ram = ("Physical memory (%)", 1, 100, pct)
    else:
        ram = None
    if ram is not None:
        descr, units, size, in_use = ram
        rows += [
            ((*_HR_STORAGE_ENTRY, 1, 1), Integer32(1)),
            ((*_HR_STORAGE_ENTRY, 2, 1), ObjectIdentifier(_HR_STORAGE_RAM)),
            ((*_HR_STORAGE_ENTRY, 3, 1), display_string(descr)),
            ((*_HR_STORAGE_ENTRY, 4, 1), Integer32(units)),
            ((*_HR_STORAGE_ENTRY, 5, 1), Integer32(size)),
            ((*_HR_STORAGE_ENTRY, 6, 1), Integer32(in_use)),
        ]
    return rows + _processors(snapshot)


def _processors(snapshot: NodeSnapshot) -> list[Row]:
    if snapshot.cpu_core_pct:
        loads = [(f"Core {i}", _pct(p)) for i, p in enumerate(snapshot.cpu_core_pct)]
    else:
        loads = [("CPU", _pct(snapshot.cpu_pct))]
    rows: list[Row] = []
    for offset, (descr, load) in enumerate(loads):
        if load is None:
            continue
        index = _FIRST_CPU + offset
        rows += [
            ((*_HR_DEVICE_ENTRY, 1, index), Integer32(index)),
            ((*_HR_DEVICE_ENTRY, 2, index), ObjectIdentifier(_HR_DEVICE_PROCESSOR)),
            ((*_HR_DEVICE_ENTRY, 3, index), display_string(descr)),
            ((*_HR_PROCESSOR_LOAD, index), Integer32(load)),
        ]
    return rows


@dataclass(frozen=True, slots=True)
class _Sensor:
    index: int
    name: str
    descr: str
    kind: int
    precision: int  # fixed per sensor: LibreNMS reads it once, at discovery
    value: float


def _sensor_list(snapshot: NodeSnapshot) -> list[_Sensor]:
    temps = sorted(snapshot.temps_c or (), key=lambda t: t.sensor)
    out = []
    for i, temp in enumerate(temps, start=1):
        name = _temperature_label(temp.sensor)
        out.append(_Sensor(i, name, f"{name} temperature", _CELSIUS, 1, temp.celsius))
    # LibreNMS's ENTITY-SENSOR-MIB (RFC 3433) has no dBm(14), so it skips 14; it
    # maps other(1) to dbm when entPhysicalName holds "Rx Power Sensor".
    backhaul = snapshot.backhaul
    if backhaul is not None and backhaul.rssi_dbm is not None:
        name, descr = "backhaul Rx Power Sensor", "backhaul RSSI in dBm"
        out.append(_Sensor(_BACKHAUL_RSSI, name, descr, _OTHER, 0, backhaul.rssi_dbm))
    for radio in snapshot.radios:
        if radio.client_rssi_dbm is not None:
            label = radio_label(radio)
            name = f"{label} clients Rx Power Sensor"
            descr = f"{label} client RSSI average in dBm"
            index = _RADIO_RSSI_BASE + radio.unit
            out.append(
                _Sensor(index, name, descr, _OTHER, 1, radio.client_rssi_dbm.avg)
            )
    return out


def _temperature_label(sensor: str) -> str:
    """``CPU``, or ``wl-5.0G radio`` for the library's ``radio_5g1``."""
    if sensor == "cpu":
        return "CPU"
    band = sensor.removeprefix("radio_")
    if band != sensor and band in BAND_LABELS:
        return f"{BAND_LABELS[band]} radio"
    return sensor


def _sensors(snapshot: NodeSnapshot) -> list[Row]:
    rows: list[Row] = []
    for sensor in _sensor_list(snapshot):
        if not math.isfinite(sensor.value):
            continue
        value = round(sensor.value * 10**sensor.precision)
        if not -_SENSOR_LIMIT <= value <= _SENSOR_LIMIT:
            continue
        i = sensor.index
        rows += [
            ((*_ENT_PHYSICAL_ENTRY, 2, i), display_string(sensor.descr)),
            ((*_ENT_PHYSICAL_ENTRY, 7, i), display_string(sensor.name)),
            ((*_ENT_SENSOR_ENTRY, 1, i), Integer32(sensor.kind)),
            ((*_ENT_SENSOR_ENTRY, 2, i), Integer32(_SCALE_UNITS)),
            ((*_ENT_SENSOR_ENTRY, 3, i), Integer32(sensor.precision)),
            ((*_ENT_SENSOR_ENTRY, 4, i), Integer32(value)),
            ((*_ENT_SENSOR_ENTRY, 5, i), Integer32(_SENSOR_OK)),
        ]
    return rows


# --- LLDP-MIB ------------------------------------------------------------------------


def _lldp(
    snapshot: NodeSnapshot,
    sys_name: str,
    interfaces: Sequence[_Interface],
    peer_names: Mapping[str, str],
) -> list[Row]:
    """This node as an LLDP chassis, its interfaces as ports, its radio links
    as remotes; lldpLocPortNum is the ifIndex, lldpLocPortId the ifName.
    """
    rows: list[Row] = []
    chassis = _mac_bytes(snapshot.mac)
    if chassis is not None:
        rows.append(((*_LLDP_LOC, 1, 0), Integer32(_CHASSIS_MAC)))
        rows.append(((*_LLDP_LOC, 2, 0), OctetString(chassis)))
    rows.append(((*_LLDP_LOC, 3, 0), display_string(sys_name)))
    port_nums: dict[str, int] = {}
    for iface in interfaces:
        port_nums[iface.name] = iface.index
        rows += [
            ((*_LLDP_LOC_PORT, 2, iface.index), Integer32(_PORT_IFNAME)),
            ((*_LLDP_LOC_PORT, 3, iface.index), display_string(iface.name)),
            ((*_LLDP_LOC_PORT, 4, iface.index), display_string(iface.alias)),
        ]
    seen: Counter[int] = Counter()
    for peer in snapshot.neighbors:
        local, mac = port_nums.get(peer.local_port), _mac_bytes(peer.mac)
        if local is None or mac is None:  # LibreNMS skips an unmatched local port
            continue
        seen[local] += 1
        index = (0, local, seen[local])  # lldpRemTimeMark 0, then the port's Nth peer
        label = BAND_LABELS.get(peer.band or "", "radio")
        desc = f"backhaul ({label})" if peer.port == "backhaul" else label
        rows += [
            ((*_LLDP_REM, 4, *index), Integer32(_CHASSIS_MAC)),
            ((*_LLDP_REM, 5, *index), OctetString(mac)),
            ((*_LLDP_REM, 6, *index), Integer32(_PORT_IFNAME)),
            ((*_LLDP_REM, 7, *index), display_string(peer.port)),
            ((*_LLDP_REM, 8, *index), display_string(desc)),
        ]
        if name := peer_names.get(peer.mac):
            rows.append(((*_LLDP_REM, 9, *index), display_string(name)))
        address = _management_ipv4(peer.ip)
        if address is not None:
            entry = (*index, _ADDR_IPV4, len(address), *address)
            rows.append(((*_LLDP_REM_MAN, 3, *entry), Integer32(_MAN_IF_UNKNOWN)))
            rows.append(((*_LLDP_REM_MAN, 4, *entry), Integer32(0)))
    return rows


def _management_ipv4(ip: str | None) -> tuple[int, ...] | None:
    """The peer's LAN IPv4 as index octets; None for anything else.

    Loopback is refused: LibreNMS polls every node at 127.0.0.1, so that
    address would match all of them and name none.
    """
    try:
        address = ipaddress.IPv4Address(ip or "")
    except ValueError:
        return None
    if address.is_loopback or address.is_unspecified:
        return None
    return tuple(address.packed)
