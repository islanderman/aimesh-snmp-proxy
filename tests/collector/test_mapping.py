import json
import logging
from dataclasses import replace
from types import SimpleNamespace

import pytest
from asusrouter.modules.aimesh.source import translate_state as translate_topology
from asusrouter.modules.clients.translate import build_clients
from asusrouter.modules.clock import ARClockField
from asusrouter.modules.common.metrics import ARMetricType
from asusrouter.modules.device.identity import ARDeviceIdentity
from asusrouter.modules.nvram import ARNvramType
from asusrouter.modules.ports.legacy import (
    translate_ethernet_ports as translate_legacy_ports,
)
from asusrouter.modules.ports.source import translate_state as translate_ports
from asusrouter.modules.system_status.source import translate_state as translate_status
from asusrouter.modules.temperature import ARTemperatureType
from asusrouter.modules.traffic.aimesh.source import (
    translate_state as translate_traffic,
)
from asusrouter.modules.traffic.enums import ARTrafficType
from asusrouter.modules.traffic.interface.source import (
    translate_state as translate_interface,
)
from asusrouter.modules.wifi import ARWiFiBand, ARWiFiField
from asusrouter.tools.identifiers import MacAddress

from aimesh_snmp_proxy.collector import mapping
from aimesh_snmp_proxy.collector.mapping import (
    ByteDelta,
    CounterBank,
    DeviceDetail,
    InterfaceCounters,
    Usage,
    build_snapshot,
    channel_to_mhz,
    eth_ports,
    mesh_nodes,
    parse_detail,
)
from aimesh_snmp_proxy.config import default_sys_name
from aimesh_snmp_proxy.model import (
    Backhaul,
    EthPort,
    Link,
    Neighbor,
    Stat,
    Temperature,
)

ROOT = "00:00:5e:00:53:01"
NODE = "00:00:5e:00:53:02"
WIRED = "00:00:5e:00:53:03"
B2, B5, B52, B6 = (
    ARWiFiBand.BAND_2G1,
    ARWiFiBand.BAND_5G1,
    ARWiFiBand.BAND_5G2,
    ARWiFiBand.BAND_6G1,
)


def identity():
    return ARDeviceIdentity.build({ARNvramType.MAC: ROOT})


def reply(mesh3, endpoint, **query):
    wanted = {k: str(v).upper() for k, v in query.items()}
    for entry in mesh3["queries"]:
        got = {k: str(v).upper() for k, v in entry["query"].items()}
        if entry["endpoint"] == endpoint and got == wanted:
            return entry["reply"]
    raise KeyError(query)


def wifi(mesh3, node, band_mac):
    return reply(mesh3, "get_diag_wifi_traffic.cgi", node_mac=node, band_mac=band_mac)


def eth(mesh3, node, is_bh):
    return reply(mesh3, "get_diag_eth_traffic.cgi", node_mac=node, is_bh=is_bh)


def traffic(mesh3, node):
    """What the library's AiMesh traffic source yields for one node."""
    raw = {
        ROOT: {
            B2: wifi(mesh3, ROOT, "00:00:5E:00:53:11"),
            B5: wifi(mesh3, ROOT, "00:00:5E:00:53:15"),
            B6: wifi(mesh3, ROOT, "00:00:5E:00:53:18"),
            ARTrafficType.WIRED: eth(mesh3, ROOT, 0),
        },
        NODE: {
            B2: wifi(mesh3, NODE, "00:00:5E:00:53:20"),
            B5: wifi(mesh3, NODE, "00:00:5E:00:53:24"),
            B52: wifi(mesh3, NODE, "00:00:5E:00:53:28"),
            ARTrafficType.WIRED: eth(mesh3, NODE, 0),
            ARTrafficType.BACKHAUL: reply(
                mesh3,
                "get_diag_sta_traffic.cgi",
                node_mac=ROOT,
                sta_mac="00:00:5E:00:53:2A",
            ),
        },
        WIRED: {
            ARTrafficType.WIRED: eth(mesh3, WIRED, 0),
            ARTrafficType.BACKHAUL: eth(mesh3, WIRED, 1),
        },
    }[node]
    return translate_traffic(raw)


def usage(mesh3, node):
    rows = reply(mesh3, "get_diag_content_data.cgi", filter=f"node_mac>txt>{node}>0")
    status = translate_status({node.upper(): rows["contents"]}, identity=identity())
    return mapping.usage_for(status, node)


@pytest.fixture
def nodes(mesh3):
    return mesh_nodes(translate_topology(mesh3["pages"]["ajax_onboarding.asp"]))


@pytest.fixture
def clients(mesh3):
    return list(build_clients(mesh3["appget"], identity()).values())


def snapshot(nodes, mesh3, clients, node, **kwargs):
    defaults = {
        "sys_name": default_sys_name(node),
        "collected_at": 500.0,
        "usage": usage(mesh3, node),
        "clients": clients,
        "traffic": traffic(mesh3, node),
    }
    return build_snapshot(nodes[node], **(defaults | kwargs))


# --- topology -------------------------------------------------------------------


def test_mesh_nodes_carry_identity_role_and_level(nodes):
    root, node, wired = nodes[ROOT], nodes[NODE], nodes[WIRED]
    assert sorted(nodes) == [ROOT, NODE, WIRED]
    assert (root.role, root.level, root.online) == ("router", 0, True)
    assert (root.ip, root.model, root.firmware) == (
        "192.168.50.1",
        "RT-AX88U",
        "3.0.0.4.388.4_0",
    )
    assert node.role == "node"
    assert node.level == 1
    assert node.model == "P2"  # product_id wins over the display names
    assert wired.model == "M3"  # ui_model_name when product_id is absent
    assert root.backhaul is None


def test_backhaul_wireless_5g2_and_wired_gigabit(nodes):
    assert nodes[NODE].backhaul == Backhaul(
        medium="wireless", band="5g2", rssi_dbm=-54, parent_mac=ROOT
    )
    assert nodes[WIRED].backhaul == Backhaul(
        medium="wired", link_bps=1_000_000_000, parent_mac=ROOT, port=1
    )


def test_radios_keep_unit_band_mac_and_state(nodes):
    root = {r.unit: r for r in nodes[ROOT].radios}
    assert {u: (r.band, r.mac, r.state) for u, r in root.items()} == {
        0: ("2g1", "00:00:5e:00:53:11", True),  # fronthaul BSSID preferred
        1: ("5g1", "00:00:5e:00:53:15", True),
        2: ("6g1", "00:00:5e:00:53:18", True),
    }
    node = {r.unit: (r.band, r.state) for r in nodes[NODE].radios}
    assert node == {0: ("2g1", True), 1: ("5g1", True), 2: ("5g2", False)}


def test_radio_without_mac_or_state_assumption_off_and_blank_mac(nodes):
    wired = {r.unit: (r.mac, r.state) for r in nodes[WIRED].radios}
    assert wired == {0: ("", False), 1: ("", False)}


def test_mesh_nodes_skip_entries_without_a_mac():
    topo = translate_topology({"get_cfg_clientlist": [[{"online": "1"}]]})
    assert mesh_nodes(topo) == {}


def test_a_standalone_node_needs_a_mac_and_counts_unflagged_radios_as_off():
    nameless = SimpleNamespace(mac=None, wifi={}, firmware=None, model=None)
    assert mapping.standalone_node(nameless, {}, ip=None) is None
    device = SimpleNamespace(
        mac=MacAddress.from_value(ROOT), wifi={B2: 0}, firmware=None, model="RT-AX58U"
    )
    node = mapping.standalone_node(device, {B2: {"other": 1}}, ip="192.168.50.110")
    assert (node.mac, node.role, node.ip, node.firmware) == (
        ROOT,
        "router",
        "192.168.50.110",
        None,
    )
    assert node.radios == (mapping.MeshRadio(0, "2g1", "", False),)


# --- LLDP neighbors -----------------------------------------------------------------

PARENT_AP5G, PARENT_AP5G1 = "00:00:5E:00:53:A0", "00:00:5E:00:53:A1"


def test_a_wireless_backhaul_is_a_neighbor_on_both_ends(nodes):
    # NODE links on its 5G-2 radio to the root's only 5 GHz radio, wl1.
    assert nodes[NODE].neighbors == (
        Neighbor("backhaul", ROOT, "wl1", "192.168.50.1", "5g1"),
    )
    assert nodes[ROOT].neighbors == (
        Neighbor("wl1", NODE, "backhaul", "192.168.50.101", "5g1"),
    )


def test_a_wired_backhaul_gives_no_neighbor(nodes):
    assert nodes[WIRED].neighbors == ()
    assert all(n.mac != WIRED for n in nodes[ROOT].neighbors)


def tri_band(child, **root):
    """A tri-band root (5G-1 is ap5g, 5G-2 is ap5g1) and one child."""
    parent = {
        "mac": ROOT.upper(),
        "re_path": "0",
        "ip": "192.168.50.1",
        "ap5g": PARENT_AP5G,
        "ap5g1": PARENT_AP5G1,
        "band_info": {"1": {"unit": 1}, "3": {"unit": 2}},
        **root,
    }
    base = {
        "mac": NODE.upper(),
        "ip": "192.168.50.101",
        "band_info": {"1": {"unit": 1}},
    }
    raw = {"get_cfg_clientlist": [[parent, base | child]]}
    return mesh_nodes(translate_topology(raw))


def test_two_parent_radios_in_the_band_are_resolved_by_the_backhaul_radio():
    nodes = tri_band({"re_path": "4", "pap5g": PARENT_AP5G1}, apdwb=PARENT_AP5G1)
    assert nodes[NODE].neighbors == (
        Neighbor("backhaul", ROOT, "wl2", "192.168.50.1", "5g2"),
    )


def test_two_parent_radios_without_a_backhaul_radio_give_no_neighbor():
    nodes = tri_band({"re_path": "4", "pap5g": PARENT_AP5G1})
    assert nodes[NODE].backhaul.parent_mac == ROOT
    assert (nodes[NODE].neighbors, nodes[ROOT].neighbors) == ((), ())


def test_mlo_and_parentless_backhauls_give_no_neighbor():
    mlo = tri_band({"re_path": "512", "papmlo": ROOT.upper()})
    assert mlo[NODE].backhaul.medium == "mlo"
    orphan = tri_band({"re_path": "4", "pap5g": "00:00:5E:00:53:FF"})
    for nodes in (mlo, orphan):
        assert (nodes[NODE].neighbors, nodes[ROOT].neighbors) == ((), ())


def test_a_parent_without_an_ip_still_is_a_neighbor():
    nodes = tri_band({"re_path": "4", "pap5g": PARENT_AP5G}, ip="", apdwb=PARENT_AP5G)
    assert nodes[NODE].neighbors == (Neighbor("backhaul", ROOT, "wl1", None, "5g1"),)


def test_snapshots_carry_the_neighbors_and_ports(nodes, mesh3, clients):
    port = EthPort("L1", "LAN1", up=True, speed_mbps=100)
    snap = snapshot(nodes, mesh3, clients, NODE, ports=[port])
    assert snap.neighbors == nodes[NODE].neighbors
    assert snap.ports == (port,)
    assert snapshot(nodes, mesh3, clients, WIRED).ports == ()


# --- Ethernet ports -----------------------------------------------------------------


def ports_of(mesh3):
    raw = reply(mesh3, "get_port_status.cgi", node_mac="all")
    return eth_ports(translate_ports(raw, identity=identity()))


def test_ethernet_ports_per_node_from_get_port_status(mesh3):
    ports = ports_of(mesh3)
    assert set(ports) == {ROOT, NODE, WIRED}
    assert ports[ROOT] == (
        EthPort("W0", "WAN", up=True, speed_mbps=1000, label="2.5G WAN"),
        EthPort("L1", "LAN1", up=True, speed_mbps=1000, label="LAN 1"),
        EthPort("L2", "LAN2", up=False, speed_mbps=0, label="LAN 2"),
    )
    assert ports[NODE] == (
        EthPort("W0", "WAN", up=False, speed_mbps=0),
        EthPort("L1", "LAN1", up=True, speed_mbps=100),
    )


@pytest.mark.parametrize(
    ("label", "name"),
    [("W0", "WAN"), ("W1", "WAN2"), ("L1", "LAN1"), ("L12", "LAN12")],
)
def test_port_names_follow_the_router_port_id(label, name):
    raw = {"port_info": {ROOT: {label: {"is_on": "1", "link_rate": "10", "cap": "2"}}}}
    (port,) = eth_ports(translate_ports(raw, identity=identity()))[ROOT]
    assert (port.native, port.name, port.speed_mbps) == (label, name, 10)


def test_usb_ai_and_unknown_ports_and_rates_are_dropped():
    raw = {
        "port_info": {
            ROOT: {
                "U1": {"is_on": "1", "cap": "128"},
                "AI": {"is_on": "1"},
                "L1": {"is_on": "1", "link_rate": "123", "cap": "2"},
            }
        }
    }
    (port,) = eth_ports(translate_ports(raw, identity=identity()))[ROOT]
    assert (port.native, port.up, port.speed_mbps) == ("L1", True, None)


@pytest.mark.parametrize("data", [None, {}, {"x": "y"}, [1]])
def test_unusable_port_data_gives_no_ports(data):
    assert eth_ports(data) == {}


def test_a_port_id_listed_twice_keeps_its_first_row():
    # ajax_ethernet_ports.asp labels map to port IDs: "LAN 1" and "LAN1" are both L1.
    raw = {"portSpeed": {"WAN 0": "G", "LAN 1": "M", "LAN1": "G"}}
    ports = eth_ports(translate_legacy_ports(raw, identity()))[ROOT]
    assert [(p.native, p.up, p.speed_mbps) for p in ports] == [
        ("W0", True, 1000),
        ("L1", True, 100),
    ]


# --- clients --------------------------------------------------------------------


def test_root_radio_client_counts_rssi_and_rates(nodes, mesh3, clients):
    snap = snapshot(nodes, mesh3, clients, ROOT)
    five = snap.radio(1)
    assert five.clients == 3  # two single-link clients and one MLO link
    assert five.client_rssi_dbm == Stat(-63, (-46 - 60 - 63) / 3, -46)
    assert five.client_tx_bps == Stat(1e6, (866e6 + 433e6 + 1e6) / 3, 866e6)
    assert five.client_rx_bps == Stat(0, (650e6 + 390e6) / 3, 650e6)
    two = snap.radio(0)
    assert (two.clients, two.client_rssi_dbm) == (1, Stat(-70, -70, -70))
    assert snap.radio(2).clients == 0
    assert snap.radio(2).client_rssi_dbm is None


def test_rates_restore_decimal_mbps_from_the_library_mebibit_scaling(clients):
    raw = next(c for c in clients if str(c.mac) == "00:00:5e:00:53:a1")
    link = raw.connection.links[0]
    assert link.tx_speed == 866 * 2**20  # the library reads curTx "866" as Mibit/s
    assert mapping.restore_mbps(link.tx_speed) == 866_000_000


def test_tri_band_5g_client_goes_to_lowest_5g_unit_assumption(nodes, mesh3, clients):
    snap = snapshot(nodes, mesh3, clients, NODE)
    assert snap.radio(1).clients == 1
    assert snap.radio(2).clients == 0


def test_offline_wired_and_mesh_entries_are_not_clients(nodes, mesh3, clients):
    snaps = [snapshot(nodes, mesh3, clients, n) for n in (ROOT, NODE, WIRED)]
    assert sum(r.clients for s in snaps for r in s.radios) == 5


# --- traffic and usage ----------------------------------------------------------


def test_links_restore_decimal_kbps_and_name_interfaces(nodes, mesh3, clients):
    root = snapshot(nodes, mesh3, clients, ROOT)
    assert {link.name: (link.rx_bps, link.tx_bps) for link in root.links} == {
        "wl0": (100_000, 200_000),
        "wl1": (2_000_000, 8_000_000),
        "wl2": (0, 0),
        "wired": (5_000_000, 3_000_000),
    }
    node = snapshot(nodes, mesh3, clients, NODE)
    assert node.link("backhaul").rx_bps == 1_400_000
    wired = snapshot(nodes, mesh3, clients, WIRED)
    assert wired.link("backhaul").tx_bps == 900_000


def test_wireless_backhaul_link_rate_from_phy_assumption_max_of_rx_tx(
    nodes, mesh3, clients
):
    snap = snapshot(nodes, mesh3, clients, NODE)
    assert snap.backhaul.link_bps == 1_729_000_000


def test_cpu_and_memory_percent_from_the_newest_diagnostics_row(nodes, mesh3, clients):
    snap = snapshot(nodes, mesh3, clients, ROOT)
    assert (snap.cpu_pct, snap.mem_pct) == (5, 26)
    assert usage(mesh3, NODE) == Usage(12, 40)
    assert mapping.usage_for({}, ROOT) == Usage(None, None)


def test_node_without_data_still_maps_with_empty_fields(nodes):
    snap = build_snapshot(nodes[NODE], sys_name="n", collected_at=1.0)
    assert snap.cpu_pct is None
    assert snap.links == ()
    assert [r.clients for r in snap.radios] == [0, 0, 0]
    assert snap.node_id == NODE
    assert snap.backhaul.link_bps is None


def test_default_sys_name_uses_the_last_six_hex_digits():
    assert default_sys_name("00:00:5e:00:53:0a") == "aimesh-00530a"


# --- detail of the logged-in device -----------------------------------------------


def legacy_raw(mesh3, bump=0):
    cpu = dict(mesh3["appget"]["cpu_usage"])
    if bump:
        for core in range(1, 5):
            cpu[f"cpu{core}_total"] = str(int(cpu[f"cpu{core}_total"]) + 1000)
            cpu[f"cpu{core}_usage"] = str(int(cpu[f"cpu{core}_usage"]) + 250 * core)
    return {"cpu_usage": cpu, "memory_usage": mesh3["appget"]["memory_usage"]}


def fetched_extras():
    return {
        "clock": {ARClockField.UPTIME: 4162},
        "temperature": {
            ARTemperatureType.RADIO_2G1: 44.0,
            ARTemperatureType.RADIO_5G1: 44.0,
            ARTemperatureType.CPU: 65.514,
        },
        "wifi": {
            B2: {ARWiFiField.CHANNEL: 6},
            B5: {ARWiFiField.CHANNEL: 100},
            B6: {ARWiFiField.CHANNEL: 5},
        },
    }


def test_detail_reads_cores_ram_bytes_uptime_temps_and_channels(mesh3):
    units = {B2: 0, B5: 1, B6: 2}
    first = parse_detail(legacy_raw(mesh3), fetched_extras(), units, None, now=10.0)
    assert first.cpu_core_pct is None  # cumulative tick counters need two samples
    assert first.mem_total_b == 1048576 * 1024
    assert first.mem_used_b == 813112 * 1024
    assert first.uptime_s == 4162
    assert first.temps_c == (
        Temperature("cpu", 65.514),
        Temperature("radio_2g1", 44.0),
        Temperature("radio_5g1", 44.0),
    )
    assert first.freq_mhz == {0: 2437, 1: 5500, 2: 5975}
    second = parse_detail(
        legacy_raw(mesh3, bump=1), fetched_extras(), units, first, now=310.0
    )
    assert second.cpu_core_pct == (25.0, 50.0, 75.0, 100.0)
    assert second.cpu_pct == 62.5


def test_detail_fills_snapshot_fields_and_ages_uptime(nodes, mesh3, clients):
    units = {B2: 0, B5: 1, B6: 2}
    first = parse_detail(legacy_raw(mesh3), fetched_extras(), units, None, now=400.0)
    snap = snapshot(nodes, mesh3, clients, ROOT, detail=first)
    assert snap.uptime_s == 4162 + 100
    assert snap.mem_total_b == 1048576 * 1024
    assert snap.radio(1).freq_mhz == 5500
    assert snap.cpu_pct == 5  # diagnostics win over the legacy aggregate


def test_expired_detail_is_not_served(nodes, mesh3, clients):
    old = DeviceDetail(collected_at=0.0, uptime_s=10, mem_total_b=1)
    snap = snapshot(nodes, mesh3, clients, ROOT, detail=old, detail_max_age_s=60)
    assert snap.uptime_s is None
    assert snap.mem_total_b is None


def test_detail_survives_missing_pieces():
    detail = parse_detail({}, {}, {}, None, now=1.0)
    assert detail == DeviceDetail(collected_at=1.0)


@pytest.mark.parametrize(
    ("band", "channel", "mhz"),
    [
        ("2g1", 1, 2412),
        ("2g1", 13, 2472),
        ("2g1", 14, 2484),
        ("5g1", 36, 5180),
        ("5g2", 165, 5825),
        ("6g1", 1, 5955),
        ("6g1", 2, 5935),
        ("6g2", 233, 7115),
        ("5g1", 0, None),
        ("xx", 6, None),
    ],
)
def test_channel_to_mhz(band, channel, mhz):
    assert channel_to_mhz(band, channel) == mhz


# --- derived octets ---------------------------------------------------------------


def test_counters_integrate_rate_times_interval(tmp_path):
    bank = CounterBank(tmp_path / "counters.json", max_gap_s=180)
    assert bank.update(ROOT, "wired", 8000, 16000, now=0.0) == (0, 0)
    assert bank.update(ROOT, "wired", 8000, 16000, now=60.0) == (60_000, 120_000)
    assert bank.update(ROOT, "wired", None, 16000, now=120.0) == (None, None)
    assert bank.update(ROOT, "wired", 800, 0, now=180.0) == (72_000, 120_000)


def test_counters_skip_gaps_longer_than_the_limit(tmp_path):
    bank = CounterBank(tmp_path / "counters.json", max_gap_s=180)
    bank.update(ROOT, "wl0", 8000, 8000, now=0.0)
    assert bank.update(ROOT, "wl0", 8000, 8000, now=1000.0) == (0, 0)


def test_counters_persist_atomically_and_stay_monotonic_across_restart(tmp_path):
    path = tmp_path / "state" / "counters.json"
    bank = CounterBank(path, max_gap_s=180)
    bank.update(ROOT, "wired", 8000, 8000, now=0.0)
    bank.update(ROOT, "wired", 8000, 8000, now=60.0)
    bank.save()
    doc = json.loads(path.read_text())
    assert doc["counters"][ROOT]["wired"] == [60_000, 60_000]
    restarted = CounterBank(path, max_gap_s=180)
    assert restarted.update(ROOT, "wired", 8000, 8000, now=5.0) == (60_000, 60_000)
    assert restarted.update(ROOT, "wired", 8000, 8000, now=65.0) == (120_000, 120_000)


def test_counters_wrap_at_2_64(tmp_path):
    path = tmp_path / "counters.json"
    path.write_text(
        json.dumps({"version": 1, "counters": {ROOT: {"wired": [2**64 - 10, 0]}}})
    )
    bank = CounterBank(path, max_gap_s=180)
    bank.update(ROOT, "wired", 8, 0, now=0.0)
    assert bank.update(ROOT, "wired", 8, 0, now=20.0) == (10, 0)


def test_counters_save_only_when_changed(tmp_path):
    path = tmp_path / "counters.json"
    bank = CounterBank(path, max_gap_s=180)
    bank.save()
    assert not path.exists()


def test_bad_counter_file_entries_are_ignored(tmp_path, caplog):
    path = tmp_path / "counters.json"
    doc = {"version": 1, "counters": {ROOT: {"wired": [-1, "x"], "wl0": [5, 6]}}}
    path.write_text(json.dumps(doc))
    bank = CounterBank(path, max_gap_s=180)
    assert bank.update(ROOT, "wired", 0, 0, now=0.0) == (0, 0)
    assert bank.update(ROOT, "wl0", 0, 0, now=0.0) == (5, 6)


def test_snapshot_links_carry_derived_octets(tmp_path, nodes, mesh3, clients):
    bank = CounterBank(tmp_path / "counters.json", max_gap_s=180)
    snapshot(nodes, mesh3, clients, ROOT, counters=bank, collected_at=0.0)
    snap = snapshot(nodes, mesh3, clients, ROOT, counters=bank, collected_at=60.0)
    wired = snap.link("wired")
    assert wired.in_octets == 5_000_000 * 60 // 8
    assert wired.out_octets == 3_000_000 * 60 // 8


# --- WAN row counters ---------------------------------------------------------------


def wan_snapshot(nodes, mesh3, clients, tmp_path, node, ports, **kwargs):
    """The second of two snapshots a minute apart: its counters have moved."""
    bank = CounterBank(tmp_path / "counters.json", max_gap_s=180)
    kwargs |= {"counters": bank, "ports": ports}
    snapshot(nodes, mesh3, clients, node, collected_at=0.0, **kwargs)
    return snapshot(nodes, mesh3, clients, node, collected_at=60.0, **kwargs)


def test_a_wired_uplink_on_the_wan_port_serves_its_counters_on_wan(
    tmp_path, nodes, mesh3, clients
):
    # re_path 1: the node's WAN port is its wired uplink, the same cable.
    snap = wan_snapshot(nodes, mesh3, clients, tmp_path, WIRED, ports_of(mesh3)[WIRED])
    backhaul = snap.link("backhaul")
    assert (backhaul.in_octets, backhaul.out_octets) == (5_250_000, 6_750_000)
    assert snap.link("W0") == replace(backhaul, name="W0")


@pytest.mark.parametrize(
    "change", ["wan_down", "uplink_on_port_2", "wireless_uplink", "no_backhaul_data"]
)
def test_wan_gets_no_backhaul_counters_unless_the_uplink_is_on_it(
    tmp_path, nodes, mesh3, clients, change
):
    ports, node, kwargs = ports_of(mesh3)[WIRED], nodes[WIRED], {}
    if change == "wan_down":
        ports = tuple(replace(p, up=False) if p.native == "W0" else p for p in ports)
    elif change == "uplink_on_port_2":  # re_path 16: a LAN port, not named here
        node = replace(node, backhaul=replace(node.backhaul, port=2))
    elif change == "wireless_uplink":
        node = replace(node, backhaul=replace(node.backhaul, medium="wireless"))
    else:
        kwargs["traffic"] = {}
    nodes = {**nodes, WIRED: node}
    snap = wan_snapshot(nodes, mesh3, clients, tmp_path, WIRED, ports, **kwargs)
    assert snap.link("W0") is None


AP_PORTS = (EthPort("W0", "WAN", up=True, speed_mbps=1000), EthPort("L1", "LAN1"))


@pytest.mark.parametrize(
    ("ports", "served"),
    [
        (AP_PORTS, True),
        ((replace(AP_PORTS[0], up=False), AP_PORTS[1]), False),  # an AP: WAN unused
        ((*AP_PORTS, EthPort("W1", "WAN2", up=True)), False),  # INTERNET may sum both
        ((), False),
    ],
)
def test_the_device_wan_counters_need_one_wan_port_with_its_link_up(
    tmp_path, ports, served
):
    bank = CounterBank(tmp_path / "counters.json", max_gap_s=180)
    counters = InterfaceCounters(max_gap_s=180)
    snap = None
    for at, rx in ((0.0, 10**9), (60.0, 10**9 + 7_500_000)):
        deltas = counters.update(AP, netdev(INTERNET=(rx, 2 * rx)), now=at)
        snap = build_snapshot(
            AP,
            sys_name="ap",
            collected_at=at,
            counters=bank,
            link_bytes=deltas,
            ports=ports,
        )
    wan = snap.link("W0")
    if served:
        assert (wan.in_octets, wan.out_octets) == (7_500_000, 15_000_000)
    else:
        assert wan is None


# --- LAN rows: a wired total only on the one up port it covers ----------------------


def lan_ports(*up):
    """W0 and L1-L5, with the named port IDs up."""
    natives = ("W0", "L1", "L2", "L3", "L4", "L5")
    return tuple(
        EthPort(n, mapping._port_name(n), up=n in up, speed_mbps=1000 if n in up else 0)
        for n in natives
    )


WIRED_TOTAL = ByteDelta(6_000_000, 3_000_000, 60.0)


def own_wired(tmp_path, ports, **extra):
    """The device's own netdev WIRED (and any ``extra`` links), a minute in."""
    bank = CounterBank(tmp_path / "counters.json", max_gap_s=180)
    snap = None
    for at in (0.0, 60.0):
        deltas = {"wired": WIRED_TOTAL if at else ByteDelta(None, None)}
        deltas |= {k: v if at else ByteDelta(None, None) for k, v in extra.items()}
        snap = build_snapshot(
            AP,
            sys_name="ap",
            collected_at=at,
            counters=bank,
            link_bytes=deltas,
            ports=ports,
        )
    return snap


def counted(snap):
    """Port IDs whose Ethernet row carries a counter, with its octets."""
    return {
        p.native: (snap.link(p.native).in_octets, snap.link(p.native).out_octets)
        for p in snap.ports
        if snap.link(p.native) is not None
    }


def test_the_own_wired_total_goes_onto_the_only_up_port_it_covers(tmp_path):
    # The root (an AP) has only its uplink LAN5 up; netdev WIRED covers every port.
    snap = own_wired(tmp_path, lan_ports("L5"))
    assert counted(snap) == {"L5": (6_000_000, 3_000_000)}
    assert snap.link("wired").in_octets == 6_000_000  # the total stays on wired


@pytest.mark.parametrize("up", [("L2", "L3"), ("W0", "L1")])
def test_two_up_ports_sharing_the_wired_total_get_no_counter(tmp_path, up):
    snap = own_wired(tmp_path, lan_ports(*up))
    assert counted(snap) == {}
    assert mapping.unmetered_ports(snap) == up


def test_a_wan_with_its_own_counter_leaves_the_wired_total_to_the_lan(tmp_path):
    internet = ByteDelta(9_000_000, 900_000, 60.0)
    snap = own_wired(tmp_path, lan_ports("W0", "L1"), W0=internet)
    assert counted(snap) == {"W0": (9_000_000, 900_000), "L1": (6_000_000, 3_000_000)}


def node_with(nodes, **backhaul):
    return replace(nodes[WIRED], backhaul=replace(nodes[WIRED].backhaul, **backhaul))


@pytest.mark.parametrize(
    ("backhaul", "up", "lan_counted"),
    [
        ({}, ("W0", "L2"), "L2"),  # re_path 1: W0 is the uplink, is_bh=0 the LAN
        ({}, ("W0", "L1", "L2"), None),
        ({"medium": "wireless", "port": None}, ("L2",), "L2"),
        ({"medium": "wireless", "port": None}, ("W0", "L2"), "L2"),  # W0: no client
        ({"medium": "wireless", "port": None}, ("W0",), None),
        ({"port": 2}, ("L1",), None),  # a LAN uplink the data does not name
    ],
)
def test_a_node_lan_total_goes_onto_its_only_up_client_port(
    tmp_path, nodes, mesh3, clients, backhaul, up, lan_counted
):
    nodes = {**nodes, WIRED: node_with(nodes, **backhaul)}
    snap = wan_snapshot(nodes, mesh3, clients, tmp_path, WIRED, lan_ports(*up))
    lan = {k: v for k, v in counted(snap).items() if k != "W0"}
    wired = snap.link("wired")
    expected = {lan_counted: (wired.in_octets, wired.out_octets)} if lan_counted else {}
    assert lan == expected


NODE_WIRED = ByteDelta(9_000_000, 4_500_000, 60.0)  # the node's own netdev WIRED


def node_own(nodes, mesh3, clients, tmp_path, ports, **backhaul):
    """WIRED as the second of two snapshots, with its own netdev and AiMesh data."""
    nodes = {**nodes, WIRED: node_with(nodes, **backhaul)}
    bank = CounterBank(tmp_path / "counters.json", max_gap_s=180)
    snap = None
    for at in (0.0, 60.0):
        own = {"wired": NODE_WIRED if at else ByteDelta(None, None)}
        snap = snapshot(
            nodes,
            mesh3,
            clients,
            WIRED,
            collected_at=at,
            counters=bank,
            ports=ports,
            link_bytes=own,
        )
    return snap


@pytest.mark.parametrize(
    ("backhaul", "up"),
    [({}, ("W0",)), ({"port": 2}, ("L1",)), ({"medium": "wireless"}, ("W0",))],
    ids=["wan-uplink", "lan-uplink", "wireless-uplink-wan-client"],
)
def test_a_node_with_one_up_port_puts_its_own_wired_total_there(
    tmp_path, nodes, mesh3, clients, backhaul, up
):
    # The node's netdev WIRED covers every wired port: one up port is exact.
    snap = node_own(nodes, mesh3, clients, tmp_path, lan_ports(*up), **backhaul)
    assert counted(snap) == {up[0]: (9_000_000, 4_500_000)}
    # The wired row stays the is_bh=0 total of the client ports (rule 3).
    assert (snap.link("wired").in_octets, snap.link("wired").out_octets) == (
        375_000,
        450_000,
    )


def test_a_node_with_more_up_ports_splits_uplink_and_client_by_aimesh(
    tmp_path, nodes, mesh3, clients
):
    # re_path 1 with LAN2 up too: W0 keeps is_bh=1, LAN2 the is_bh=0 total.
    snap = node_own(nodes, mesh3, clients, tmp_path, lan_ports("W0", "L2"))
    backhaul, lan = snap.link("backhaul"), snap.link("wired")
    assert counted(snap) == {
        "W0": (backhaul.in_octets, backhaul.out_octets),
        "L2": (lan.in_octets, lan.out_octets),
    }
    assert (lan.in_octets, lan.out_octets) == (375_000, 450_000)


def test_a_node_lan_uplink_with_more_up_ports_leaves_them_all_unmetered(
    tmp_path, nodes, mesh3, clients
):
    snap = node_own(nodes, mesh3, clients, tmp_path, lan_ports("L1", "L3"), port=2)
    assert counted(snap) == {}
    assert mapping.unmetered_ports(snap) == ("L1", "L3")


def test_a_wired_total_without_counters_lends_none(tmp_path):
    snap = build_snapshot(
        AP,
        sys_name="ap",
        collected_at=0.0,
        link_bytes={"wired": ByteDelta(None, None)},
        ports=lan_ports("L5"),
    )
    assert counted(snap) == {}


# --- a standalone device's own byte counters (update.cgi netdev) --------------------

AP = mapping.MeshNode(
    ROOT,
    True,
    "router",
    0,
    radios=(
        mapping.MeshRadio(0, "2g1", "", True),
        mapping.MeshRadio(1, "5g1", "", True),
    ),
)


def netdev(**ifaces):
    """An ARTrafficInterfaceSource result for ``WIRELESS0=(rx, tx)`` and the like."""
    now = {name: {"rx": rx, "tx": tx} for name, (rx, tx) in ifaces.items()}
    device = SimpleNamespace(wifi_by_unit={0: B2, 1: B5})
    return translate_interface(
        {"now": now, "prev": None, "delta_time": None}, identity=device
    )


def test_interface_counters_give_each_link_its_byte_delta():
    counters = InterfaceCounters(max_gap_s=180)
    first = netdev(
        WIRELESS0=(1_000, 2_000),
        WIRELESS1=(0, 0),
        WIRED=(5, 5),
        BRIDGE=(9, 9),
        INTERNET=(1, 1),
    )
    unknown = ByteDelta(None, None)  # no earlier sample yet
    assert counters.update(AP, first, now=0.0) == {
        "wl0": unknown,
        "wl1": unknown,
        "wired": unknown,
        "W0": unknown,  # INTERNET; BRIDGE has no row
    }
    later = netdev(
        WIRELESS0=(1_000 + 7_500_000, 2_000 + 750_000), WIRELESS1=(15, 0), WIRED=(5, 5)
    )
    assert counters.update(AP, later, now=60.0) == {
        "wl0": ByteDelta(7_500_000, 750_000, 60.0),
        "wl1": ByteDelta(15, 0, 60.0),
        "wired": ByteDelta(0, 0, 60.0),
    }


def test_a_counter_that_went_back_or_a_long_gap_gives_an_unknown_delta():
    counters = InterfaceCounters(max_gap_s=180)
    counters.update(AP, netdev(WIRELESS0=(10_000, 10_000)), now=0.0)
    # A reboot or a 32-bit wrap restarts one counter: only that one is unknown.
    went_back = netdev(WIRELESS0=(500, 20_000))
    assert counters.update(AP, went_back, now=60.0) == {
        "wl0": ByteDelta(None, 10_000, 60.0)
    }
    assert counters.update(AP, netdev(WIRELESS0=(600, 20_100)), now=241.0) == {
        "wl0": ByteDelta(None, None)
    }
    assert counters.update(AP, netdev(WIRELESS0=(1_200, 20_100)), now=301.0) == {
        "wl0": ByteDelta(600, 0, 60.0)
    }


def test_two_byte_deltas_add_up_and_an_unknown_one_adds_nothing():
    first, later = ByteDelta(1_000, None, 60.0), ByteDelta(2_000, 3_000, 60.0)
    assert first.plus(later) == ByteDelta(3_000, 3_000, 120.0)
    assert ByteDelta(None, None).plus(ByteDelta(None, None)) == ByteDelta(None, None)


def test_interface_counters_ignore_unusable_counters():
    counters = InterfaceCounters(max_gap_s=180)
    bad = {B2: {"rx": "x"}, B5: "not a mapping", ARTrafficType.WAN: {}}
    assert counters.update(AP, bad, now=0.0) == {}


def test_snapshot_links_add_byte_deltas_and_hold_on_unknown(tmp_path):
    bank = CounterBank(tmp_path / "counters.json", max_gap_s=180)

    def links(at, **deltas):
        snap = build_snapshot(
            AP, sys_name="ap", collected_at=at, counters=bank, link_bytes=deltas
        )
        return snap.links

    assert links(0.0, wl0=ByteDelta(None, None)) == (Link("wl0", None, None, 0, 0),)
    assert links(60.0, wl0=ByteDelta(7_500_000, 0, 60.0)) == (
        Link("wl0", 1_000_000, 0, 7_500_000, 0),
    )
    assert links(120.0, wl0=ByteDelta(None, 15, 60.0)) == (
        Link("wl0", None, 2, 7_500_000, 15),
    )


def test_counter_bank_adds_byte_deltas_modulo_2_64(tmp_path):
    path = tmp_path / "counters.json"
    path.write_text(
        json.dumps({"version": 1, "counters": {ROOT: {"wl0": [2**64 - 5, 0]}}})
    )
    bank = CounterBank(path, max_gap_s=180)
    assert bank.add(ROOT, "wl0", 10, None, now=0.0) == (5, 0)


def test_the_devices_own_byte_counters_win_over_aimesh_rates():
    # The root's AiMesh rates can stick at 0 (live: .6 wl0 in, wired); the kernel's
    # byte counters of the logged-in device do not, so they win for its own links.
    traffic = {
        ARTrafficType.WIRED: {ARMetricType.RX_SPEED: 0, ARMetricType.TX_SPEED: 0},
        B5: {ARMetricType.RX_SPEED: 1024, ARMetricType.TX_SPEED: 2048},
    }
    deltas = {"wired": ByteDelta(60, 120, 60.0), "wl0": ByteDelta(60, 0, 60.0)}
    snap = build_snapshot(
        AP, sys_name="ap", collected_at=0.0, traffic=traffic, link_bytes=deltas
    )
    assert snap.links == (
        Link("wired", 8, 16),
        Link("wl0", 8, 0),
        Link("wl1", 1_000, 2_000),  # no own counter: the AiMesh rate stays
    )


def test_mapping_logs_no_client_identifiers(nodes, mesh3, clients, caplog):
    with caplog.at_level(logging.DEBUG):
        snapshot(nodes, mesh3, clients, ROOT)
    assert "53:a1" not in caplog.text.lower()
