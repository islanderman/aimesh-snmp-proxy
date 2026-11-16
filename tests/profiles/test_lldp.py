"""LLDP-MIB rows, checked against how LibreNMS discovery-protocols matches them.

LibreNMS maps lldpRemLocalPortNum to lldpLocPortId and then to an ifName,
finds the remote device by lldpRemSysName or the management IPv4 address,
and the remote port by its interfaceName port ID, the remote ifName.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from asusrouter.modules.aimesh.source import translate_state as translate_topology

from aimesh_snmp_proxy.collector.mapping import build_snapshot, mesh_nodes
from aimesh_snmp_proxy.model import Backhaul, EthPort, Neighbor
from aimesh_snmp_proxy.profiles import PROFILES

LOC = "1.0.8802.1.1.2.1.3."
LOC_PORT = LOC + "7.1."
REM = "1.0.8802.1.1.2.1.4.1.1."
REM_MAN = "1.0.8802.1.1.2.1.4.2.1."
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1."
ROOT, NODE, WIRED = "00:00:5e:00:53:01", "00:00:5e:00:53:02", "00:00:5e:00:53:03"
NAMES = {ROOT: "aimesh-root", NODE: "aimesh-005302", WIRED: "aimesh-005303"}
MESH3 = Path(__file__).resolve().parent.parent / "fixtures" / "mesh3.json"


def under(rows, prefix):
    return {
        oid[len(prefix) :]: value
        for oid, value in rows.items()
        if oid.startswith(prefix)
    }


@pytest.fixture
def render(served):
    def _render(snapshot, **kwargs):
        kwargs.setdefault("sys_name", "office")
        return served(PROFILES["asuswrt-merlin"].render(snapshot, **kwargs))

    return _render


@pytest.fixture
def mesh(render):
    """Every mesh3.json node through the real mapping, rendered with peer names."""
    doc = json.loads(MESH3.read_text())
    nodes = mesh_nodes(translate_topology(doc["pages"]["ajax_onboarding.asp"]))
    snaps = {
        mac: build_snapshot(node, sys_name=NAMES[mac], collected_at=1.0)
        for mac, node in nodes.items()
    }
    return {
        mac: render(snap, sys_name=NAMES[mac], peer_names=NAMES)
        for mac, snap in snaps.items()
    }


# --- local system --------------------------------------------------------------------


def test_the_local_chassis_is_the_node_mac_and_the_served_sysname(node, render):
    rows = render(node(), sys_name="aimesh-hall")
    assert under(rows, LOC + "1.") == {"0": "2|4"}  # macAddress
    assert under(rows, LOC + "2.") == {"0": "4x|00005e005301"}
    assert under(rows, LOC + "3.") == {"0": "4|aimesh-hall"}


def test_every_served_interface_is_a_local_port_named_by_its_ifname(
    node, radio, render
):
    snap = node(
        backhaul=Backhaul(medium="wireless", band="5g1"),
        radios=[radio(0), radio(1, "5g1")],
        ports=[EthPort("W0", "WAN", label="2.5G WAN")],
    )
    rows = render(snap)
    if_names = under(rows, IF_NAME)
    assert set(if_names) == {"2", "10", "11", "100"}
    assert under(rows, LOC_PORT + "3.") == if_names  # lldpLocPortNum = ifIndex
    assert set(under(rows, LOC_PORT + "2.").values()) == {"2|5"}  # interfaceName
    assert under(rows, LOC_PORT + "4.") == {
        "2": "4|backhaul",
        "10": "4|wl-2.4G",
        "11": "4|wl-5.0G",
        "100": "4|2.5G WAN",
    }


def test_a_node_without_neighbors_serves_no_remote_rows(node, render):
    rows = render(node())
    assert under(rows, REM) == under(rows, REM_MAN) == {}


# --- remote rows from mesh3.json ----------------------------------------------------


def test_the_child_sees_its_parent_radio_through_its_backhaul_port(mesh):
    rows = mesh[NODE]
    assert under(rows, REM) == {
        "4.0.2.1": "2|4",
        "5.0.2.1": "4x|00005e005301",  # the parent's chassis ID
        "6.0.2.1": "2|5",
        "7.0.2.1": "4|wl1",
        "8.0.2.1": "4|wl-5.0G",
        "9.0.2.1": "4|aimesh-root",
    }
    assert under(rows, REM_MAN) == {
        "3.0.2.1.1.4.192.168.50.1": "2|1",
        "4.0.2.1.1.4.192.168.50.1": "2|0",
    }


def test_the_parent_sees_the_child_through_its_radio_port(mesh):
    rows = mesh[ROOT]
    assert under(rows, REM) == {
        "4.0.11.1": "2|4",
        "5.0.11.1": "4x|00005e005302",
        "6.0.11.1": "2|5",
        "7.0.11.1": "4|backhaul",
        "8.0.11.1": "4|backhaul (wl-5.0G)",
        "9.0.11.1": "4|aimesh-005302",
    }
    assert set(under(rows, REM_MAN)) == {
        "3.0.11.1.1.4.192.168.50.101",
        "4.0.11.1.1.4.192.168.50.101",
    }


def test_librenms_can_match_both_ends_of_the_radio_link(mesh):
    for local, peer in ((NODE, ROOT), (ROOT, NODE)):
        rows = mesh[local]
        for key, port_id in under(rows, REM + "7.").items():
            local_port = key.split(".")[1]
            # lldpRemLocalPortNum -> lldpLocPortId -> a served ifName
            assert rows[LOC_PORT + f"3.{local_port}"] == rows[IF_NAME + local_port]
            # the remote interfaceName port ID is an ifName the peer serves
            assert port_id in under(mesh[peer], IF_NAME).values()
        man = list(under(rows, REM_MAN + "3."))
        assert [m.split(".", 5)[5] for m in man] == [
            {NODE: "192.168.50.1", ROOT: "192.168.50.101"}[local]
        ]


def test_a_wired_backhaul_gives_no_remote_rows(mesh):
    assert under(mesh[WIRED], REM) == under(mesh[WIRED], REM_MAN) == {}
    assert "5.0.11.2" not in under(mesh[ROOT], REM)
    chassis = under(mesh[ROOT], REM + "5.").values()
    assert "4x|00005e005303" not in chassis


def test_no_loopback_address_appears_anywhere(mesh):
    for rows in mesh.values():
        for oid, value in rows.items():
            assert ".127.0.0.1" not in oid
            assert "127.0.0.1" not in value
            assert "7f000001" not in value


# --- edge cases ----------------------------------------------------------------------


def peer(**overrides):
    fields = {
        "local_port": "backhaul",
        "mac": ROOT,
        "port": "wl1",
        "ip": "192.168.50.1",
        "band": "5g1",
    }
    return Neighbor(**(fields | overrides))


def child(node, **neighbor):
    return node(backhaul=Backhaul(medium="wireless"), neighbors=[peer(**neighbor)])


@pytest.mark.parametrize("ip", [None, "127.0.0.1", "0.0.0.0", "fe80::1", "bogus"])
def test_a_missing_or_loopback_address_sends_no_management_address(node, render, ip):
    rows = render(child(node, ip=ip))
    assert under(rows, REM + "7.") == {"0.2.1": "4|wl1"}
    assert under(rows, REM_MAN) == {}


def test_an_unknown_peer_name_or_band_omits_or_generalizes_the_text(node, render):
    rows = render(child(node, band=None))
    assert REM + "9.0.2.1" not in rows
    assert rows[REM + "8.0.2.1"] == "4|radio"


def test_a_neighbor_on_an_unserved_port_or_with_a_bad_mac_is_skipped(node, render):
    assert under(render(child(node, local_port="wl7")), REM) == {}
    assert under(render(child(node, mac="nope")), REM) == {}


def test_several_children_on_one_radio_get_their_own_remote_index(node, radio, render):
    kids = [
        peer(local_port="wl1", mac=mac, port="backhaul", ip=ip)
        for mac, ip in ((NODE, "192.168.50.101"), (WIRED, "192.168.50.102"))
    ]
    rows = render(node(radios=[radio(1, "5g1")], neighbors=kids))
    assert under(rows, REM + "5.") == {
        "0.11.1": "4x|00005e005302",
        "0.11.2": "4x|00005e005303",
    }
