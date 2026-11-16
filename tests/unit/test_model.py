import dataclasses
import math

import pytest

from aimesh_snmp_proxy.model import (
    Backhaul,
    EthPort,
    Link,
    Neighbor,
    NodeSnapshot,
    Radio,
    Stat,
    Temperature,
    normalize_mac,
)


def snapshot(**overrides):
    fields = {
        "node_id": "aimesh-root",
        "sys_name": "aimesh-root",
        "mac": "00:00:5e:00:53:01",
        "online": True,
        "role": "router",
        "level": 0,
        "collected_at": 1000.0,
    }
    fields.update(overrides)
    return NodeSnapshot(**fields)


def radio(unit, **overrides):
    fields = {
        "unit": unit,
        "band": "2g1",
        "mac": f"00:00:5e:00:53:1{unit}",
        "state": True,
    }
    fields.update(overrides)
    return Radio(**fields)


def test_required_fields_only_leaves_every_metric_null():
    s = snapshot()
    assert s.ip is None
    assert s.model is None
    assert s.firmware is None
    assert s.location is None
    assert s.cpu_pct is None
    assert s.mem_pct is None
    assert s.cpu_core_pct is None
    assert s.mem_total_b is None
    assert s.mem_used_b is None
    assert s.uptime_s is None
    assert s.temps_c is None
    assert s.backhaul is None
    assert s.radios == ()
    assert s.links == ()


def test_snapshot_is_frozen():
    s = snapshot()
    with pytest.raises(dataclasses.FrozenInstanceError):
        s.online = False


def test_nested_types_are_frozen():
    r = radio(0)
    with pytest.raises(dataclasses.FrozenInstanceError):
        r.clients = 3
    with pytest.raises(dataclasses.FrozenInstanceError):
        Link("wired").rx_bps = 1
    with pytest.raises(dataclasses.FrozenInstanceError):
        Backhaul().rssi_dbm = -40
    with pytest.raises(dataclasses.FrozenInstanceError):
        Stat(1, 2, 3).avg = 5
    with pytest.raises(dataclasses.FrozenInstanceError):
        Temperature("cpu", 50.0).celsius = 1.0


def test_sequences_are_stored_as_tuples():
    s = snapshot(
        radios=[radio(1), radio(0)],
        links=[Link("wired"), Link("wl0")],
        cpu_core_pct=[10.0, 20.0],
        temps_c=[Temperature("cpu", 61.5)],
    )
    assert isinstance(s.radios, tuple)
    assert isinstance(s.links, tuple)
    assert s.cpu_core_pct == (10.0, 20.0)
    assert s.temps_c == (Temperature("cpu", 61.5),)
    hash(s)


def test_radios_are_sorted_by_wl_unit():
    s = snapshot(radios=[radio(2), radio(0), radio(1)])
    assert [r.unit for r in s.radios] == [0, 1, 2]


def test_duplicate_radio_unit_is_rejected():
    with pytest.raises(ValueError, match="duplicate radio unit 1"):
        snapshot(radios=[radio(1), radio(1)])


def test_duplicate_link_name_is_rejected():
    with pytest.raises(ValueError, match="duplicate link 'wired'"):
        snapshot(links=[Link("wired"), Link("wired")])


def test_neighbors_and_ports_default_empty_and_are_stored_as_tuples():
    assert (snapshot().neighbors, snapshot().ports) == ((), ())
    peer = Neighbor("backhaul", "00:00:5e:00:53:01", "wl1", "192.168.50.1", "5g1")
    s = snapshot(neighbors=[peer], ports=[EthPort("L1", "LAN1"), EthPort("W0", "WAN")])
    assert s.neighbors == (peer,)
    assert [p.native for p in s.ports] == ["L1", "W0"]
    assert (peer.ip, EthPort("L1", "LAN1").up) == ("192.168.50.1", None)
    hash(s)


def test_duplicate_port_id_is_rejected():
    with pytest.raises(ValueError, match="duplicate port 'L1'"):
        snapshot(ports=[EthPort("L1", "LAN1"), EthPort("L1", "LAN1")])


def test_radio_defaults_are_null_safe():
    r = radio(0)
    assert r.clients == 0
    assert r.freq_mhz is None
    assert r.client_rssi_dbm is None
    assert r.client_tx_bps is None
    assert r.client_rx_bps is None


def test_link_carries_rates_and_derived_octets():
    link = Link("wl0", rx_bps=1_000, tx_bps=2_000, in_octets=5, out_octets=7)
    assert (link.rx_bps, link.tx_bps) == (1_000, 2_000)
    assert (link.in_octets, link.out_octets) == (5, 7)
    assert Link("backhaul").in_octets is None


def test_backhaul_fields_default_to_null():
    b = Backhaul()
    assert (b.medium, b.band, b.rssi_dbm, b.link_bps, b.parent_mac) == (
        None,
        None,
        None,
        None,
        None,
    )


def test_radio_and_link_lookup():
    s = snapshot(radios=[radio(0), radio(1)], links=[Link("wired"), Link("wl1")])
    assert s.radio(1).unit == 1
    assert s.radio(5) is None
    assert s.link("wl1").name == "wl1"
    assert s.link("backhaul") is None


@pytest.mark.parametrize(
    ("now", "fresh"),
    [
        (1000.0, True),
        (1100.0, True),
        (1180.0, True),
        (1180.001, False),
        (999.0, False),
        (math.nan, False),
    ],
)
def test_is_fresh(now, fresh):
    assert snapshot(collected_at=1000.0).is_fresh(now, 180) is fresh


def test_is_fresh_with_nan_collection_time_is_stale():
    assert snapshot(collected_at=math.nan).is_fresh(1000.0, 180) is False


def test_stat_of_summarizes_non_null_values():
    assert Stat.of([10, None, 20, 30]) == Stat(min=10, avg=20.0, max=30)


@pytest.mark.parametrize("values", [[], [None, None]])
def test_stat_of_without_values_is_null(values):
    assert Stat.of(values) is None


def test_stat_of_accepts_generators():
    assert Stat.of(v for v in (4, 8)) == Stat(4, 6.0, 8)


@pytest.mark.parametrize(
    ("raw", "normalized"),
    [
        ("00:00:5E:00:53:0A", "00:00:5e:00:53:0a"),
        ("00-00-5e-00-53-0a", "00:00:5e:00:53:0a"),
        ("00005E00530A", "00:00:5e:00:53:0a"),
        (" 00:00:5e:00:53:0a ", "00:00:5e:00:53:0a"),
    ],
)
def test_normalize_mac(raw, normalized):
    assert normalize_mac(raw) == normalized


@pytest.mark.parametrize(
    "raw", ["00:00:5e:00:53", "00:00:5e:00:53:zz", "00:00-5e:00:53:01", "", "x"]
)
def test_normalize_mac_rejects_malformed(raw):
    assert normalize_mac(raw) is None
