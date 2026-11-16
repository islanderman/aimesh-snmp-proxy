import math

import pytest

from aimesh_snmp_proxy.model import Backhaul, EthPort, Link, Stat, Temperature
from aimesh_snmp_proxy.profiles.base import NET_SNMP_LINUX, base_rows

SYS = "1.3.6.1.2.1.1."
IF = "1.3.6.1.2.1.2.2.1."
IFX = "1.3.6.1.2.1.31.1.1.1."
STORAGE = "1.3.6.1.2.1.25.2.3.1."
DEVICE = "1.3.6.1.2.1.25.3.2.1."
LOAD = "1.3.6.1.2.1.25.3.3.1.2."
ENT = "1.3.6.1.2.1.47.1.1.1.1."
SENSOR = "1.3.6.1.2.1.99.1.1.1."


@pytest.fixture
def render(served):
    def _render(snapshot, **kwargs):
        kwargs.setdefault("sys_object_id", NET_SNMP_LINUX)
        return served(base_rows(snapshot, **kwargs))

    return _render


def under(rows, prefix):
    return {oid: value for oid, value in rows.items() if oid.startswith(prefix)}


def test_system_group(node, render):
    rows = render(
        node(
            model="RT-AX88U",
            firmware="3.0.0.4.388_10000",
            location="office",
            uptime_s=3600,
        )
    )
    assert under(rows, SYS) == {
        SYS + "1.0": "4|ASUS RT-AX88U stock 3.0.0.4.388_10000 via aimesh-snmp-proxy",
        SYS + "2.0": "6|1.3.6.1.4.1.8072.3.2.10",
        SYS + "3.0": "67|360000",
        SYS + "4.0": "4|",
        SYS + "5.0": "4|aimesh-0053a1",
        SYS + "6.0": "4|office",
    }


@pytest.mark.parametrize(
    ("model", "firmware", "descr"),
    [
        (None, None, "ASUS via aimesh-snmp-proxy"),
        ("RT-AX88U", None, "ASUS RT-AX88U via aimesh-snmp-proxy"),
        (None, "3.0.0.4", "ASUS stock 3.0.0.4 via aimesh-snmp-proxy"),
    ],
)
def test_sys_descr_drops_unknown_parts(node, render, model, firmware, descr):
    rows = render(node(model=model, firmware=firmware))
    assert rows[SYS + "1.0"] == f"4|{descr}"


def test_unknown_location_is_an_empty_string(node, render):
    assert render(node())[SYS + "6.0"] == "4|"


def test_sys_object_id_and_sys_name_come_from_the_caller(node, render):
    rows = render(node(), sys_object_id=(1, 3, 6, 1, 4, 1, 99), sys_name="office")
    assert rows[SYS + "2.0"] == "6|1.3.6.1.4.1.99"
    assert rows[SYS + "5.0"] == "4|office"


def test_known_uptime_advances_from_collection_time(node, render):
    rows = render(node(uptime_s=3600, collected_at=1000.0), now=1010.5)
    assert rows[SYS + "3.0"] == "67|361050"
    assert rows["1.3.6.1.2.1.25.1.1.0"] == "67|361050"


def test_known_uptime_never_moves_backwards_for_a_future_snapshot(node, render):
    rows = render(node(uptime_s=10, collected_at=1000.0), now=900.0)
    assert rows[SYS + "3.0"] == "67|1000"


def test_unknown_uptime_counts_from_serving_start(node, render):
    rows = render(node(), now=1500.0, serving_since=1200.0)
    assert rows[SYS + "3.0"] == "67|30000"
    assert "1.3.6.1.2.1.25.1.1.0" not in rows


def test_unknown_uptime_without_context_is_zero(node, render):
    assert render(node())[SYS + "3.0"] == "67|0"


def test_uptime_wraps_like_timeticks(node, render):
    rows = render(node(uptime_s=50_000_000))
    assert rows[SYS + "3.0"] == f"67|{5_000_000_000 % 2**32}"


def full_node(node, radio, **overrides):
    fields = {
        "backhaul": Backhaul(medium="wireless", band="5g1", link_bps=866_700_000),
        "radios": [radio(0, "2g1"), radio(1, "5g1", state=False)],
        "links": [
            Link("wired", in_octets=2**32 + 5, out_octets=7),
            Link("backhaul", rx_bps=1000, tx_bps=2000),
            Link("wl0", in_octets=10, out_octets=None),
        ],
    }
    fields.update(overrides)
    return node(**fields)


def test_interfaces_wired_backhaul_and_one_per_radio(node, radio, render):
    rows = render(full_node(node, radio))
    assert rows["1.3.6.1.2.1.2.1.0"] == "2|4"
    assert under(rows, IF + "1.") == {
        IF + "1.1": "2|1",
        IF + "1.2": "2|2",
        IF + "1.10": "2|10",
        IF + "1.11": "2|11",
    }
    assert [rows[IF + f"2.{i}"] for i in (1, 2, 10, 11)] == [
        "4|wired",
        "4|backhaul",
        "4|wl0",
        "4|wl1",
    ]
    assert [rows[IFX + f"1.{i}"] for i in (1, 2, 10, 11)] == [
        "4|wired",
        "4|backhaul",
        "4|wl0",
        "4|wl1",
    ]


def test_radio_interface_columns(node, radio, render):
    rows = render(full_node(node, radio))
    assert rows[IF + "3.10"] == "2|71"
    assert rows[IF + "5.10"] == "66|0"
    assert rows[IFX + "15.10"] == "66|0"
    assert rows[IF + "6.10"] == "4x|00005e005310"
    assert (rows[IF + "7.10"], rows[IF + "8.10"]) == ("2|1", "2|1")
    assert (rows[IF + "7.11"], rows[IF + "8.11"]) == ("2|2", "2|2")


def test_derived_octets_and_alias_suffix(node, radio, render):
    rows = render(full_node(node, radio))
    assert rows[IF + "10.1"] == "65|5"
    assert rows[IF + "16.1"] == "65|7"
    assert rows[IFX + "6.1"] == f"70|{2**32 + 5}"
    assert rows[IFX + "10.1"] == "70|7"
    assert rows[IFX + "18.1"] == "4|wired (derived)"
    assert rows[IFX + "6.10"] == "70|10"
    assert IFX + "10.10" not in rows
    assert IF + "16.10" not in rows
    assert rows[IFX + "18.10"] == "4|wl-2.4G (derived)"


def test_interfaces_without_octets_have_a_plain_alias(node, radio, render):
    rows = render(full_node(node, radio))
    assert IF + "10.2" not in rows
    assert IFX + "6.2" not in rows
    assert rows[IFX + "18.2"] == "4|backhaul"
    assert rows[IFX + "18.11"] == "4|wl-5.0G"


def test_wired_interface(node, radio, render):
    rows = render(full_node(node, radio))
    assert rows[IF + "3.1"] == "2|6"
    assert rows[IF + "6.1"] == "4x|00005e005301"
    assert (rows[IF + "7.1"], rows[IF + "8.1"]) == ("2|1", "2|1")  # it has counters
    assert rows[IF + "5.1"] == "66|0"


def test_a_wired_row_without_counters_has_an_unknown_status(node, radio, render):
    rows = render(full_node(node, radio, links=[Link("wired", rx_bps=5)]))
    assert (rows[IF + "7.1"], rows[IF + "8.1"]) == ("2|1", "2|4")


@pytest.mark.parametrize(
    ("backhaul", "if_type", "oper"),
    [
        (Backhaul(medium="wireless"), "2|71", "2|1"),
        (Backhaul(medium="mlo"), "2|71", "2|1"),
        (Backhaul(medium="wired"), "2|6", "2|1"),
        (Backhaul(medium="plc"), "2|1", "2|1"),
        (Backhaul(medium="unknown"), "2|1", "2|4"),
        (Backhaul(), "2|1", "2|4"),
    ],
)
def test_backhaul_type_and_status_follow_the_medium(
    node, render, backhaul, if_type, oper
):
    rows = render(node(backhaul=backhaul))
    assert rows[IF + "3.2"] == if_type
    assert rows[IF + "8.2"] == oper
    assert rows[IF + "7.2"] == "2|1"
    assert IF + "6.2" not in rows


def test_backhaul_speed(node, render):
    rows = render(node(backhaul=Backhaul(medium="wired", link_bps=866_700_000)))
    assert rows[IF + "5.2"] == "66|866700000"
    assert rows[IFX + "15.2"] == "66|866"


def test_backhaul_speed_above_gauge32_saturates(node, render):
    rows = render(node(backhaul=Backhaul(medium="wireless", link_bps=4_803_900_000)))
    assert rows[IF + "5.2"] == "66|4294967295"
    assert rows[IFX + "15.2"] == "66|4803"


def test_a_backhaul_link_without_backhaul_info_still_gets_a_row(node, render):
    rows = render(node(links=[Link("backhaul", in_octets=1)]))
    assert rows[IF + "2.2"] == "4|backhaul"
    assert rows[IF + "8.2"] == "2|4"


def test_root_without_backhaul_and_unknown_links_get_no_rows(node, render):
    rows = render(node(level=0, links=[Link("eth0"), Link("wl3"), Link("wl")]))
    assert rows["1.3.6.1.2.1.2.1.0"] == "2|0"
    assert under(rows, IF) == {}
    assert under(rows, IFX) == {}


def test_negative_octets_are_omitted(node, render):
    rows = render(node(links=[Link("wired", in_octets=-1, out_octets=3)]))
    assert IF + "10.1" not in rows
    assert rows[IF + "16.1"] == "65|3"


def test_invalid_mac_omits_the_physical_address(node, radio, render):
    rows = render(node(radios=[radio(0, mac="not-a-mac")]))
    assert IF + "6.10" not in rows
    assert rows[IF + "2.10"] == "4|wl0"


def test_unknown_band_label_falls_back_to_the_unit(node, radio, render):
    rows = render(node(radios=[radio(2, "unknown")]))
    assert rows[IFX + "18.12"] == "4|wl2"


# --- Ethernet ports -----------------------------------------------------------------

PORTS = (
    EthPort("W0", "WAN", up=True, speed_mbps=2500, label="2.5G WAN"),
    EthPort("L1", "LAN1", up=False, speed_mbps=0),
    EthPort("L12", "LAN12"),
)


def test_ethernet_ports_get_their_own_stable_ifindex_range(node, radio, render):
    rows = render(full_node(node, radio, ports=PORTS))
    assert rows["1.3.6.1.2.1.2.1.0"] == "2|7"
    indexes = [int(oid.rsplit(".", 1)[1]) for oid in under(rows, IF + "1.")]
    assert indexes == [1, 2, 10, 11, 100, 111, 122]
    for i, name in ((100, "WAN"), (111, "LAN1"), (122, "LAN12")):
        assert rows[IF + f"2.{i}"] == rows[IFX + f"1.{i}"] == f"4|{name}"
        assert rows[IF + f"3.{i}"] == "2|6"  # ethernetCsmacd
        assert rows[IF + f"7.{i}"] == "2|1"
        assert IF + f"6.{i}" not in rows  # no per-port MAC is known
        assert IF + f"10.{i}" not in rows  # nor port counters


def test_ethernet_port_status_speed_and_alias(node, render):
    rows = render(node(ports=PORTS))
    assert [rows[IF + f"8.{i}"] for i in (100, 111, 122)] == ["2|1", "2|2", "2|4"]
    assert rows[IF + "5.100"] == "66|2500000000"
    assert rows[IFX + "15.100"] == "66|2500"
    assert [rows[IF + f"5.{i}"] for i in (111, 122)] == ["66|0", "66|0"]
    assert rows[IFX + "18.100"] == "4|2.5G WAN"
    assert rows[IFX + "18.111"] == "4|LAN1"


def test_no_port_data_serves_no_port_rows(node, radio, render):
    rows = render(full_node(node, radio))
    assert not [
        oid for oid in under(rows, IF + "1.") if int(oid.rsplit(".")[-1]) >= 100
    ]


def test_memory_in_bytes(node, render):
    rows = render(node(mem_total_b=512 * 2**20, mem_used_b=200 * 2**20, mem_pct=39.0))
    assert rows["1.3.6.1.2.1.25.2.2.0"] == "2|524288"
    assert under(rows, STORAGE) == {
        STORAGE + "1.1": "2|1",
        STORAGE + "2.1": "6|1.3.6.1.2.1.25.2.1.2",
        STORAGE + "3.1": "4|Physical memory",
        STORAGE + "4.1": "2|1024",
        STORAGE + "5.1": "2|524288",
        STORAGE + "6.1": "2|204800",
    }


def test_memory_as_percent_when_bytes_are_unknown(node, render):
    rows = render(node(mem_pct=42.4))
    assert "1.3.6.1.2.1.25.2.2.0" not in rows
    assert under(rows, STORAGE) == {
        STORAGE + "1.1": "2|1",
        STORAGE + "2.1": "6|1.3.6.1.2.1.25.2.1.2",
        STORAGE + "3.1": "4|Physical memory (%)",
        STORAGE + "4.1": "2|1",
        STORAGE + "5.1": "2|100",
        STORAGE + "6.1": "2|42",
    }


def test_total_memory_without_used_bytes_falls_back_to_percent(node, render):
    rows = render(node(mem_total_b=256 * 2**20, mem_pct=101.0))
    assert rows["1.3.6.1.2.1.25.2.2.0"] == "2|262144"
    assert rows[STORAGE + "6.1"] == "2|100"


@pytest.mark.parametrize(
    ("total", "used"), [(2**41 + 2**10, 2**20), (512 * 2**20, 600 * 2**20)]
)
def test_unrepresentable_memory_bytes_fall_back_to_percent(node, render, total, used):
    rows = render(node(mem_total_b=total, mem_used_b=used, mem_pct=12.0))
    assert rows[STORAGE + "3.1"] == "4|Physical memory (%)"
    assert rows[STORAGE + "6.1"] == "2|12"


@pytest.mark.parametrize("mem_pct", [None, math.nan])
def test_no_memory_data_serves_no_storage(node, render, mem_pct):
    rows = render(node(mem_pct=mem_pct))
    assert under(rows, STORAGE) == {}
    assert "1.3.6.1.2.1.25.2.2.0" not in rows


def test_processors_per_core(node, render):
    rows = render(node(cpu_pct=55.0, cpu_core_pct=(10.4, 99.6)))
    assert under(rows, LOAD) == {LOAD + "196608": "2|10", LOAD + "196609": "2|100"}
    assert under(rows, DEVICE) == {
        DEVICE + "1.196608": "2|196608",
        DEVICE + "1.196609": "2|196609",
        DEVICE + "2.196608": "6|1.3.6.1.2.1.25.3.1.3",
        DEVICE + "2.196609": "6|1.3.6.1.2.1.25.3.1.3",
        DEVICE + "3.196608": "4|Core 0",
        DEVICE + "3.196609": "4|Core 1",
    }


def test_one_aggregate_processor_without_per_core_data(node, render):
    rows = render(node(cpu_pct=37.6))
    assert under(rows, LOAD) == {LOAD + "196608": "2|38"}
    assert rows[DEVICE + "3.196608"] == "4|CPU"


def test_processor_load_is_clamped_and_non_finite_is_dropped(node, render):
    rows = render(node(cpu_core_pct=(-3.0, 140.0, math.inf)))
    assert under(rows, LOAD) == {LOAD + "196608": "2|0", LOAD + "196609": "2|100"}


def test_no_cpu_data_serves_no_processors(node, render):
    rows = render(node(cpu_core_pct=()))
    assert under(rows, LOAD) == {}
    assert under(rows, DEVICE) == {}


def test_temperatures_sorted_by_sensor_name(node, render):
    temps = (Temperature("radio_5g1", 55.0), Temperature("cpu", 61.5))
    rows = render(node(temps_c=temps))
    # LibreNMS labels a sensor with entPhysicalName and walks entPhysicalDescr first.
    assert under(rows, ENT) == {
        ENT + "2.1": "4|CPU temperature",
        ENT + "2.2": "4|wl-5.0G radio temperature",
        ENT + "7.1": "4|CPU",
        ENT + "7.2": "4|wl-5.0G radio",
    }
    assert under(rows, SENSOR) == {
        SENSOR + "1.1": "2|8",
        SENSOR + "2.1": "2|9",
        SENSOR + "3.1": "2|1",
        SENSOR + "4.1": "2|615",
        SENSOR + "5.1": "2|1",
        SENSOR + "1.2": "2|8",
        SENSOR + "2.2": "2|9",
        SENSOR + "3.2": "2|1",
        SENSOR + "4.2": "2|550",
        SENSOR + "5.2": "2|1",
    }


def test_rssi_sensors_take_the_one_path_librenms_maps_to_dbm(node, radio, render):
    # LibreNMS skips entPhySensorType 14 (no dBm in RFC 3433); it maps other(1)
    # named "... Rx Power Sensor" to dbm (entity-sensor.inc.php:74-76).
    rows = render(
        node(
            backhaul=Backhaul(medium="wireless", rssi_dbm=-61),
            radios=[radio(1, "5g1", client_rssi_dbm=Stat(-70, -55.0, -40))],
        )
    )
    assert rows[ENT + "7.100"] == "4|backhaul Rx Power Sensor"
    assert rows[ENT + "2.100"] == "4|backhaul RSSI in dBm"
    assert [rows[SENSOR + f"{c}.100"] for c in range(1, 6)] == [
        "2|1",
        "2|9",
        "2|0",
        "2|-61",
        "2|1",
    ]
    assert rows[ENT + "7.201"] == "4|wl-5.0G clients Rx Power Sensor"
    assert rows[ENT + "2.201"] == "4|wl-5.0G client RSSI average in dBm"
    assert [rows[SENSOR + f"{c}.201"] for c in range(1, 6)] == [
        "2|1",
        "2|9",
        "2|1",
        "2|-550",
        "2|1",
    ]
    assert "2|14" not in under(rows, SENSOR + "1.").values()


def test_unusable_sensor_values_are_dropped(node, render):
    temps = (Temperature("cpu", math.nan), Temperature("hot", 1e12))
    rows = render(node(temps_c=temps))
    assert under(rows, ENT) == {}
    assert under(rows, SENSOR) == {}


def test_no_ucd_snmp_mib(node, radio, render):
    snapshot = full_node(node, radio, cpu_pct=5.0, mem_pct=5.0)
    assert under(render(snapshot), "1.3.6.1.4.1.2021.") == {}
