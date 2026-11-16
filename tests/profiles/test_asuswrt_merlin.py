import pytest

from aimesh_snmp_proxy.model import Stat
from aimesh_snmp_proxy.profiles import DEFAULT_PROFILE, PROFILES, get_profile
from aimesh_snmp_proxy.profiles.asuswrt_merlin import AsuswrtMerlin, encode_string
from aimesh_snmp_proxy.snmp.oidtable import format_oid

INFO = "1.3.6.1.4.1.2021.7890.1.101.1"
ONE_LINE = "1.3.6.1.4.1.8072.1.3.2.3.1.1."
INTERFACES = "1.3.6.1.4.1.8072.1.3.2.3.1.2.10.105.110.116.101.114.102.97.99.101.115"


def extend(name):
    return ONE_LINE + format_oid(encode_string(name))


def extends(rows):
    """Served extend lines as ``{name: value}``."""
    out = {}
    for oid, value in rows.items():
        if oid.startswith(ONE_LINE):
            arcs = [int(a) for a in oid[len(ONE_LINE) :].split(".")]
            assert arcs[0] == len(arcs) - 1
            out[bytes(arcs[1:]).decode()] = value
    return out


@pytest.fixture
def render(served):
    def _render(snapshot, profile=None, **kwargs):
        return served((profile or AsuswrtMerlin()).render(snapshot, **kwargs))

    return _render


@pytest.fixture
def three_radios(node, radio):
    return node(
        model="RT-AX92U",
        firmware="3.0.0.4.388_10000",
        radios=[
            radio(
                2,
                "5g2",
                clients=0,
                client_tx_bps=Stat(1, 2, 3),
                client_rx_bps=Stat(1, 2, 3),
            ),
            radio(
                0,
                "2g1",
                clients=3,
                freq_mhz=2437,
                client_tx_bps=Stat(1_000_000, 72_224_999.6, 144_400_000),
                client_rx_bps=None,
            ),
            radio(1, "5g1", clients=1, freq_mhz=5180),
        ],
    )


def test_encode_string_matches_librenms():
    assert format_oid(encode_string("clients-eth1")) == (
        "12.99.108.105.101.110.116.115.45.101.116.104.49"
    )


def test_detection_oids(node, render):
    rows = render(node(model="RT-AC68U", firmware="384.17_0"))
    assert rows["1.3.6.1.2.1.1.2.0"] == "6|1.3.6.1.4.1.8072.3.2.10"
    assert rows[INFO] == "4|ASUSWRT-Merlin RT-AC68U 384.17_0"


@pytest.mark.parametrize(
    ("model", "firmware", "info"),
    [
        ("RT AX88U Pro", " 388.1 beta\t2 ", "ASUSWRT-Merlin RT_AX88U_Pro 388.1_beta_2"),
        ("RT-AX88U", None, "ASUSWRT-Merlin RT-AX88U"),
        (None, "388.1", "ASUSWRT-Merlin"),
        ("  ", "388.1", "ASUSWRT-Merlin"),
        (None, None, "ASUSWRT-Merlin"),
    ],
)
def test_info_string_keeps_one_word_per_part(node, render, model, firmware, info):
    assert render(node(model=model, firmware=firmware))[INFO] == f"4|{info}"


def test_interfaces_line_order_and_format(three_radios, render):
    value = render(three_radios)[INTERFACES]
    assert value.startswith("4x|")
    assert bytes.fromhex(value[3:]) == b"wl0,wl-2.4G\nwl1,wl-5.0G\nwl2,wl-5.0G-2"


def test_client_counts(three_radios, render):
    served = extends(render(three_radios))
    assert served["clients-wlan"] == "4|4"
    assert [served[f"clients-wl{u}"] for u in range(3)] == ["4|3", "4|1", "4|0"]


def test_frequency_only_when_known(three_radios, render):
    served = extends(render(three_radios))
    assert served["frequency-wl0"] == "4|2437"
    assert served["frequency-wl1"] == "4|5180"
    assert "frequency-wl2" not in served


def test_rates_need_clients_and_data(three_radios, render):
    served = extends(render(three_radios))
    rates = {name: value for name, value in served.items() if name.startswith("rate")}
    assert rates == {
        "rate-tx-wl0-min": "4|1000000",
        "rate-tx-wl0-max": "4|144400000",
        "rate-tx-wl0-avg": "4|72225000",
    }


def test_unusable_rates_are_dropped(node, radio, render):
    stat = Stat(-1.0, float("nan"), 5.4)
    served = extends(render(node(radios=[radio(0, clients=2, client_rx_bps=stat)])))
    assert {k: v for k, v in served.items() if k.startswith("rate")} == {
        "rate-rx-wl0-max": "4|5"
    }


def test_snr_and_noise_floor_are_never_served(three_radios, render):
    names = extends(render(three_radios))
    assert not [n for n in names if n.startswith(("snr-", "noise-floor-"))]


def test_no_radios_serves_no_wireless_oids(node, render):
    rows = render(node(model="RT-AX88U"))
    assert INTERFACES not in rows
    assert extends(rows) == {}
    assert rows[INFO] == "4|ASUSWRT-Merlin RT-AX88U"


def test_injected_interface_keys(three_radios, render):
    profile = AsuswrtMerlin(iface_keys={0: "eth1", 1: "eth2"})
    rows = render(three_radios, profile)
    assert bytes.fromhex(rows[INTERFACES][3:]) == (
        b"eth1,wl-2.4G\neth2,wl-5.0G\nwl2,wl-5.0G-2"
    )
    assert extends(rows)["clients-eth1"] == "4|3"
    assert "clients-wl0" not in extends(rows)


@pytest.mark.parametrize("key", ["", "a,b", "a\nb", "a b", "-x", "x" * 33])
def test_invalid_interface_keys_are_rejected(key):
    with pytest.raises(ValueError, match="invalid interface key"):
        AsuswrtMerlin(iface_keys={0: key})


def test_render_passes_context_to_the_base_rows(node, render):
    rows = render(node(), now=1050.0, serving_since=1000.0, sys_name="office")
    assert rows["1.3.6.1.2.1.1.3.0"] == "67|5000"
    assert rows["1.3.6.1.2.1.1.5.0"] == "4|office"


def test_registry():
    assert DEFAULT_PROFILE == "asuswrt-merlin"
    assert set(PROFILES) == {"asuswrt-merlin"}
    assert isinstance(get_profile("asuswrt-merlin"), AsuswrtMerlin)
    assert get_profile("asuswrt-merlin").name == "asuswrt-merlin"


def test_unknown_profile_is_rejected():
    with pytest.raises(
        ValueError, match=r"unknown profile 'zebra'; known: asuswrt-merlin"
    ):
        get_profile("zebra")
