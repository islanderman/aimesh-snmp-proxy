import dataclasses
import importlib
import json
from types import SimpleNamespace

import pytest

from aimesh_snmp_proxy.__main__ import COMMANDS
from aimesh_snmp_proxy.model import Backhaul, EthPort, Link, Neighbor, Stat, Temperature
from aimesh_snmp_proxy.profiles import cli_dump_snmprec, snapshot_json
from aimesh_snmp_proxy.profiles.snapshot_json import (
    MAX_SNAPSHOT_BYTES,
    load_snapshot,
    snapshot_from_dict,
)


@pytest.fixture
def full(node, radio):
    return node(
        model="RT-AX88U",
        firmware="3.0.0.4.388_10000",
        location="hall",
        cpu_pct=12.5,
        cpu_core_pct=(10.0, 15),
        mem_total_b=512 * 2**20,
        mem_used_b=100 * 2**20,
        uptime_s=86400,
        temps_c=(Temperature("cpu", 61.5),),
        backhaul=Backhaul(medium="wireless", band="5g1", rssi_dbm=-60, link_bps=10),
        radios=(
            radio(0, clients=2, client_tx_bps=Stat(1, 2, 3), freq_mhz=2437),
            radio(1, "5g1", client_rssi_dbm=Stat(-70, -60, -50)),
        ),
        links=(Link("wired", in_octets=5, out_octets=6), Link("backhaul", rx_bps=1)),
        neighbors=(
            Neighbor("backhaul", "00:00:5e:00:53:02", "wl1", "192.168.50.1", "5g1"),
        ),
        ports=(EthPort("W0", "WAN", up=True, speed_mbps=1000, label="WAN"),),
    )


def as_json(snapshot):
    return json.loads(json.dumps(dataclasses.asdict(snapshot)))


def test_round_trip_through_json(full):
    assert snapshot_from_dict(as_json(full)) == full


def test_ints_are_accepted_for_floats(full):
    data = as_json(full)
    data["collected_at"] = 7
    snapshot = snapshot_from_dict(data)
    assert snapshot.collected_at == 7.0
    assert isinstance(snapshot.collected_at, float)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda d: d.update(colour="red"), r"snapshot: unknown key\(s\): colour"),
        (
            lambda d: d["radios"][0].update(ssid="x"),
            r"snapshot\.radios\[0\]: unknown key\(s\): ssid",
        ),
        (lambda d: d.pop("mac"), "snapshot: .*mac"),
        (
            lambda d: d["radios"][0].update(state="false"),
            r"snapshot\.radios\[0\]\.state: expected bool",
        ),
        (lambda d: d.update(level=True), r"snapshot\.level: expected int"),
        (lambda d: d.update(level=1.5), r"snapshot\.level: expected int"),
        (lambda d: d.update(cpu_pct="5"), r"snapshot\.cpu_pct: expected float"),
        (lambda d: d.update(node_id=None), r"snapshot\.node_id: must not be null"),
        (lambda d: d.update(radios={}), r"snapshot\.radios: expected a list"),
        (lambda d: d.update(backhaul=[]), r"snapshot\.backhaul: expected an object"),
        (
            lambda d: d["temps_c"][0].update(celsius=None),
            r"snapshot\.temps_c\[0\]\.celsius: must not be null",
        ),
        (
            lambda d: d.update(radios=d["radios"] * 2),
            "duplicate radio unit",
        ),
    ],
)
def test_invalid_snapshots_are_rejected(full, mutate, message):
    data = as_json(full)
    mutate(data)
    with pytest.raises(ValueError, match=message):
        snapshot_from_dict(data)


def test_top_level_must_be_an_object():
    with pytest.raises(ValueError, match="snapshot: expected an object"):
        snapshot_from_dict([])


def test_load_snapshot_reads_a_file(tmp_path, full):
    path = tmp_path / "node.json"
    path.write_text(json.dumps(dataclasses.asdict(full)))
    assert load_snapshot(path) == full


def test_load_snapshot_rejects_bad_json(tmp_path):
    path = tmp_path / "node.json"
    path.write_text("{")
    with pytest.raises(ValueError, match=r"node\.json: invalid JSON"):
        load_snapshot(path)


def test_load_snapshot_rejects_huge_files(tmp_path):
    path = tmp_path / "node.json"
    path.write_bytes(b" " * (MAX_SNAPSHOT_BYTES + 1))
    with pytest.raises(ValueError, match="larger than"):
        load_snapshot(path)


def test_an_unsupported_model_field_type_is_a_loader_bug():
    with pytest.raises(TypeError, match="unsupported field type"):
        snapshot_json._convert("dict[str, int]", {}, "snapshot.x")


@pytest.fixture
def snapshot_file(tmp_path, full):
    path = tmp_path / "node.json"
    path.write_text(json.dumps(dataclasses.asdict(full)))
    return path


def test_cli_prints_snmprec(snapshot_file, capsys):
    assert cli_dump_snmprec(None, ["--snapshot", str(snapshot_file)]) == 0
    out = capsys.readouterr().out
    lines = out.splitlines()
    assert out.endswith("\n")
    assert "1.3.6.1.2.1.1.5.0|4|aimesh-0053a1" in lines
    assert "1.3.6.1.2.1.1.3.0|67|8640000" in lines
    assert (
        "1.3.6.1.4.1.2021.7890.1.101.1|4|ASUSWRT-Merlin RT-AX88U 3.0.0.4.388_10000"
        in lines
    )
    oids = [tuple(map(int, line.split("|")[0].split("."))) for line in lines]
    assert oids == sorted(oids)


def test_cli_profile_comes_from_the_flag_then_the_config(snapshot_file, capsys):
    config = SimpleNamespace(snmp=SimpleNamespace(profile="zebra"))
    args = ["--snapshot", str(snapshot_file)]
    assert cli_dump_snmprec(config, args) == 1
    assert "unknown profile 'zebra'" in capsys.readouterr().err
    assert cli_dump_snmprec(config, [*args, "--profile", "asuswrt-merlin"]) == 0


@pytest.mark.parametrize("content", [None, "{", '{"node_id": 1}'])
def test_cli_reports_unreadable_snapshots(tmp_path, capsys, content):
    path = tmp_path / "node.json"
    if content is not None:
        path.write_text(content)
    assert cli_dump_snmprec(None, ["--snapshot", str(path)]) == 1
    assert capsys.readouterr().err.startswith("dump-snmprec: ")


def test_cli_requires_a_snapshot():
    with pytest.raises(SystemExit) as exc:
        cli_dump_snmprec(None, [])
    assert exc.value.code == 2


def test_the_cli_registry_finds_the_handler():
    module_name, attribute, _ = COMMANDS["dump-snmprec"]
    assert getattr(importlib.import_module(module_name), attribute) is cli_dump_snmprec
