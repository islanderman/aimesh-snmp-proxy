import copy

import pytest

from aimesh_snmp_proxy.config import load_config
from aimesh_snmp_proxy.ops import onboard
from aimesh_snmp_proxy.ops.ledger import Entry, Ledger, LedgerError

API = "/api/v0/devices"
REMOVE = ["--remove", "--apply", "--allow-http"]


@pytest.fixture
def cfg(make_config, base_config, fake):
    doc = copy.deepcopy(base_config)
    doc["onboard"] = {"url": fake.url, "token_file": "onboard_token"}
    cfg = load_config(make_config(doc), env={})
    cfg.state_dir.mkdir()
    return cfg


@pytest.fixture
def ledger(cfg):
    return Ledger.load(cfg.state_dir / "onboarded.json")


def record(ledger, fake, hostname, port, *, device_id=None, origin=None):
    """Create the device on the fake (unless an id is given) and record it."""
    if device_id is None:
        device_id = fake.add_existing(hostname, overwrite_ip="127.0.0.1", port=port)
    ledger.record(
        Entry(hostname, device_id, port, origin or fake.url, "2026-11-13T20:00:00Z")
    )
    return device_id


def run(cfg, *argv):
    return onboard.cli_onboard(cfg, list(argv))


def remaining(cfg):
    return [e.hostname for e in Ledger.load(cfg.state_dir / "onboarded.json").entries()]


def test_remove_is_a_dry_run_by_default(cfg, fake, ledger, capsys):
    record(ledger, fake, "aimesh-00000a", 16102)
    fake.requests.clear()
    assert run(cfg, "--remove", "--allow-http") == 0
    out = capsys.readouterr().out
    assert fake.requests == []
    assert f"GET    {API}/500  (created as aimesh-00000a" in out
    assert "must still be at 127.0.0.1:16102" in out
    assert f"DELETE {API}/500" in out
    assert "--apply" in out
    assert remaining(cfg) == ["aimesh-00000a"]


def test_remove_deletes_only_the_recorded_devices_in_port_order(cfg, fake, ledger):
    record(ledger, fake, "aimesh-00000b", 16103)
    record(ledger, fake, "aimesh-root", 16101)
    fake.add_existing("core-switch")
    fake.add_existing("aimesh-00000c")  # added by hand, never recorded
    assert run(cfg, *REMOVE) == 0
    assert fake.calls() == [
        ("GET", f"{API}/501"),
        ("DELETE", f"{API}/501"),
        ("GET", f"{API}/500"),
        ("DELETE", f"{API}/500"),
    ]
    assert sorted(d["hostname"] for d in fake.devices.values()) == [
        "aimesh-00000c",
        "core-switch",
    ]
    assert remaining(cfg) == []


def test_remove_deletes_a_renamed_device_by_its_id(cfg, fake, ledger, capsys):
    device_id = record(ledger, fake, "aimesh-00000a", 16102)
    fake.devices[device_id]["hostname"] = "192.168.50.101"  # renamed in LibreNMS
    assert run(cfg, *REMOVE) == 0
    assert fake.calls() == [("GET", f"{API}/500"), ("DELETE", f"{API}/500")]
    assert fake.devices == {}
    assert remaining(cfg) == []
    assert f"removed (device {device_id})" in capsys.readouterr().out


def test_remove_never_touches_a_device_recreated_under_the_old_name(
    cfg, fake, ledger, capsys
):
    record(ledger, fake, "aimesh-00000a", 16102, device_id=42)  # gone from LibreNMS
    fake.add_existing("aimesh-00000a", overwrite_ip="127.0.0.1", port=16102)  # 500
    assert run(cfg, *REMOVE) == 0
    assert fake.calls() == [("GET", f"{API}/42")]
    assert list(fake.devices) == [500]
    assert remaining(cfg) == []
    assert "already gone" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("fields", "seen"),
    [
        ({"overwrite_ip": "127.0.0.1", "port": 16999}, "127.0.0.1:16999"),
        ({"overwrite_ip": "192.168.50.50", "port": 16102}, "192.168.50.50:16102"),
        ({"overwrite_ip": None, "port": 161}, "-:161"),
        ({}, "-:-"),
    ],
    ids=["other-port", "other-ip", "reused-id", "no-endpoint"],
)
def test_remove_keeps_a_device_that_is_not_at_the_recorded_endpoint(
    cfg, fake, ledger, capsys, fields, seen
):
    device_id = fake.add_existing("someone-elses", **fields)  # 500
    record(ledger, fake, "aimesh-00000a", 16102, device_id=device_id)
    assert run(cfg, *REMOVE) == 1
    assert fake.calls() == [("GET", f"{API}/500")]
    assert list(fake.devices) == [500]
    assert remaining(cfg) == ["aimesh-00000a"]
    out = capsys.readouterr().out
    assert f"kept: device 500 (someone-elses) is at {seen}" in out
    assert "not at 127.0.0.1:16102 where onboard created it" in out


def test_remove_forgets_devices_that_are_already_gone(cfg, fake, ledger, capsys):
    record(ledger, fake, "aimesh-00000a", 16102, device_id=42)
    assert run(cfg, *REMOVE) == 0
    assert [c[0] for c in fake.calls()] == ["GET"]
    assert remaining(cfg) == []
    assert "already gone" in capsys.readouterr().out


def test_remove_leaves_devices_recorded_for_another_server(cfg, fake, ledger, capsys):
    record(ledger, fake, "aimesh-00000a", 16102, device_id=7, origin="https://x:443")
    assert run(cfg, *REMOVE) == 0
    assert fake.requests == []
    assert remaining(cfg) == ["aimesh-00000a"]
    assert "https://x:443" in capsys.readouterr().out


def test_remove_with_an_empty_ledger_sends_nothing(cfg, fake, capsys):
    assert run(cfg, *REMOVE) == 0
    assert fake.requests == []
    assert "Nothing to remove" in capsys.readouterr().out


def test_remove_stops_at_a_401_after_one_request(cfg, fake, ledger, capsys):
    record(ledger, fake, "aimesh-00000a", 16102)
    record(ledger, fake, "aimesh-00000b", 16103)
    fake.requests.clear()
    fake.token = "another-token"
    assert run(cfg, *REMOVE) == 1
    assert len(fake.requests) == 1
    assert "HTTP 401" in capsys.readouterr().out
    assert len(remaining(cfg)) == 2


def test_remove_stops_when_the_token_may_not_delete(cfg, fake, ledger, capsys):
    device_id = record(ledger, fake, "aimesh-00000a", 16102)
    fake.routes["DELETE", f"{API}/{device_id}"] = lambda seen: fake.reply(
        403, {"message": "Insufficient permissions to delete this device"}
    )
    assert run(cfg, *REMOVE) == 1
    assert "Insufficient permissions to delete" in capsys.readouterr().out
    assert remaining(cfg) == ["aimesh-00000a"]


def test_a_dropped_delete_stops_and_keeps_the_entry(cfg, fake, ledger, capsys):
    device_id = record(ledger, fake, "aimesh-00000a", 16102)
    fake.routes["DELETE", f"{API}/{device_id}"] = lambda seen: None
    assert run(cfg, *REMOVE) == 1
    assert "may be gone" in capsys.readouterr().out
    assert remaining(cfg) == ["aimesh-00000a"]


def test_a_failed_delete_keeps_the_entry_and_continues(cfg, fake, ledger, capsys):
    device_id = record(ledger, fake, "aimesh-00000a", 16102)
    record(ledger, fake, "aimesh-00000b", 16103)
    fake.routes["DELETE", f"{API}/{device_id}"] = lambda seen: fake.reply(
        500, {"message": "Device deletion failed"}
    )
    assert run(cfg, *REMOVE) == 1
    assert remaining(cfg) == ["aimesh-00000a"]
    assert "failed: HTTP 500: Device deletion failed" in capsys.readouterr().out


def test_remove_does_not_need_a_valid_ports_json(cfg, fake, ledger):
    record(ledger, fake, "aimesh-00000a", 16102)
    cfg.ports_file.write_text("{")
    assert run(cfg, *REMOVE) == 0
    assert remaining(cfg) == []


def test_force_with_remove_is_a_usage_error(cfg, capsys):
    with pytest.raises(SystemExit) as caught:
        run(cfg, "--force", "--remove")
    assert caught.value.code == 2
    assert "--force" in capsys.readouterr().err


def test_a_ledger_failure_after_a_delete_stops_the_run(
    cfg, fake, ledger, monkeypatch, capsys
):
    record(ledger, fake, "aimesh-00000a", 16102)
    record(ledger, fake, "aimesh-00000b", 16103)

    def broken(self, hostname):
        raise LedgerError("onboarded.json: cannot write: disk full")

    monkeypatch.setattr(Ledger, "forget", broken)
    fake.requests.clear()
    assert run(cfg, *REMOVE) == 1
    assert fake.calls() == [("GET", f"{API}/500"), ("DELETE", f"{API}/500")]
    assert "device 500 is gone, but onboarded.json: cannot write" in (
        capsys.readouterr().out
    )
