import asyncio
import copy
import re
import time

import pytest

from aimesh_snmp_proxy.collector import Collector, NodeIdentity
from aimesh_snmp_proxy.config import load_config, load_router_pin, load_secrets
from aimesh_snmp_proxy.model import NodeSnapshot, Radio, Stat
from aimesh_snmp_proxy.ops import selftest as selftest_mod
from aimesh_snmp_proxy.ops.selftest import (
    check_nodes,
    cli_selftest,
    selftest,
    wireless_sensors,
)

ROOT = "00:00:5e:00:53:01"
NODE = "00:00:5e:00:53:02"
MAC_TEXT = re.compile(r"[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}", re.IGNORECASE)


# --- which LibreNMS wireless sensors the extend rows create ------------------------


def test_every_sensor_is_created_when_every_value_is_served():
    extends = {
        "clients-wlan": "3",
        "clients-wl0": "1",
        "clients-wl1": "2",
        "frequency-wl0": "2437",
        "frequency-wl1": "5180",
        **{
            f"rate-{d}-{k}-{p}": "1000"
            for d in ("tx", "rx")
            for k in ("wl0", "wl1")
            for p in ("min", "max", "avg")
        },
    }
    created, omitted = wireless_sensors("wl0,wl-2.4G\nwl1,wl-5.0G", extends)
    assert created == ("clients wl0 wl1 wlan", "frequency wl0 wl1", "rate wl0 wl1")
    assert omitted == ("snr, noise-floor (never served)",)


def test_omitted_sensors_say_why():
    extends = {
        "clients-wl0": "0",
        "clients-wl1": "4",
        "clients-wl2": "0",
        "frequency-wl1": "5500",
        **{f"rate-tx-wl1-{p}": "9" for p in ("min", "max", "avg")},
    }
    created, omitted = wireless_sensors(
        "wl0,wl-2.4G\nwl1,wl-5.0G\nwl2,wl-6.0G", extends
    )
    assert created == ("clients wl0 wl1 wl2", "frequency wl1")
    assert omitted == (
        "clients wlan (missing)",
        "frequency wl0 wl2 (channel unknown)",
        "rate wl0 wl2 (no clients)",
        "rate wl1 (3 of 6 values)",
        "snr, noise-floor (never served)",
    )


def test_one_interface_needs_no_wlan_total_and_non_numbers_are_dropped():
    created, omitted = wireless_sensors(
        "wl0,wl-2.4G", {"clients-wl0": "2", "frequency-wl0": "n/a"}
    )
    assert created == ("clients wl0",)
    assert "frequency wl0 (channel unknown)" in omitted
    assert "rate wl0 (rate unknown)" in omitted


def test_no_interfaces_extend_means_no_wireless_sensors():
    assert wireless_sensors(None, {}) == ((), ("all (no interfaces extend)",))


# --- engines on loopback, one serving and one silent ---------------------------------


class FakeSource:
    def __init__(self, snapshots):
        self.snapshots = snapshots

    def current(self, node_id):
        return self.snapshots.get(node_id)


def snapshot(node_id, sys_name):
    return NodeSnapshot(
        node_id=node_id,
        sys_name=sys_name,
        mac=node_id,
        online=True,
        role="node",
        level=1,
        collected_at=time.monotonic(),
        model="XT9",
        firmware="3.0.0.6",
        radios=(
            Radio(
                0,
                "2g1",
                "00:00:5e:00:53:10",
                True,
                clients=2,
                freq_mhz=2437,
                client_tx_bps=Stat(1, 2, 3),
                client_rx_bps=Stat(4, 5, 6),
            ),
            Radio(1, "5g1", "00:00:5e:00:53:11", True, clients=0),
        ),
    )


@pytest.fixture
def cfg(make_config, base_config):
    return load_config(make_config(base_config), env={})


def test_check_nodes_queries_serving_engines_and_times_out_silent_ones(cfg):
    identities = [
        NodeIdentity(ROOT, ROOT, "192.168.50.1", "router", "aimesh-root", "RT-AX88U"),
        NodeIdentity(NODE, NODE, "192.168.50.101", "node", "aimesh-005302", "XT9"),
    ]
    source = FakeSource({ROOT: snapshot(ROOT, "aimesh-root")})
    reports = asyncio.run(
        check_nodes(cfg, load_secrets(cfg), source, identities, {ROOT: True})
    )
    root, node = reports
    assert root.serving
    assert root.sys_name == "aimesh-root"
    assert root.sys_object_id == "1.3.6.1.4.1.8072.3.2.10"
    assert root.sys_descr.startswith("ASUS XT9")
    assert root.oid_count > 20
    assert root.created == ("clients wl0 wl1 wlan", "frequency wl0", "rate wl0")
    assert "rate wl1 (no clients)" in root.omitted
    assert "frequency wl1 (channel unknown)" in root.omitted
    assert root.online is True
    assert not node.serving
    assert node.online is None
    assert "no SNMP reply" in node.reason
    for report in reports:
        assert not cfg.snmp.port_base <= report.port <= cfg.snmp.port_base + 255


# --- against the mock router ------------------------------------------------------


@pytest.fixture
def live_cfg(make_config, base_config):
    def _make(router, expected="192.168.50.101-102"):
        doc = copy.deepcopy(base_config)
        doc["asus"].update(host="127.0.0.1", port=router.port)
        doc["nodes"] = {"expected": expected}
        return load_config(make_config(doc), env={})

    return _make


def run_selftest(cfg, **kwargs):
    secrets = load_secrets(cfg)
    pin = load_router_pin(cfg.asus.ca_file)
    return selftest(cfg, secrets, pin, kdf_n=2, **kwargs)


def tree(path):
    """Every file under ``path`` with its bytes and mtime."""
    if not path.exists():
        return {}
    return {
        p.relative_to(path): (p.read_bytes(), p.stat().st_mtime_ns)
        for p in sorted(path.rglob("*"))
        if p.is_file()
    }


def test_selftest_reports_every_node_and_writes_nothing(
    mock_router, live_cfg, capsys, canaries
):
    async def scenario():
        async with mock_router() as router:
            cfg = live_cfg(router)
            cfg.state_dir.mkdir()
            (cfg.state_dir / "ports.json").write_text(
                '{"version": 1, "next_index": 3, "nodes": {}}\n'
            )
            (cfg.state_dir / "counters.json").write_text("{}\n")
            before = tree(cfg.state_dir)
            code = await run_selftest(cfg)
            return code, router, cfg, before

    code, router, cfg, before = asyncio.run(scenario())
    out, err = capsys.readouterr()
    assert code == 0, out
    assert tree(cfg.state_dir) == before
    assert router.paths()[-1] == "/Logout.asp"
    lines = out.splitlines()
    header = next(i for i, line in enumerate(lines) if line.startswith("NODE"))
    rows = [line.split() for line in lines[header + 1 : header + 4]]
    # The root is aimesh-root once its MAC or IP is known as the root's.
    assert rows[0][0] in ("aimesh-root", "aimesh-005301")
    assert [r[0] for r in rows[1:]] == ["aimesh-005302", "aimesh-005303"]
    assert [r[3] for r in rows] == ["serving"] * 3
    assert all(int(r[4]) > 20 for r in rows)
    assert "wireless created: clients" in out
    assert "snr, noise-floor (never served)" in out
    assert "OK: all 3 nodes serve" in out
    for value in canaries.values():
        assert value not in out + err
    assert MAC_TEXT.search(out) is None


def test_an_absent_expected_node_fails(mock_router, live_cfg, capsys):
    async def scenario():
        async with mock_router() as router:
            return await run_selftest(live_cfg(router, expected="192.168.50.101-103"))

    assert asyncio.run(scenario()) == 1
    out = capsys.readouterr().out
    assert "expected 192.168.50.103: absent from the AiMesh list" in out
    assert "FAIL" in out


def test_a_latched_router_gets_no_login(mock_router, live_cfg, capsys):
    async def scenario():
        async with mock_router() as router:
            cfg = live_cfg(router)
            secrets = load_secrets(cfg)
            pin = load_router_pin(cfg.asus.ca_file)
            router.login_error = 10  # CAPTCHA: the service latches
            latched = Collector.from_config(cfg, secrets, pin, kdf_n=2)
            await latched.poll_once()
            await latched.shutdown(persist=False)
            router.login_error = None
            logins = len(router.logins())
            before = tree(cfg.state_dir)
            code = await run_selftest(cfg)
            return code, len(router.logins()) - logins, before, cfg

    code, new_logins, before, cfg = asyncio.run(scenario())
    assert code == 1
    assert new_logins == 0
    assert tree(cfg.state_dir) == before
    out = capsys.readouterr().out
    assert "no AiMesh list" in out
    assert "latched" in out


# --- cli_selftest --------------------------------------------------------------------


def test_cli_selftest_hands_its_parts_to_selftest(cfg, monkeypatch, canaries):
    seen = {}

    async def fake(cfg_, secrets, pin, **kwargs):
        seen.update(cfg=cfg_, secrets=secrets, pin=pin)
        return 0

    monkeypatch.setattr(selftest_mod, "selftest", fake)
    assert cli_selftest(cfg, []) == 0
    assert seen["cfg"] is cfg
    assert seen["secrets"].asus_password.get_secret_value() == canaries["asus_password"]
    assert seen["pin"].fingerprints


def test_cli_selftest_reports_config_errors_with_exit_78(cfg, capsys):
    cfg.asus.password_file.chmod(0o644)
    assert cli_selftest(cfg, []) == selftest_mod.EXIT_CONFIG
    assert "asus.password_file" in capsys.readouterr().err


def test_cli_selftest_usage_errors_exit_2(cfg):
    with pytest.raises(SystemExit) as caught:
        cli_selftest(cfg, ["--bogus"])
    assert caught.value.code == 2


# --- edges ---------------------------------------------------------------------------


def _index(name):
    data = name.encode()
    return ".".join(map(str, (len(data), *data)))


def test_extends_decodes_names_and_skips_malformed_indexes():
    from pysnmp.proto.rfc1902 import OctetString

    one = "1.3.6.1.4.1.8072.1.3.2.3.1.1"
    full = "1.3.6.1.4.1.8072.1.3.2.3.1.2"
    rows = [
        ("1.3.6.1.2.1.1.5.0", OctetString("x")),
        (f"{full}.{_index('interfaces')}", OctetString("wl0,wl-2.4G")),
        (f"{one}.{_index('clients-wl0')}", OctetString("2")),
        (f"{one}.3.99.99", OctetString("length says 3, 2 bytes follow")),
        (f"{one}.1.300", OctetString("not a byte")),
    ]
    assert selftest_mod._extends(rows) == ("wl0,wl-2.4G", {"clients-wl0": "2"})


def test_free_ports_avoid_the_service_range(cfg, monkeypatch):
    from types import SimpleNamespace

    picks = iter([cfg.snmp.port_base + 3, 1000, 50000])

    class FakeSocket:
        def __init__(self, *args):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def bind(self, address):
            pass

        def getsockname(self):
            return ("127.0.0.1", next(picks))

    fake = SimpleNamespace(socket=FakeSocket, AF_INET=0, SOCK_DGRAM=0)
    monkeypatch.setattr(selftest_mod, "socket", fake)
    assert selftest_mod._free_port(cfg) == 50000


class FlakyServer:
    def __init__(self, failures):
        self.failures = failures
        self.ports = []

    async def add(self, spec):
        self.ports.append(spec.port)
        if self.failures:
            self.failures -= 1
            raise OSError(48, "Address already in use")


def _root_identity():
    return NodeIdentity(ROOT, ROOT, "192.168.50.1", "router", "aimesh-root", None)


def test_a_taken_test_port_is_replaced_by_another_free_one(cfg):
    server = FlakyServer(failures=1)
    port = asyncio.run(
        selftest_mod._start(server, cfg, load_secrets(cfg), _root_identity())
    )
    assert len(server.ports) == 2
    assert port == server.ports[-1]


def test_a_node_without_an_engine_is_reported(cfg, monkeypatch, capsys):
    async def no_port(*args):
        raise OSError(48, "Address already in use")

    monkeypatch.setattr(selftest_mod, "_start", no_port)
    reports = asyncio.run(
        check_nodes(cfg, load_secrets(cfg), FakeSource({}), [_root_identity()], {})
    )
    assert reports[0].reason.startswith("no engine:")
    assert selftest_mod.print_report(cfg, reports, None, __import__("sys").stdout) == 1
    assert "aimesh-root: silent: no engine" in capsys.readouterr().out


def test_a_failed_walk_or_wrong_sysname_fails_the_node(cfg, monkeypatch, capsys):
    async def broken_walk(*args, **kwargs):
        raise selftest_mod.SnmpCheckError("no SNMP reply from 127.0.0.1:1")

    monkeypatch.setattr(selftest_mod, "walk", broken_walk)
    source = FakeSource({ROOT: snapshot(ROOT, "aimesh-root")})
    identity = NodeIdentity(ROOT, ROOT, "192.168.50.1", "router", "aimesh-root", None)
    (report,) = asyncio.run(
        check_nodes(cfg, load_secrets(cfg), source, [identity], {ROOT: True})
    )
    assert report.serving
    assert not report.ok
    import io

    out = io.StringIO()
    assert selftest_mod.print_report(cfg, [report], None, out) == 1
    assert "FAIL: walk: no SNMP reply" in out.getvalue()


def test_an_unreadable_latch_file_stops_before_any_login(cfg, capsys):
    cfg.state_dir.mkdir()
    cfg.lockout_file.write_text("{}")
    cfg.lockout_file.chmod(0)
    try:
        if cfg.lockout_file.stat().st_uid == 0:
            pytest.skip("root reads any file")
        code = asyncio.run(
            selftest(cfg, load_secrets(cfg), load_router_pin(cfg.asus.ca_file))
        )
    finally:
        cfg.lockout_file.chmod(0o600)
    assert code == 1
    assert "cannot read" in capsys.readouterr().out


def test_a_config_the_collector_refuses_exits_78(cfg, monkeypatch, capsys):
    def refuse(*args, **kwargs):
        raise selftest_mod.ConfigError("asus.use_ssl: pinned HTTPS only")

    monkeypatch.setattr(selftest_mod.Collector, "from_config", refuse)
    code = asyncio.run(
        selftest(cfg, load_secrets(cfg), load_router_pin(cfg.asus.ca_file))
    )
    assert code == selftest_mod.EXIT_CONFIG
    assert "pinned HTTPS only" in capsys.readouterr().err
