import asyncio
import copy
import errno
import logging
import signal
import socket

import pytest

from aimesh_snmp_proxy.collector import Collector, NodeIdentity
from aimesh_snmp_proxy.config import (
    ConfigError,
    default_sys_name,
    load_config,
    load_router_pin,
    load_secrets,
)
from aimesh_snmp_proxy.ops import run as run_mod
from aimesh_snmp_proxy.ops.run import Engines, cli_run, serve
from aimesh_snmp_proxy.ports import PortMap

ROOT = "00:00:5e:00:53:01"
NODE_A = "00:00:5e:00:53:02"
NODE_B = "00:00:5e:00:53:03"
BASE = 16101


def ident(mac, ip, role="node", name=None, model="XT9"):
    return NodeIdentity(mac, mac, ip, role, name or default_sys_name(mac), model)


class FakeTime:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class FakeServer:
    """SnmpServer's add/close contract; ``busy`` ports fail with OSError N times."""

    def __init__(self):
        self.specs = []
        self.attempts = []
        self.busy = {}
        self.invalid = set()
        self.broken = None
        self.closed = False

    async def add(self, spec):
        self.attempts.append((spec.node_id, spec.port))
        if self.broken is not None:
            raise self.broken
        if self.busy.get(spec.port, 0) > 0:
            self.busy[spec.port] -= 1
            message = f"node {spec.node_id!r}: cannot bind 127.0.0.1:{spec.port}"
            raise OSError(errno.EADDRINUSE, message)
        if spec.port in self.invalid:
            raise ValueError(f"port {spec.port} already serves another node")
        self.specs.append(spec)

    def close(self):
        self.closed = True


@pytest.fixture
def make_cfg(make_config, base_config):
    def _make(**doc):
        conf = copy.deepcopy(base_config)
        conf.update(doc)
        return load_config(make_config(conf), env={})

    return _make


@pytest.fixture
def cfg(make_cfg):
    return make_cfg()


def engines_for(cfg, server, **kwargs):
    ports = PortMap.load(cfg.ports_file, cfg.snmp.port_base, cfg.nodes.expected)
    return Engines(cfg, load_secrets(cfg), ports, server, **kwargs)


def served(server):
    return [(spec.node_id, spec.port) for spec in server.specs]


# --- engine allocation -------------------------------------------------------------


def test_the_root_takes_port_base_and_nodes_their_pinned_ports(cfg, canaries):
    server = FakeServer()
    engines = engines_for(cfg, server)
    nodes = [
        ident(NODE_B, "192.168.50.102"),
        ident(ROOT, "192.168.50.1", "router"),
        ident(NODE_A, "192.168.50.50"),
    ]
    asyncio.run(engines.sync(nodes))
    assert served(server) == [(ROOT, BASE), (NODE_A, BASE + 11), (NODE_B, BASE + 2)]
    reloaded = PortMap.load(cfg.ports_file, BASE, cfg.nodes.expected)
    assert reloaded.pinned() == {NODE_A: BASE + 11, NODE_B: BASE + 2}
    spec = server.specs[0]
    assert (spec.sys_name, spec.mac, spec.profile) == (
        "aimesh-005301",
        ROOT,
        "asuswrt-merlin",
    )
    assert spec.community.get_secret_value() == canaries["snmp_community"]
    assert spec.v3 is None
    asyncio.run(engines.sync(nodes))
    assert len(server.attempts) == 3  # a served node is never added twice


def test_the_router_ip_marks_the_root_even_with_a_node_role(cfg):
    server = FakeServer()
    asyncio.run(engines_for(cfg, server).sync([ident(ROOT, "192.168.50.1")]))
    assert served(server) == [(ROOT, BASE)]
    assert PortMap.load(cfg.ports_file, BASE, ()).pinned() == {}


def test_a_node_on_the_router_ip_beside_the_router_is_refused(cfg, caplog):
    server = FakeServer()
    nodes = [ident(NODE_A, "192.168.50.1"), ident(ROOT, "192.168.50.200", "router")]
    asyncio.run(engines_for(cfg, server).sync(nodes))
    assert served(server) == [(ROOT, BASE)]
    assert any("second root" in r.getMessage() for r in caplog.records)


def test_a_node_without_a_usable_ip_is_no_root(cfg):
    server = FakeServer()
    nodes = [ident(NODE_A, None), ident(NODE_B, "not-an-ip")]
    asyncio.run(engines_for(cfg, server).sync(nodes))
    assert served(server) == [(NODE_A, BASE + 11), (NODE_B, BASE + 12)]


def test_a_v3_user_reaches_the_engine(make_cfg, base_config, v3_table, canaries):
    cfg = make_cfg(snmp={**base_config["snmp"], "v3": v3_table})
    server = FakeServer()
    asyncio.run(engines_for(cfg, server).sync([ident(ROOT, None, "router")]))
    user = server.specs[0].v3
    assert (user.user, user.auth, user.priv) == ("librenms", "SHA-256", "AES-128")
    assert user.auth_key.get_secret_value() == canaries["snmp_auth_key"]
    assert user.priv_key.get_secret_value() == canaries["snmp_priv_key"]


def test_a_busy_port_is_retried_later_and_never_swapped(cfg, caplog):
    caplog.set_level(logging.INFO, logger="aimesh_snmp_proxy.ops.run")
    server, clock = FakeServer(), FakeTime()
    server.busy[BASE + 2] = 2
    engines = engines_for(cfg, server, clock=clock, retry_first_s=5, retry_max_s=8)
    node = [ident(NODE_B, "192.168.50.102")]
    asyncio.run(engines.sync(node))
    asyncio.run(engines.sync(node))  # not due yet
    clock.advance(5)
    asyncio.run(engines.sync(node))  # fails again, waits 8 s (the cap)
    clock.advance(7.9)
    asyncio.run(engines.sync(node))
    clock.advance(0.1)
    asyncio.run(engines.sync(node))
    assert server.attempts == [(NODE_B, BASE + 2)] * 3
    assert served(server) == [(NODE_B, BASE + 2)]
    waits = [r for r in caplog.records if "retrying" in r.getMessage()]
    assert len(waits) == 1
    assert waits[0].levelno == logging.WARNING
    assert "cannot bind 127.0.0.1:16103" in waits[0].getMessage()


def test_a_port_override_pins_a_new_node(make_cfg):
    cfg = make_cfg(override=[{"match": NODE_A, "port": BASE + 50}])
    server = FakeServer()
    asyncio.run(engines_for(cfg, server).sync([ident(NODE_A, "192.168.50.101")]))
    assert served(server) == [(NODE_A, BASE + 50)]


def test_an_override_never_takes_the_port_of_a_served_node(make_cfg, caplog):
    cfg = make_cfg(override=[{"match": NODE_B, "port": BASE + 11}])
    server = FakeServer()
    engines = engines_for(cfg, server)
    asyncio.run(engines.sync([ident(NODE_A, "192.168.50.50")]))
    both = [ident(NODE_A, "192.168.50.50"), ident(NODE_B, "192.168.50.51")]
    asyncio.run(engines.sync(both))
    asyncio.run(engines.sync(both))
    assert served(server) == [(NODE_A, BASE + 11)]
    pinned = PortMap.load(cfg.ports_file, BASE, cfg.nodes.expected).pinned()
    assert pinned == {NODE_A: BASE + 11}
    refused = [r for r in caplog.records if "until restart" in r.getMessage()]
    assert len(refused) == 1
    assert refused[0].levelno == logging.ERROR


def test_pinned_nodes_start_before_the_rest(make_cfg):
    cfg = make_cfg(override=[{"match": NODE_B, "port": BASE + 11}])
    server = FakeServer()
    nodes = [ident(NODE_A, "192.168.50.50"), ident(NODE_B, "192.168.50.51")]
    asyncio.run(engines_for(cfg, server).sync(nodes))
    assert served(server) == [(NODE_B, BASE + 11), (NODE_A, BASE + 12)]


def test_a_second_root_router_is_refused(cfg, caplog):
    server = FakeServer()
    nodes = [
        ident(ROOT, "192.168.50.1", "router"),
        ident(NODE_A, "192.168.50.7", "router"),
    ]
    engines = engines_for(cfg, server)
    asyncio.run(engines.sync(nodes))
    asyncio.run(engines.sync(nodes))
    assert served(server) == [(ROOT, BASE)]
    assert len([r for r in caplog.records if "second root" in r.getMessage()]) == 1


def test_a_renamed_node_keeps_its_engine_name_until_restart(cfg, caplog):
    server = FakeServer()
    engines = engines_for(cfg, server)
    asyncio.run(engines.sync([ident(NODE_A, "192.168.50.101")]))
    renamed = [ident(NODE_A, "192.168.50.101", name="aimesh-hall")]
    asyncio.run(engines.sync(renamed))
    asyncio.run(engines.sync(renamed))
    assert [s.sys_name for s in server.specs] == ["aimesh-005302"]
    notes = [r for r in caplog.records if "aimesh-hall" in r.getMessage()]
    assert len(notes) == 1


def test_a_refused_spec_is_not_retried(cfg):
    server, clock = FakeServer(), FakeTime()
    server.invalid.add(BASE + 1)
    engines = engines_for(cfg, server, clock=clock)
    node = [ident(NODE_A, "192.168.50.101")]
    asyncio.run(engines.sync(node))
    clock.advance(3600)
    asyncio.run(engines.sync(node))
    assert len(server.attempts) == 1


def test_an_unwritable_ports_json_is_retried(cfg, caplog):
    cfg.state_dir.mkdir()
    server, clock = FakeServer(), FakeTime()
    engines = engines_for(cfg, server, clock=clock, retry_first_s=1)
    cfg.state_dir.chmod(0o500)
    try:
        if cfg.state_dir.stat().st_uid == 0:
            pytest.skip("root ignores directory permissions")
        asyncio.run(engines.sync([ident(NODE_A, "192.168.50.101")]))
    finally:
        cfg.state_dir.chmod(0o700)
    assert server.attempts == []
    assert any("cannot write" in r.getMessage() for r in caplog.records)
    clock.advance(1)
    asyncio.run(engines.sync([ident(NODE_A, "192.168.50.101")]))
    assert served(server) == [(NODE_A, BASE + 1)]


# --- serve(): signals and lifecycle ---------------------------------------------------


class FakeStore:
    def __init__(self):
        self.idents = ()
        self.refreshes = 0

    def identities(self):
        return self.idents

    def refresh_states(self):
        self.refreshes += 1
        return {}

    def current(self, node_id):
        return None


class FakeCollector:
    def __init__(self, crash=None, hang_s=0.0):
        self.store = FakeStore()
        self.crash = crash
        self.hang_s = hang_s
        self.started = asyncio.Event()
        self.reloads = []
        self.shutdowns = []

    async def run(self, stop):
        self.started.set()
        if self.crash is not None:
            raise self.crash
        await stop.wait()
        if self.hang_s:
            await asyncio.sleep(self.hang_s)
        await self.shutdown()

    async def reload(self, reason):
        self.reloads.append(reason)

    async def shutdown(self, *, persist=True):
        self.shutdowns.append(persist)


@pytest.fixture
def restore_signals():
    saved = {
        s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
    }
    yield
    for sig, handler in saved.items():
        signal.signal(sig, handler)


async def until(predicate, timeout=10.0):
    async with asyncio.timeout(timeout):
        while not predicate():
            await asyncio.sleep(0.01)


def serve_fake(cfg, collector, server, **kwargs):
    ports = PortMap.load(cfg.ports_file, cfg.snmp.port_base, cfg.nodes.expected)
    kwargs.setdefault("interval", 0.01)
    return serve(cfg, load_secrets(cfg), collector, ports, server=server, **kwargs)


def test_sighup_reloads_and_sigterm_stops_cleanly(cfg, restore_signals):
    async def scenario():
        collector, server = FakeCollector(), FakeServer()
        task = asyncio.create_task(serve_fake(cfg, collector, server))
        await asyncio.wait_for(collector.started.wait(), 5)
        signal.raise_signal(signal.SIGHUP)
        await until(lambda: collector.reloads)
        signal.raise_signal(signal.SIGTERM)
        return await asyncio.wait_for(task, 5), collector, server

    code, collector, server = asyncio.run(scenario())
    assert code == 0
    assert collector.reloads == ["SIGHUP"]
    assert collector.shutdowns == [True, False]  # the run's own, then stragglers
    assert server.closed
    assert signal.getsignal(signal.SIGTERM) is signal.SIG_DFL
    assert signal.getsignal(signal.SIGHUP) is signal.SIG_DFL
    assert signal.getsignal(signal.SIGINT) is signal.default_int_handler


def test_sigint_stops_cleanly(cfg, restore_signals):
    async def scenario():
        collector, server = FakeCollector(), FakeServer()
        task = asyncio.create_task(serve_fake(cfg, collector, server))
        await asyncio.wait_for(collector.started.wait(), 5)
        signal.raise_signal(signal.SIGINT)
        return await asyncio.wait_for(task, 5)

    assert asyncio.run(scenario()) == 0


def test_engines_follow_the_identities_the_store_reports(cfg, restore_signals):
    async def scenario():
        collector, server = FakeCollector(), FakeServer()
        task = asyncio.create_task(serve_fake(cfg, collector, server))
        await asyncio.wait_for(collector.started.wait(), 5)
        collector.store.idents = (ident(ROOT, "192.168.50.1", "router"),)
        await until(lambda: server.specs)
        collector.store.idents += (ident(NODE_A, "192.168.50.101"),)
        await until(lambda: len(server.specs) == 2)
        signal.raise_signal(signal.SIGTERM)
        await asyncio.wait_for(task, 5)
        return collector, server

    collector, server = asyncio.run(scenario())
    assert served(server) == [(ROOT, BASE), (NODE_A, BASE + 1)]
    assert collector.store.refreshes >= 2


def test_a_collector_crash_stops_with_exit_1(cfg, restore_signals, caplog):
    async def scenario():
        collector, server = FakeCollector(crash=RuntimeError("boom")), FakeServer()
        code = await asyncio.wait_for(serve_fake(cfg, collector, server), 5)
        return code, server

    code, server = asyncio.run(scenario())
    assert code == 1
    assert server.closed
    assert any("collector" in r.getMessage() for r in caplog.records)


def test_an_engine_sync_crash_stops_the_collector(cfg, restore_signals):
    async def scenario():
        collector, server = FakeCollector(), FakeServer()
        server.broken = RuntimeError("bug")
        collector.store.idents = (ident(ROOT, "192.168.50.1", "router"),)
        code = await asyncio.wait_for(serve_fake(cfg, collector, server), 5)
        return code, collector

    code, collector = asyncio.run(scenario())
    assert code == 1
    assert collector.shutdowns[0] is True


def test_a_collector_that_will_not_stop_is_cancelled(cfg, restore_signals, caplog):
    async def scenario():
        collector, server = FakeCollector(hang_s=30), FakeServer()
        task = asyncio.create_task(serve_fake(cfg, collector, server, grace_s=0.1))
        await asyncio.wait_for(collector.started.wait(), 5)
        signal.raise_signal(signal.SIGTERM)
        return await asyncio.wait_for(task, 5), collector

    code, collector = asyncio.run(scenario())
    assert code == 0
    assert collector.shutdowns == [False]
    assert any("cancelling" in r.getMessage() for r in caplog.records)


# --- cli_run -----------------------------------------------------------------------


@pytest.fixture
def unprivileged(monkeypatch):
    calls = []
    monkeypatch.setattr(run_mod, "assert_unprivileged_user", lambda: calls.append(1))
    return calls


def test_cli_run_hands_its_parts_to_serve(cfg, unprivileged, monkeypatch, canaries):
    seen = {}

    async def fake_serve(cfg_, secrets, collector, ports, **kwargs):
        seen.update(cfg=cfg_, secrets=secrets, collector=collector, ports=ports)
        return 0

    monkeypatch.setattr(run_mod, "serve", fake_serve)
    assert cli_run(cfg, []) == 0
    assert unprivileged == [1]
    assert seen["cfg"] is cfg
    assert isinstance(seen["collector"], Collector)
    assert isinstance(seen["ports"], PortMap)
    assert seen["secrets"].asus_password.get_secret_value() == canaries["asus_password"]


def test_cli_run_refuses_a_privileged_user(cfg, monkeypatch, caplog):
    def refuse():
        raise ConfigError("run: refusing to run as root (uid 0)")

    monkeypatch.setattr(run_mod, "assert_unprivileged_user", refuse)
    assert cli_run(cfg, []) == run_mod.EXIT_CONFIG
    assert any("uid 0" in r.getMessage() for r in caplog.records)


def test_cli_run_reports_config_errors_with_exit_78(cfg, unprivileged, caplog):
    cfg.asus.password_file.chmod(0o644)
    assert cli_run(cfg, []) == run_mod.EXIT_CONFIG
    assert any("asus.password_file" in r.getMessage() for r in caplog.records)


def test_cli_run_refuses_a_corrupt_ports_json(cfg, unprivileged, caplog):
    cfg.state_dir.mkdir()
    cfg.ports_file.write_text("{")
    assert cli_run(cfg, []) == run_mod.EXIT_CONFIG
    assert any("ports.json" in r.getMessage() for r in caplog.records)


def test_cli_run_takes_no_options(cfg, unprivileged):
    with pytest.raises(SystemExit) as caught:
        cli_run(cfg, ["--bogus"])
    assert caught.value.code == 2


# --- the real thing: mock router, loopback engines, NET-SNMP --------------------

SYS_NAME = ".1.3.6.1.2.1.1.5.0"


async def expected_names(collector):
    """sysNames in port order (root, .101, .102), as the collector names them."""
    await until(lambda: len(collector.store.identities()) == 3)
    by_ip = {i.ip: i.sys_name for i in collector.store.identities()}
    return [by_ip["192.168.50.1"], by_ip["192.168.50.101"], by_ip["192.168.50.102"]]


@pytest.fixture
def live_cfg(make_cfg, base_config, port_block):
    """A config pointing at a mock router, with a fast cadence and free ports."""

    def _make(router):
        return make_cfg(
            asus={**base_config["asus"], "host": "127.0.0.1", "port": router.port},
            nodes={"expected": "192.168.50.101-102"},
            snmp={**base_config["snmp"], "port_base": port_block(3)},
            collector={
                "metrics_interval_s": 0.2,
                "topology_interval_s": 0.5,
                "stale_after_s": 2.0,
                "request_timeout_s": 5,
            },
        )

    return _make


def live_parts(cfg):
    secrets = load_secrets(cfg)
    pin = load_router_pin(cfg.asus.ca_file)
    ports = PortMap.load(cfg.ports_file, cfg.snmp.port_base, cfg.nodes.expected)
    return secrets, Collector.from_config(cfg, secrets, pin, kdf_n=2), ports


def handled_sighup(caplog):
    return any(r.getMessage().startswith("SIGHUP:") for r in caplog.records)


async def names_on(snmp_get, base, community, count=3):
    return [await snmp_get(base + i, community, SYS_NAME) for i in range(count)]


def test_run_serves_every_node_and_stops_on_sigterm(
    mock_router, live_cfg, snmp_get, canaries, restore_signals, caplog
):
    caplog.set_level(logging.INFO)
    community = canaries["snmp_community"]

    async def scenario():
        async with mock_router() as router:
            cfg = live_cfg(router)
            secrets, collector, ports = live_parts(cfg)
            task = asyncio.create_task(
                serve(cfg, secrets, collector, ports, interval=0.05)
            )
            base = cfg.snmp.port_base
            names = await expected_names(collector)
            async with asyncio.timeout(15):
                while await names_on(snmp_get, base, community) != names:
                    await asyncio.sleep(0.1)
            logins = len(router.logins())
            signal.raise_signal(signal.SIGHUP)
            await until(lambda: handled_sighup(caplog))
            async with asyncio.timeout(15):  # still serving after the reload
                while await names_on(snmp_get, base, community) != names:
                    await asyncio.sleep(0.1)
            signal.raise_signal(signal.SIGTERM)
            code = await asyncio.wait_for(task, 15)
            after = await names_on(snmp_get, base, community, count=1)
            return code, router, cfg, after, len(router.logins()) - logins

    code, router, cfg, after, extra_logins = asyncio.run(scenario())
    assert code == 0
    assert after == [None]  # every socket closed
    assert extra_logins == 0  # a SIGHUP with nothing to renew keeps the session
    assert router.tokens == set()  # every login was logged out
    assert router.paths()[-1] == "/Logout.asp"
    assert cfg.counters_file.exists()
    base = cfg.snmp.port_base
    pinned = PortMap.load(cfg.ports_file, base, ()).pinned()
    assert pinned == {NODE_A: base + 1, NODE_B: base + 2}
    messages = [r.getMessage() for r in caplog.records]
    assert sum("engine on 127.0.0.1" in m for m in messages) == 3
    for value in canaries.values():
        assert all(value not in m for m in messages)


def test_run_retries_a_busy_port_until_it_frees(
    mock_router, live_cfg, snmp_get, canaries, restore_signals, caplog, monkeypatch
):
    caplog.set_level(logging.INFO)
    monkeypatch.setattr(run_mod, "RETRY_FIRST_S", 0.2)
    community = canaries["snmp_community"]

    def retrying():
        return [r for r in caplog.records if "retrying" in r.getMessage()]

    async def scenario():
        async with mock_router() as router:
            cfg = live_cfg(router)
            base = cfg.snmp.port_base
            squatter = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            squatter.bind(("127.0.0.1", base + 1))
            secrets, collector, ports = live_parts(cfg)
            task = asyncio.create_task(
                serve(cfg, secrets, collector, ports, interval=0.05)
            )
            try:
                await until(retrying)
            finally:
                squatter.close()
            names = await expected_names(collector)
            async with asyncio.timeout(15):
                while await names_on(snmp_get, base, community) != names:
                    await asyncio.sleep(0.1)
            signal.raise_signal(signal.SIGTERM)
            return await asyncio.wait_for(task, 15)

    assert asyncio.run(scenario()) == 0
    assert len(retrying()) == 1


def test_signals_during_shutdown_are_absorbed(cfg, restore_signals):
    async def scenario():
        collector, server = FakeCollector(hang_s=0.3), FakeServer()
        task = asyncio.create_task(serve_fake(cfg, collector, server))
        await asyncio.wait_for(collector.started.wait(), 5)
        signal.raise_signal(signal.SIGTERM)
        await asyncio.sleep(0.1)  # the collector is still shutting down
        signal.raise_signal(signal.SIGHUP)
        signal.raise_signal(signal.SIGTERM)
        return await asyncio.wait_for(task, 5), collector

    code, collector = asyncio.run(scenario())
    assert code == 0
    assert collector.reloads == []


def test_a_failing_final_close_is_only_logged(cfg, restore_signals, caplog):
    class BrokenClose(FakeCollector):
        async def shutdown(self, *, persist=True):
            await super().shutdown(persist=persist)
            if not persist:
                raise RuntimeError("aiohttp")

    async def scenario():
        collector, server = BrokenClose(), FakeServer()
        task = asyncio.create_task(serve_fake(cfg, collector, server))
        await asyncio.wait_for(collector.started.wait(), 5)
        signal.raise_signal(signal.SIGTERM)
        return await asyncio.wait_for(task, 5), server

    code, server = asyncio.run(scenario())
    assert code == 0
    assert server.closed
    assert any(
        "closing router sessions failed" in r.getMessage() for r in caplog.records
    )
