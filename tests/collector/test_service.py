import asyncio
import json
import logging
import os
from dataclasses import replace
from types import SimpleNamespace

import pytest
from asusrouter.error import AsusRouterAccessError
from asusrouter.modules.endpoint.error import ARAccessError

from aimesh_snmp_proxy.collector.backoff import (
    PROBE_INTERVAL_S,
    Gate,
    Latch,
    Outcome,
    SystemClock,
)
from aimesh_snmp_proxy.collector.mapping import ByteDelta, MeshNode
from aimesh_snmp_proxy.collector.service import (
    Collector,
    CollectorSettings,
    OverrideRule,
    Overrides,
)
from aimesh_snmp_proxy.collector.session import RequestBlockedError, Target
from aimesh_snmp_proxy.config import (
    COUNTERS_FILE,
    LOCKOUT_FILE,
    ConfigError,
    load_config,
    load_node_ca,
    load_node_pin,
    load_secrets,
)
from aimesh_snmp_proxy.logsafe import SecretStr
from aimesh_snmp_proxy.profiles import PROFILES

ROOT = "00:00:5e:00:53:01"
NODE = "00:00:5e:00:53:02"
WIRED = "00:00:5e:00:53:03"
PASSWORD = "canary-router-Pa55-1"
PASSWORD_CANARY = PASSWORD  # make_config writes the same canary


@pytest.fixture
def password_file(tmp_path):
    path = tmp_path / "asus_password"
    path.write_text(PASSWORD + "\n")
    path.chmod(0o600)
    return path


@pytest.fixture
def make_collector(tmp_path, clock, pin, password_file):
    def _make(router, **kwargs):
        target = Target(
            "root",
            router.host,
            router.port,
            "admin",
            SecretStr(kwargs.pop("password", PASSWORD)),
            kwargs.pop("pin", pin),
        )
        return Collector(
            target,
            tmp_path / "state",
            settings=kwargs.pop("settings", CollectorSettings(request_timeout_s=5)),
            password_file=password_file,
            clock=kwargs.pop("clock", clock),
            kdf_n=2,
            **kwargs,
        )

    return _make


def run(coro):
    return asyncio.run(coro)


async def polled(collector, times=1):
    for _ in range(times):
        await collector.poll_once()
    return collector


# --- one full cycle ---------------------------------------------------------------


def test_poll_once_serves_every_node_with_one_login(mock_router, make_collector):
    async def scenario():
        async with mock_router() as router:
            collector = await polled(make_collector(router))
            await collector.shutdown()
            return router, collector

    router, collector = run(scenario())
    store = collector.store
    assert store.serving() == (ROOT, NODE, WIRED)
    assert len(router.logins()) == 1
    root = store.current(ROOT)
    assert root.sys_name == "aimesh-root"
    assert (root.cpu_pct, root.mem_pct) == (5, 26)
    assert root.uptime_s == 4162
    assert root.mem_total_b == 1048576 * 1024
    assert [r.freq_mhz for r in root.radios] == [2437, 5500, 5975]
    assert root.radio(1).clients == 3
    assert root.link("wired").rx_bps == 5_000_000
    node = store.current(NODE)
    assert node.backhaul.link_bps == 1_729_000_000
    assert node.uptime_s is None  # root_only: nodes report no detail
    assert store.current(WIRED).backhaul.medium == "wired"


def test_shutdown_logs_out_and_persists_counters(mock_router, make_collector, tmp_path):
    async def scenario():
        async with mock_router() as router:
            collector = await polled(make_collector(router))
            await collector.shutdown()
            return router

    router = run(scenario())
    assert router.paths()[-1] == "/Logout.asp"
    doc = json.loads((tmp_path / "state" / COUNTERS_FILE).read_text())
    assert set(doc["counters"]) == {ROOT, NODE, WIRED}
    assert (tmp_path / "state" / LOCKOUT_FILE).exists()  # the paths config reports


def test_metrics_jobs_are_spread_by_node_offset(mock_router, make_collector):
    async def scenario():
        async with mock_router() as router:
            collector = make_collector(router)
            await collector.topology()
            await collector.shutdown()
            return collector

    collector = run(scenario())
    jobs = collector.scheduler
    names = [n for n in jobs.names() if n.startswith("metrics:")]
    assert names == [f"metrics:{m}" for m in (ROOT, NODE, WIRED)]
    start = min(jobs.job(n).due for n in names)
    assert [jobs.job(n).due - start for n in names] == [0, 20, 40]


def test_empty_aimesh_list_keeps_the_previous_one(mock_router, make_collector, mesh3):
    async def scenario():
        async with mock_router(mesh3) as router:
            collector = await polled(make_collector(router))
            mesh3["pages"]["ajax_onboarding.asp"]["get_cfg_clientlist"] = [[]]
            await collector.topology()
            await collector.shutdown()
            return collector

    assert run(scenario()).store.serving() == (ROOT, NODE, WIRED)


# --- standalone routers: AP or media bridge, an empty AiMesh list ---------------------

BRIDGE = "02:00:00:00:00:01"  # every capture aliases the logged-in device to this MAC


@pytest.mark.parametrize(
    ("fixture", "model", "uptime"),
    [("bridge-ac", "RT-AC88U", None), ("bridge-ax", "RT-AX58U", 54321)],
)
def test_a_standalone_router_is_served_as_one_root_node(
    mock_router, make_collector, capture, fixture, model, uptime
):
    async def scenario():
        async with mock_router(capture(fixture)) as router:
            collector = await polled(make_collector(router))
            await collector.shutdown()
            return collector

    collector = run(scenario())
    assert collector.store.serving() == (BRIDGE,)
    snap = collector.store.current(BRIDGE)
    assert (snap.role, snap.level, snap.model) == ("router", 0, model)
    assert snap.sys_name == "aimesh-root"
    assert snap.firmware.startswith("3.0.0.4.")
    assert [(r.unit, r.band, r.state) for r in snap.radios] == [
        (0, "2g1", True),
        (1, "5g1", True),
    ]
    assert [r.freq_mhz for r in snap.radios] == [2437, 5180]  # channels 6 and 36
    assert [(t.sensor, round(t.celsius)) for t in snap.temps_c] == [
        ("cpu", {"RT-AC88U": 58, "RT-AX58U": 52}[model])
    ]
    assert snap.uptime_s == uptime  # the 386 firmware reports none
    assert snap.mem_total_b == 524288 * 1024
    assert [r.clients for r in snap.radios] == [0, 0]  # a media bridge serves no Wi-Fi


def netdev_js(**ifaces):
    """``update.cgi?output=netdev``: the byte counters the router's UI graphs."""
    rows = "\n,".join(
        f"'{name}':{{rx:{rx:#x},tx:{tx:#x}}}" for name, (rx, tx) in ifaces.items()
    )
    return f"netdev = {{\n {rows}\n}};"


@pytest.mark.parametrize("fixture", ["bridge-ac", "bridge-ax"])
def test_a_standalone_router_serves_radio_and_wired_traffic_from_its_counters(
    mock_router, make_collector, capture, clock, fixture
):
    # No AiMesh list, so no AiMesh traffic: one minute apart, these counters grow by
    # 7.5 MB in and 0.75 MB out on wl0, 15 MB out on wl1, 1.5 MB each way wired.
    base = {"WIRELESS0": (10**9, 2 * 10**9), "WIRELESS1": (5 * 10**9, 10**9)}
    base |= {"WIRED": (7 * 10**8, 3 * 10**8), "BRIDGE": (1, 1)}
    step = {"WIRELESS0": (7_500_000, 750_000), "WIRELESS1": (0, 15_000_000)}
    step |= {"WIRED": (1_500_000, 1_500_000), "BRIDGE": (0, 0)}

    async def scenario():
        async with mock_router(capture(fixture)) as router:
            collector = make_collector(router)
            for n in range(3):
                if n:
                    clock.advance(60)
                router.raw_replies["update.cgi"] = netdev_js(
                    **{
                        k: (rx + n * step[k][0], tx + n * step[k][1])
                        for k, (rx, tx) in base.items()
                    }
                )
                await collector.poll_once()
            await collector.shutdown()
            return router, collector

    router, collector = run(scenario())
    snap = collector.store.current(BRIDGE)
    # Served from the first sample on; each later minute adds its own bytes.
    assert [(link.name, link.in_octets, link.out_octets) for link in snap.links] == [
        ("wired", 3_000_000, 3_000_000),
        ("wl0", 15_000_000, 1_500_000),
        ("wl1", 0, 30_000_000),
    ]
    reads = [s.query for s in router.seen if s.path == "/update.cgi"]
    assert reads == [{"output": "netdev"}] * 3
    assert "/get_diag_eth_traffic.cgi" not in router.paths()  # AiMesh-only data
    rows = dict(PROFILES["asuswrt-merlin"].render(snap))
    in_octets, out_octets, alias = (
        (1, 3, 6, 1, 2, 1, 31, 1, 1, 1, c) for c in (6, 10, 18)
    )
    assert int(rows[(*in_octets, 10)]) == 15_000_000  # ifHCInOctets.wl0
    assert int(rows[(*out_octets, 11)]) == 30_000_000  # ifHCOutOctets.wl1
    assert bytes(rows[(*alias, 10)]) == b"wl-2.4G (derived)"


def served_wl0(mock_router, make_collector, capture, clock, samples):
    """Poll once per (rx, tx) wl0 counter sample, a minute apart; served octets."""

    async def scenario():
        async with mock_router(capture("bridge-ax")) as router:
            collector = make_collector(router)
            served = []
            for n, counters in enumerate(samples):
                if n:
                    clock.advance(60)
                router.raw_replies["update.cgi"] = netdev_js(
                    WIRELESS0=counters, WIRELESS1=(0, 0), WIRED=(0, 0)
                )
                await collector.poll_once()
                link = collector.store.current(BRIDGE).link("wl0")
                served.append((link.in_octets, link.out_octets))
            await collector.shutdown()
            return served

    return run(scenario())


def test_a_router_reboot_holds_the_served_counters_for_one_sample(
    mock_router, make_collector, capture, clock
):
    # The reboot restarts the router's counters near 0: that minute adds nothing,
    # and the next one adds only its own bytes (no negative rate, no spike).
    rx, tx = 5 * 10**9, 6 * 10**9
    samples = [
        (rx, tx),
        (rx + 7_500_000, tx + 750_000),
        (1_000, 2_000),
        (1_000 + 15_000_000, 2_000 + 1_500_000),
    ]
    assert served_wl0(mock_router, make_collector, capture, clock, samples) == [
        (0, 0),
        (7_500_000, 750_000),
        (7_500_000, 750_000),
        (22_500_000, 2_250_000),
    ]


def test_a_32_bit_counter_wrap_holds_the_served_counters_for_one_sample(
    mock_router, make_collector, capture, clock
):
    # Old firmware wraps at 2**32: the wrapped minute is skipped, never guessed.
    top = 2**32
    samples = [(top - 3_000_000, 10), (top - 1_000_000, 10), (1_000_000, 10)]
    samples.append((4_000_000, 10))
    assert served_wl0(mock_router, make_collector, capture, clock, samples) == [
        (0, 0),
        (2_000_000, 0),
        (2_000_000, 0),
        (5_000_000, 0),
    ]


# Firmware without get_port_status.cgi (some 386 and 388 builds): the library falls
# back to ajax_ethernet_ports.asp, whose portSpeed maps each port to one speed code.
PORTS_PAGE = (
    'get_wan_lan_status = {"portSpeed": {"WAN 0": "G", "LAN 1": "M", "LAN 2": "X",'
    ' "LAN 3": "X", "LAN 4": "G"}, "portCount": {"wanCount": 1, "lanCount": 4}};'
)


def with_ports_page(router, page):
    router.raw_replies["get_port_status.cgi"] = "{}"  # answered, but empty
    router.raw_replies["ajax_ethernet_ports.asp"] = page


@pytest.mark.parametrize("fixture", ["bridge-ac", "bridge-ax"])
def test_a_standalone_router_serves_its_ethernet_ports_from_the_ports_page(
    mock_router, make_collector, capture, fixture
):
    async def scenario():
        async with mock_router(capture(fixture)) as router:
            with_ports_page(router, PORTS_PAGE)
            collector = await polled(make_collector(router))
            await collector.shutdown()
            return router, collector

    router, collector = run(scenario())
    snap = collector.store.current(BRIDGE)
    assert [(p.name, p.up, p.speed_mbps) for p in snap.ports] == [
        ("WAN", True, 1000),
        ("LAN1", True, 100),
        ("LAN2", False, 0),
        ("LAN3", False, 0),
        ("LAN4", True, 1000),
    ]
    (page,) = [s for s in router.seen if s.path == "/ajax_ethernet_ports.asp"]
    assert (page.method, page.query, page.body) == ("POST", {}, "")
    rows = dict(PROFILES["asuswrt-merlin"].render(snap))
    if_entry = (1, 3, 6, 1, 2, 1, 2, 2, 1)
    assert bytes(rows[(*if_entry, 2, 100)]) == b"WAN"
    assert [int(rows[(*if_entry, 8, i)]) for i in (100, 111, 112)] == [1, 1, 2]
    assert int(rows[(*if_entry, 5, 100)]) == 10**9
    # Link state and speed only: no octet counter on any Ethernet row, never a 0.
    assert not [oid for oid in rows if oid[:10] == (*if_entry, 10) and oid[10] >= 100]


@pytest.mark.parametrize(
    "page",
    [
        "get_wan_lan_status = not json;",
        '{"portSpeed": ["G", "X"]}',
        '{"portSpeed": {"WAN 0": {"code": "G"}}}',
        '{"portCount": {"wanCount": 1}}',
    ],
    ids=["not-json", "list", "nested", "no-portSpeed"],
)
def test_an_unusable_ports_page_omits_the_rows_with_one_warning(
    mock_router, make_collector, capture, clock, caplog, page
):
    async def scenario():
        async with mock_router(capture("bridge-ax")) as router:
            with_ports_page(router, PORTS_PAGE)
            collector = make_collector(router)
            await collector.poll_once()
            served = collector.store.current(BRIDGE).ports
            router.raw_replies["ajax_ethernet_ports.asp"] = page
            clock.advance(60)
            with caplog.at_level(logging.WARNING):
                await collector.poll_once()
                clock.advance(60)
                await collector.poll_once()
            await collector.shutdown()
            return served, collector

    served, collector = run(scenario())
    assert len(served) == 5
    snap = collector.store.current(BRIDGE)
    assert snap.ports == ()  # dropped at once, not left to go stale
    assert snap.radios  # the collector still serves the device
    assert caplog.text.count("no Ethernet port status") == 1
    assert collector.root.guard.last_failure is None


def test_a_standalone_device_counts_only_its_own_wireless_clients(
    mock_router, make_collector, capture
):
    data = capture("node-triband")  # an AiMesh node, logged in directly
    listed = data["appget"]["get_clientlist"].values()
    local = [c for c in listed if c["isOnline"] == "1" and c["isWL"] != "0"]

    async def scenario():
        async with mock_router(data) as router:
            collector = await polled(make_collector(router))
            await collector.shutdown()
            return collector

    snap = run(scenario()).store.current(BRIDGE)
    assert (len(listed), len(local)) == (31, 5)  # the list is network-wide
    assert [(r.unit, r.band) for r in snap.radios] == [
        (0, "2g1"),
        (1, "5g1"),
        (2, "6g1"),
    ]
    assert sum(r.clients for r in snap.radios) == len(local)
    assert (snap.uptime_s, round(snap.temps_c[0].celsius)) == (43210, 63)


def test_a_standalone_router_tolerates_unparsable_replies(
    mock_router, make_collector, capture
):
    async def scenario():
        async with mock_router(capture("bridge-ac")) as router:
            router.raw_replies["ajax_coretmp.asp"] = "<html>not available</html>"
            router.raw_replies["get_diag_content_data.cgi"] = "not json"
            collector = await polled(make_collector(router))
            await collector.shutdown()
            return collector

    collector = run(scenario())
    assert collector.store.serving() == (BRIDGE,)
    assert collector.store.current(BRIDGE).temps_c is None


def test_an_aimesh_list_replaces_the_standalone_node(
    mock_router, make_collector, mesh3
):
    onboarding = mesh3["pages"]["ajax_onboarding.asp"]
    full, onboarding["get_cfg_clientlist"] = onboarding["get_cfg_clientlist"], [[]]

    async def scenario():
        async with mock_router(mesh3) as router:
            collector = await polled(make_collector(router))
            alone = collector.store.serving()
            onboarding["get_cfg_clientlist"] = full
            await polled(collector)
            await collector.shutdown()
            return alone, collector

    alone, collector = run(scenario())
    assert alone == (ROOT,)  # the logged-in root, from its identity
    assert collector.store.serving() == (ROOT, NODE, WIRED)


def test_stale_clients_report_zero_clients(mock_router, make_collector, clock):
    async def scenario():
        async with mock_router() as router:
            collector = make_collector(router)
            await collector.topology()
            await collector.clients()
            clock.advance(collector.settings.stale_after_s + 1)
            await collector.metrics(ROOT)
            await collector.shutdown()
            return collector

    assert run(scenario()).store.current(ROOT).radio(1).clients == 0


# --- overrides ----------------------------------------------------------------------


def test_overrides_rename_locate_and_exclude(mock_router, make_collector):
    rules = Overrides(
        [
            OverrideRule("192.168.50.101", sys_name="aimesh-hall", location="Office"),
            OverrideRule(WIRED, exclude=True),
        ]
    )

    async def scenario():
        async with mock_router() as router:
            collector = await polled(make_collector(router, overrides=rules))
            await collector.shutdown()
            return collector

    store = run(scenario()).store
    assert [i.node_id for i in store.identities()] == [ROOT, NODE]
    assert store.current(NODE).sys_name == "aimesh-hall"
    assert store.current(NODE).location == "Office"


def test_overrides_from_config_read_v02_overrides():
    cfg = SimpleNamespace(
        overrides=(
            SimpleNamespace(match="192.168.50.101", sys_name="a", login=False),
            SimpleNamespace(match="00-00-5E-00-53-03", exclude=True),
            SimpleNamespace(match="not-an-address"),
        ),
    )
    rules = Overrides.from_config(cfg)
    assert rules.find(NODE, "192.168.50.101") == OverrideRule(
        "192.168.50.101", sys_name="a", login=False
    )
    assert rules.find(WIRED, None).exclude
    assert rules.find("00:00:5e:00:53:09", "192.168.50.9") is None


def test_generated_sys_names_that_clash_fall_back_to_the_full_mac():
    a, b = "00:00:5e:00:53:01", "02:00:5e:00:53:01"
    rules = Overrides([OverrideRule(NODE, sys_name="aimesh-005303")])
    names = rules.sys_names([(a, None), (b, None), (NODE, None), (WIRED, None)])
    assert names == {
        a: "aimesh-00005e005301",
        b: "aimesh-02005e005301",
        NODE: "aimesh-005303",
        WIRED: "aimesh-00005e005303",
    }


def test_topology_hands_the_root_mac_to_the_namer(mock_router, make_collector):
    calls = []

    def namer(pairs, *, root_mac=None):
        pairs = list(pairs)
        calls.append(root_mac)
        return {mac: f"n-{mac[-2:]}" for mac, _ in pairs}

    async def scenario():
        async with mock_router() as router:
            collector = make_collector(router, namer=namer)
            await collector.topology()
            await collector.shutdown()
            return collector

    collector = run(scenario())
    assert calls == [ROOT]
    assert collector.names[NODE] == "n-02"


PARITY_PAIRS = [
    (ROOT, "192.168.50.1"),
    (NODE, "192.168.50.101"),
    (WIRED, "192.168.50.102"),
    ("02:00:5e:00:53:02", None),  # same last 6 hex as NODE once NODE is renamed
    ("00:00:5e:00:53:09", "192.168.50.109"),
    ("02:00:5e:00:53:09", None),  # clashes with the one above
]


@pytest.mark.parametrize("root_mac", [None, ROOT, "00:00:5e:00:53:09"])
@pytest.mark.parametrize("host", ["192.168.50.1", "router.lan"])
def test_fallback_namer_matches_config_sys_names(
    make_config, base_config, root_mac, host
):
    from aimesh_snmp_proxy.config import load_config

    base_config["asus"]["host"] = host
    base_config["override"] = [
        {"match": "192.168.50.101", "sys_name": "aimesh-hall"},
        {"match": WIRED, "exclude": True},
    ]
    cfg = load_config(make_config(base_config), env={})
    mine = Overrides.from_config(cfg).sys_names(PARITY_PAIRS, root_mac=root_mac)
    assert mine == cfg.sys_names(PARITY_PAIRS, root_mac=root_mac)


def test_override_name_beats_the_root_name():
    rules = Overrides([OverrideRule(ROOT, sys_name="core")])
    assert rules.sys_names([(ROOT, None)], root_mac=ROOT) == {ROOT: "core"}


def test_mac_rule_beats_ip_rule():
    rules = Overrides(
        [
            OverrideRule("192.168.50.101", sys_name="ip"),
            OverrideRule(NODE, sys_name="mac"),
        ]
    )
    assert rules.find(NODE, "192.168.50.101").sys_name == "mac"


def test_from_config_builds_targets_and_settings(tmp_path, pin):
    cfg = SimpleNamespace(
        asus=SimpleNamespace(
            host="192.168.50.1",
            port=None,
            username="admin",
            password_file=tmp_path / "pw",
        ),
        collector=SimpleNamespace(
            mode="per_node",
            stale_after_s=180.0,
            metrics_interval_s=60.0,
            topology_interval_s=300.0,
            request_timeout_s=10.0,
        ),
        state_dir=tmp_path / "state",
    )
    secrets = SimpleNamespace(asus_password=SecretStr(PASSWORD))
    collector = Collector.from_config(cfg, secrets, pin, kdf_n=2)
    assert collector.root.target.port == 8443
    assert collector.settings.mode == "per_node"
    assert PASSWORD not in repr(collector.root.target)


# --- protection paths -------------------------------------------------------------


def test_refused_credentials_latch_and_the_next_poll_sends_no_login(
    mock_router, make_collector
):
    async def scenario():
        async with mock_router() as router:
            collector = await polled(make_collector(router, password="wrong"), times=2)
            await collector.shutdown()
            return router, collector

    router, collector = run(scenario())
    assert len(router.logins()) == 1
    assert collector.root.guard.latch is Latch.CREDENTIALS
    assert collector.store.serving() == ()


def test_password_file_change_clears_the_latch_and_logs_in_again(
    mock_router, make_collector, password_file
):
    async def scenario():
        async with mock_router() as router:
            router.password = "new-password-77"
            collector = await polled(make_collector(router))
            password_file.write_text("new-password-77\n")
            os.utime(password_file, (1, 1))
            await collector.housekeeping()
            await collector.poll_once()
            await collector.shutdown()
            return router, collector

    router, collector = run(scenario())
    assert len(router.logins()) == 2
    assert collector.root.guard.gate() is Gate.OPEN
    assert collector.store.serving() == (ROOT, NODE, WIRED)


def test_token_loss_relogs_in_on_the_next_poll(mock_router, make_collector):
    async def scenario():
        async with mock_router() as router:
            collector = await polled(make_collector(router))
            router.expire_tokens()
            await collector.poll_once()
            await collector.shutdown()
            return router, collector

    router, collector = run(scenario())
    assert len(router.logins()) == 2
    assert collector.store.serving() == (ROOT, NODE, WIRED)


def test_wrong_certificate_logs_both_fingerprints_and_sends_nothing(
    mock_router, make_collector, rogue_cert, router_cert, caplog
):
    async def scenario():
        async with mock_router(cert=rogue_cert) as router:
            collector = make_collector(router)
            with caplog.at_level(logging.ERROR):
                await collector.topology()
            await collector.shutdown()
            return router, collector

    router, collector = run(scenario())
    assert router.seen == []
    assert rogue_cert.fingerprint in caplog.text
    assert router_cert.fingerprint in caplog.text
    assert collector.root.guard.gate() is Gate.BLOCKED


def test_try_again_blocks_further_requests(mock_router, make_collector):
    async def scenario():
        async with mock_router() as router:
            router.login_error = 7
            collector = await polled(make_collector(router), times=2)
            await collector.shutdown()
            return router, collector

    router, collector = run(scenario())
    assert len(router.logins()) == 1
    assert collector.root.guard.gate() is Gate.BLOCKED


def test_captcha_latch_probes_hourly_without_credentials(
    mock_router, make_collector, clock, caplog
):
    async def scenario():
        async with mock_router() as router:
            router.login_error = 10
            collector = await polled(make_collector(router))
            seen = len(router.seen)
            clock.advance(PROBE_INTERVAL_S)
            with caplog.at_level(logging.WARNING):
                await collector.topology()
            probe_seen = len(router.seen) - seen
            await collector.shutdown()
            return router, collector, probe_seen

    router, collector, probe_seen = run(scenario())
    assert len(router.logins()) == 1
    assert probe_seen == 0  # TLS handshake only
    assert "still latched" in caplog.text
    assert collector.root.guard.gate() is Gate.LATCHED


def test_sighup_clears_latches(mock_router, make_collector):
    async def scenario():
        async with mock_router() as router:
            router.login_error = 10
            collector = await polled(make_collector(router))
            router.login_error = None
            await collector.reload("SIGHUP")
            await collector.poll_once()
            await collector.shutdown()
            return router, collector

    router, collector = run(scenario())
    assert len(router.logins()) == 2
    assert collector.store.serving() == (ROOT, NODE, WIRED)


def test_bad_password_file_on_reload_keeps_the_old_password(
    mock_router, make_collector, password_file, caplog
):
    async def scenario():
        async with mock_router() as router:
            collector = await polled(make_collector(router))
            password_file.chmod(0o644)
            with caplog.at_level(logging.ERROR):
                await collector.reload("SIGHUP")
            await collector.poll_once()
            await collector.shutdown()
            return collector

    collector = run(scenario())
    assert "asus.password_file" in caplog.text
    assert collector.store.serving() == (ROOT, NODE, WIRED)


# --- per_node -----------------------------------------------------------------------


def per_node(**overrides):
    return CollectorSettings(mode="per_node", request_timeout_s=5, **overrides)


def test_per_node_skips_nodes_without_a_pinned_certificate(
    mock_router, make_collector, caplog
):
    async def scenario():
        async with mock_router() as router:
            collector = make_collector(router, settings=per_node())
            with caplog.at_level(logging.WARNING):
                await polled(collector, times=2)
            await collector.shutdown()
            return collector

    collector = run(scenario())
    assert caplog.text.count("no pinned certificate") == 2  # once per node
    assert collector.store.current(NODE).uptime_s is None


def test_per_node_session_adds_node_detail(mock_router, make_collector, pin):
    async def scenario():
        async with mock_router() as root_router, mock_router() as node_router:

            def node_target(node):
                return Target(
                    f"node:{node.mac}",
                    node_router.host,
                    node_router.port,
                    "admin",
                    SecretStr(PASSWORD),
                    pin,
                )

            collector = make_collector(
                root_router, settings=per_node(), node_target=node_target
            )
            await polled(collector)
            await collector.shutdown()
            return node_router, collector

    node_router, collector = run(scenario())
    node = collector.store.current(NODE)
    assert node.uptime_s == 4162
    assert node.temps_c
    assert len(node_router.logins()) == 2  # one session per non-root node
    assert node_router.paths().count("/Logout.asp") == 2


def test_node_refusal_turns_per_node_off_for_that_node(
    mock_router, make_collector, pin, clock
):
    async def scenario():
        async with mock_router() as root_router, mock_router() as node_router:
            node_router.login_error = 3

            def node_target(node):
                return Target(
                    f"node:{node.mac}",
                    node_router.host,
                    node_router.port,
                    "admin",
                    SecretStr(PASSWORD),
                    pin,
                )

            collector = make_collector(
                root_router, settings=per_node(), node_target=node_target
            )
            await polled(collector, times=2)
            await collector.shutdown()
            return node_router, collector

    node_router, collector = run(scenario())
    assert len(node_router.logins()) == 2  # one refusal per node, then 24 h off
    assert collector.node_guard(NODE).latch is Latch.REFUSED
    assert collector.root.guard.gate() is Gate.OPEN
    assert collector.store.serving() == (ROOT, NODE, WIRED)


def test_login_false_override_skips_the_node_session(mock_router, make_collector, pin):
    rules = Overrides(
        [OverrideRule(NODE, login=False), OverrideRule(WIRED, login=False)]
    )

    async def scenario():
        async with mock_router() as root_router, mock_router() as node_router:

            def node_target(node):
                return Target(
                    "n",
                    node_router.host,
                    node_router.port,
                    "admin",
                    SecretStr(PASSWORD),
                    pin,
                )

            collector = make_collector(
                root_router,
                settings=per_node(),
                node_target=node_target,
                overrides=rules,
            )
            await polled(collector)
            await collector.shutdown()
            return node_router

    assert run(scenario()).seen == []


# --- per_node with the node CA pin (asus.node_ca_file) ------------------------------


def nodes_on_loopback(mesh3):
    """mesh3 with every node at 127.0.0.1, the IP the test node certificate names."""
    for node in mesh3["pages"]["ajax_onboarding.asp"]["get_cfg_clientlist"][0]:
        if node["re_path"] != "0":
            node["ip"] = "127.0.0.1"
    return mesh3


@pytest.fixture
def node_pin(write_file, node_ca):
    return load_node_ca(write_file("asus_node_ca.pem", node_ca.cert_pem, 0o644))


def test_per_node_verifies_each_node_by_the_node_ca_and_its_ip(
    mock_router, make_collector, mesh3, capture, node_leaf, node_pin
):
    async def scenario():
        async with (
            mock_router(nodes_on_loopback(mesh3)) as root_router,
            mock_router(capture("node-triband"), cert=node_leaf) as node_router,
        ):
            collector = make_collector(
                root_router,
                settings=per_node(),
                node_pin=node_pin,
                node_port=node_router.port,
            )
            await polled(collector)
            await collector.shutdown()
            return node_router, collector

    node_router, collector = run(scenario())
    assert len(node_router.logins()) == 2  # NODE and WIRED, one session each
    node = collector.store.current(NODE)
    assert node.uptime_s == 43210  # the node's own uptime, not the service's
    assert [(t.sensor, round(t.celsius)) for t in node.temps_c] == [("cpu", 63)]
    assert node.mem_total_b == 524288 * 1024
    assert collector.store.current(ROOT).uptime_s == 4162
    # Served health: real uptime (no false reboots), RAM, a CPU sensor by name.
    rows = dict(PROFILES["asuswrt-merlin"].render(node))
    assert int(rows[(1, 3, 6, 1, 2, 1, 1, 3, 0)]) == 43210 * 100  # sysUpTime
    assert int(rows[(1, 3, 6, 1, 2, 1, 25, 1, 1, 0)]) == 43210 * 100  # hrSystemUptime
    assert int(rows[(1, 3, 6, 1, 2, 1, 25, 2, 2, 0)]) == 524288  # hrMemorySize, KiB
    assert bytes(rows[(1, 3, 6, 1, 2, 1, 47, 1, 1, 1, 1, 7, 1)]) == b"CPU"
    assert int(rows[(1, 3, 6, 1, 2, 1, 99, 1, 1, 1, 1, 1)]) == 8  # celsius


@pytest.mark.parametrize("leaf", ["foreign_leaf", "nameless_leaf"])
def test_a_node_certificate_off_the_ca_or_the_ip_is_refused(
    mock_router, make_collector, mesh3, request, node_pin, leaf
):
    async def scenario():
        async with (
            mock_router(nodes_on_loopback(mesh3)) as root_router,
            mock_router(cert=request.getfixturevalue(leaf)) as node_router,
        ):
            collector = make_collector(
                root_router,
                settings=per_node(),
                node_pin=node_pin,
                node_port=node_router.port,
            )
            await polled(collector)
            await collector.shutdown()
            return node_router, collector

    node_router, collector = run(scenario())
    assert node_router.seen == []  # TLS failed before any request, the login too
    assert collector.store.current(NODE).uptime_s is None
    assert collector.node_guard(NODE).last_failure.outcome is Outcome.PIN_MISMATCH
    assert collector.store.serving() == (ROOT, NODE, WIRED)


def test_per_node_netdev_gives_each_node_exact_radio_and_port_counters(
    mock_router, make_collector, mesh3, capture, node_leaf, node_pin, clock
):
    # Each minute the node's own counters grow by these bytes (in, out).
    step = {
        "WIRELESS0": (600_000, 60_000),
        "WIRELESS1": (6_000_000, 3_000_000),
        "WIRELESS2": (30_000, 90_000),
        "WIRED": (1_200_000, 240_000),
    }

    async def scenario():
        async with (
            mock_router(nodes_on_loopback(mesh3)) as root_router,
            mock_router(capture("node-triband"), cert=node_leaf) as node_router,
        ):
            collector = make_collector(
                root_router,
                settings=per_node(),
                node_pin=node_pin,
                node_port=node_router.port,
            )
            for n in range(3):
                if n:
                    clock.advance(60)
                node_router.raw_replies["update.cgi"] = netdev_js(
                    **{
                        k: (10**9 + n * rx, 10**9 + n * tx)
                        for k, (rx, tx) in step.items()
                    }
                )
                await collector.poll_once()
            await collector.shutdown()
            return node_router, collector

    node_router, collector = run(scenario())
    node, wired = collector.store.current(NODE), collector.store.current(WIRED)
    # Exact: the first sample is the baseline, then each minute adds its own bytes.
    two = {k: (2 * rx, 2 * tx) for k, (rx, tx) in step.items()}
    octets = {
        n: (node.link(n).in_octets, node.link(n).out_octets) for n in ("wl0", "wl1")
    }
    assert octets == {"wl0": two["WIRELESS0"], "wl1": two["WIRELESS1"]}
    # The node calls unit 2 6g1 while the AiMesh list calls it 5g2: matched by unit.
    assert (node.link("wl2").in_octets, node.link("wl2").out_octets) == two["WIRELESS2"]
    # The wired row keeps the root's is_bh=0 total for NODE's client ports (0 here).
    assert (node.link("wired").in_octets, node.link("wired").out_octets) == (0, 0)
    # One up wired port each, so it gets the node's WIRED: NODE LAN1, WIRED's WAN
    # (over the backhaul copy).
    assert (node.link("L1").in_octets, node.link("L1").out_octets) == two["WIRED"]
    assert (wired.link("W0").in_octets, wired.link("W0").out_octets) == two["WIRED"]
    reads = [s.query for s in node_router.seen if s.path == "/update.cgi"]
    assert reads == [{"output": "netdev"}] * 6  # 3 polls x 2 node sessions, no login
    assert len(node_router.logins()) == 2


def test_node_bytes_are_taken_once_and_go_stale_for_the_aimesh_fallback(
    make_collector, clock
):
    collector = make_collector(SimpleNamespace(host="127.0.0.1", port=1))
    now = clock.monotonic()
    sample = {"wl0": ByteDelta(6_000, 600, 60.0)}
    collector._node_bytes[NODE] = (now - 10, sample)
    assert collector._take_node_bytes(NODE, now) == sample
    assert collector._take_node_bytes(NODE, now + 1) == {"wl0": ByteDelta(None, None)}
    collector._node_bytes[NODE] = (now - 181, sample)  # older than stale_after_s
    assert collector._take_node_bytes(NODE, now) is None
    assert collector._take_node_bytes(WIRED, now) is None  # never sampled


def test_from_config_builds_a_node_target_for_every_node_with_an_ip(
    make_config, base_config, write_file, node_ca, pin, caplog
):
    write_file("asus_node_ca.pem", node_ca.cert_pem, 0o644)
    base_config["asus"] |= {"node_ca_file": "asus_node_ca.pem", "port": 8443}
    base_config["collector"] = {"mode": "per_node"}
    cfg = load_config(make_config(base_config), env={})
    collector = Collector.from_config(cfg, load_secrets(cfg), pin, kdf_n=2)
    node = MeshNode(NODE, True, "node", 1, ip="192.168.50.101")
    target = collector._node_target(node)
    assert (target.host, target.port, target.username) == (
        "192.168.50.101",
        8443,
        "admin",
    )
    assert target.pin.check_hostname is True
    assert target.password.get_secret_value() == PASSWORD_CANARY
    assert collector._node_target(replace(node, ip=None)) is None
    base_config["collector"] = {"mode": "root_only"}
    cfg = load_config(make_config(base_config), env={})
    Collector.from_config(cfg, load_secrets(cfg), pin, kdf_n=2)
    assert "node_ca_file is set, but collector.mode is root_only" in caplog.text


# --- per_node with a node's own leaf pin ([[override]] ca_file) ----------------------


def test_an_override_leaf_pin_verifies_its_node_in_place_of_the_node_ca(
    mock_router, make_collector, mesh3, capture, write_file, old_node_cert, node_pin
):
    # Like some older node models: self-signed, no IP SAN, not issued by the node CA.
    leaf = load_node_pin(write_file("node-wired.pem", old_node_cert.cert_pem, 0o644))

    async def scenario():
        async with (
            mock_router(nodes_on_loopback(mesh3)) as root_router,
            mock_router(capture("node-triband"), cert=old_node_cert) as node_router,
        ):
            collector = make_collector(
                root_router,
                settings=per_node(),
                overrides=Overrides([OverrideRule(WIRED, pin=leaf)]),
                node_pin=node_pin,
                node_port=node_router.port,
            )
            await polled(collector)
            await collector.shutdown()
            return node_router, collector

    node_router, collector = run(scenario())
    assert len(node_router.logins()) == 1  # WIRED only, by its leaf pin
    assert collector.store.current(WIRED).uptime_s == 43210
    assert collector.store.current(NODE).uptime_s is None
    assert collector.node_guard(NODE).last_failure.outcome is Outcome.PIN_MISMATCH


def test_an_override_leaf_pin_refuses_a_cert_its_pinned_ca_true_cert_signed(
    mock_router, make_collector, mesh3, write_file, old_node_cert, old_node_child
):
    leaf = load_node_pin(write_file("node-wired.pem", old_node_cert.cert_pem, 0o644))

    async def scenario():
        async with (
            mock_router(nodes_on_loopback(mesh3)) as root_router,
            mock_router(cert=old_node_child) as node_router,
        ):
            collector = make_collector(
                root_router,
                settings=per_node(),
                overrides=Overrides([OverrideRule(WIRED, pin=leaf)]),
                node_port=node_router.port,
            )
            await polled(collector)
            await collector.shutdown()
            return node_router, collector

    node_router, collector = run(scenario())
    assert node_router.seen == []  # refused in the handshake, before any request
    assert collector.node_guard(WIRED).last_failure.outcome is Outcome.PIN_MISMATCH


def test_from_config_gives_an_override_node_its_leaf_pin(
    make_config, base_config, write_file, old_node_cert, pin, caplog
):
    write_file("node-104.pem", old_node_cert.cert_pem, 0o644)
    base_config["override"] = [{"match": "192.168.50.104", "ca_file": "node-104.pem"}]
    base_config["collector"] = {"mode": "per_node"}
    cfg = load_config(make_config(base_config), env={})
    collector = Collector.from_config(cfg, load_secrets(cfg), pin, kdf_n=2)
    node = MeshNode(NODE, True, "node", 1, ip="192.168.50.104")
    target = collector._node_target(node)
    assert (target.host, target.pin.exact, target.pin.check_hostname) == (
        "192.168.50.104",
        True,
        False,
    )
    assert target.pin.fingerprints == (old_node_cert.fingerprint,)
    with caplog.at_level(logging.WARNING):
        assert collector._node_target(replace(node, ip="192.168.50.105")) is None
    assert "no pinned certificate for node" in caplog.text


def test_from_config_reads_pins_only_when_the_caller_passes_none(
    make_config, base_config, pin
):
    base_config["asus"]["node_ca_file"] = "missing_ca.pem"
    base_config["override"] = [
        {"match": "192.168.50.103"},
        {"match": "192.168.50.104", "ca_file": "node-104.pem"},
    ]
    cfg = load_config(make_config(base_config), env={})
    secrets = load_secrets(cfg)
    with pytest.raises(ConfigError, match=r"override\[1\].ca_file: file not found"):
        Collector.from_config(cfg, secrets, pin, node_pin=None, kdf_n=2)
    # discover --pin-cert --node passes both: a pin it is about to write is no error.
    Collector.from_config(cfg, secrets, pin, overrides=Overrides(), node_pin=None)


# --- Ethernet ports (get_port_status.cgi) ------------------------------------------


def test_port_status_reaches_every_snapshot_in_one_request(mock_router, make_collector):
    async def scenario():
        async with mock_router() as router:
            collector = await polled(make_collector(router))
            await collector.shutdown()
            return router, collector

    router, collector = run(scenario())
    assert router.paths().count("/get_port_status.cgi") == 1
    root = collector.store.current(ROOT)
    assert [(p.name, p.up, p.speed_mbps) for p in root.ports] == [
        ("WAN", True, 1000),
        ("LAN1", True, 1000),
        ("LAN2", False, 0),
    ]
    assert [p.name for p in collector.store.current(WIRED).ports] == ["WAN", "LAN1"]
    assert collector.store.current(NODE).neighbors[0].port == "wl1"


IF_HC_IN, IF_HC_OUT = (
    (1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 6),
    (1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 10),
)


@pytest.mark.parametrize("internet", [True, False], ids=["router", "ap-mode"])
def test_wan_rows_carry_counters_only_from_a_source_that_measures_them(
    mock_router, make_collector, clock, caplog, internet
):
    # The root's own WAN counter is netdev INTERNET (absent in AP mode); a node whose
    # wired uplink is its WAN port (re_path 1) lends that uplink's counters.
    async def scenario():
        async with mock_router() as router:
            collector = make_collector(router)
            for n in range(2):
                if n:
                    clock.advance(60)
                ifaces = {"WIRED": (n * 10**6, n * 10**6)}
                if internet:
                    ifaces["INTERNET"] = (5 * 10**9 + n * 7_500_000, n * 1_500_000)
                router.raw_replies["update.cgi"] = netdev_js(**ifaces)
                with caplog.at_level(logging.INFO):
                    await collector.poll_once()
            await collector.shutdown()
            return router, collector

    router, collector = run(scenario())
    root, node, wired = (collector.store.current(m) for m in (ROOT, NODE, WIRED))
    rows = {
        m: dict(PROFILES["asuswrt-merlin"].render(s))
        for m, s in ((ROOT, root), (NODE, node), (WIRED, wired))
    }
    if internet:
        assert (
            int(rows[ROOT][(*IF_HC_IN, 100)]),
            int(rows[ROOT][(*IF_HC_OUT, 100)]),
        ) == (
            7_500_000,
            1_500_000,
        )
    else:
        assert (*IF_HC_IN, 100) not in rows[ROOT]
    assert root.link("wired").rx_bps == 133_333  # its own counter wins: 1 MB/min
    assert (*IF_HC_IN, 100) not in rows[NODE]  # wireless uplink, WAN down
    uplink = wired.link("backhaul")
    assert int(rows[WIRED][(*IF_HC_IN, 100)]) == uplink.in_octets
    assert int(rows[WIRED][(*IF_HC_OUT, 100)]) == uplink.out_octets
    # LAN: a wired total counts for a port only when it is the one up port it covers.
    # NODE (wireless uplink, WAN down) has LAN1 up alone: its is_bh=0 total is LAN1.
    assert int(rows[NODE][(*IF_HC_IN, 111)]) == node.link("wired").in_octets
    # The root's netdev WIRED covers WAN too, unless INTERNET counts WAN itself.
    shared = "aimesh-root: no counter of its own for WAN, LAN1"
    if internet:
        assert int(rows[ROOT][(*IF_HC_IN, 111)]) == root.link("wired").in_octets
        assert shared not in caplog.text
    else:
        assert (*IF_HC_IN, 111) not in rows[ROOT]
        assert caplog.text.count(shared) == 1  # once, not every poll
    assert (*IF_HC_IN, 111) not in rows[WIRED]  # its only LAN port is down
    assert [s.query for s in router.seen if s.path == "/update.cgi"] == [
        {"output": "netdev"}
    ] * 2  # the root only: nodes have no netdev here


def without_port_status(mesh3):
    mesh3["queries"] = [
        q for q in mesh3["queries"] if q["endpoint"] != "get_port_status.cgi"
    ]
    return mesh3


def with_unusable_port_status(mesh3):
    for query in mesh3["queries"]:
        if query["endpoint"] == "get_port_status.cgi":
            query["reply"] = {"unexpected": "1"}
    return mesh3


@pytest.mark.parametrize("change", [without_port_status, with_unusable_port_status])
def test_a_router_without_port_status_omits_the_rows_and_logs_once(
    mock_router, make_collector, mesh3, caplog, change
):
    async def scenario():
        async with mock_router(change(mesh3)) as router:
            collector = await polled(make_collector(router), times=2)
            await collector.shutdown()
            return router, collector

    router, collector = run(scenario())
    # Asked once; the library tries ajax_ethernet_ports.asp only after no reply.
    assert router.paths().count("/get_port_status.cgi") == 1
    fallback = router.paths().count("/ajax_ethernet_ports.asp")
    assert fallback == (1 if change is without_port_status else 0)
    assert collector.store.serving() == (ROOT, NODE, WIRED)
    assert [collector.store.current(m).ports for m in (ROOT, NODE, WIRED)] == [()] * 3
    assert collector.root.guard.gate() is Gate.OPEN
    logged = [r for r in caplog.records if "Ethernet port status" in r.getMessage()]
    assert len(logged) == 1


def test_an_http_error_omits_the_rows_without_backing_off(
    mock_router, make_collector, monkeypatch, caplog
):
    async def scenario():
        async with mock_router() as router:
            collector = make_collector(router)
            await collector.topology()

            async def failing(request):
                raise AsusRouterAccessError("Cannot access endpoint, status 500")

            monkeypatch.setattr(collector.root, "fetch", failing)
            for _ in range(2):
                await collector.ports()
            await collector.shutdown()
            return collector

    collector = run(scenario())
    assert collector.root.guard.gate() is Gate.OPEN
    logged = [r for r in caplog.records if "Ethernet port status" in r.getMessage()]
    assert len(logged) == 1


def test_a_refused_port_request_stops_the_port_job_without_backing_off(
    mock_router, make_collector, monkeypatch, caplog
):
    calls = []

    async def scenario():
        async with mock_router() as router:
            collector = make_collector(router)
            await collector.topology()

            async def refused(request):
                calls.append(request)
                raise RequestBlockedError("root: endpoint 'x.asp' is not allowlisted")

            monkeypatch.setattr(collector.root, "fetch", refused)
            for _ in range(2):
                await collector.ports()
            await collector.shutdown()
            return collector

    collector = run(scenario())
    assert len(calls) == 1  # asked once, then the job stops asking
    assert collector.root.guard.gate() is Gate.OPEN
    assert "guard refused the port status request" in caplog.text


def test_a_login_refusal_in_the_port_fetch_stays_with_the_guard(
    mock_router, make_collector, monkeypatch
):
    async def scenario():
        async with mock_router() as router:
            collector = make_collector(router)
            await collector.topology()

            async def refused(request):
                raise AsusRouterAccessError(
                    "Access error", ARAccessError.CREDENTIALS, {}
                )

            monkeypatch.setattr(collector.root, "fetch", refused)
            await collector.ports()
            await collector.shutdown()
            return collector

    assert run(scenario()).root.guard.latch is Latch.CREDENTIALS


def test_port_data_older_than_stale_after_is_not_served(
    mock_router, make_collector, clock
):
    async def scenario():
        async with mock_router() as router:
            collector = await polled(make_collector(router))
            fresh = collector.store.current(ROOT).ports
            clock.advance(collector.settings.stale_after_s + 1)
            await collector.metrics(ROOT)
            await collector.shutdown()
            return fresh, collector

    fresh, collector = run(scenario())
    assert len(fresh) == 3
    assert collector.store.current(ROOT).ports == ()


# --- the long-running loop ---------------------------------------------------------


def test_run_serves_nodes_then_stops_cleanly(mock_router, make_collector):
    settings = CollectorSettings(
        stale_after_s=2.0,
        metrics_interval_s=0.2,
        topology_interval_s=0.5,
        request_timeout_s=5,
        housekeeping_s=0.2,
    )

    async def scenario():
        async with mock_router() as router:
            collector = make_collector(router, settings=settings, clock=SystemClock())
            stop = asyncio.Event()
            task = asyncio.create_task(collector.run(stop))
            for _ in range(100):
                await asyncio.sleep(0.05)
                if collector.store.serving() == (ROOT, NODE, WIRED):
                    break
            stop.set()
            await asyncio.wait_for(task, timeout=10)
            return router, collector

    router, collector = run(scenario())
    assert collector.store.serving() == (ROOT, NODE, WIRED)
    assert len(router.logins()) == 1
    assert router.paths().count("/ajax_onboarding.asp") >= 2  # connect + topology
    identity = [s for s in router.seen if "label_mac" in s.body]
    assert len(identity) == 1  # one connect, not one per parallel job
    assert router.paths()[-1] == "/Logout.asp"
    assert collector.root.closed


def test_settings_reject_unknown_mode():
    with pytest.raises(ValueError, match="mode"):
        CollectorSettings(mode="everything")
    assert replace(CollectorSettings(), mode="per_node").per_node


def test_from_config_refuses_cleartext(tmp_path, pin):
    from aimesh_snmp_proxy.config import ConfigError

    cfg = SimpleNamespace(
        asus=SimpleNamespace(use_ssl=False), collector=None, state_dir=tmp_path
    )
    with pytest.raises(ConfigError, match="H1"):
        Collector.from_config(cfg, None, pin, kdf_n=2)


# --- SIGHUP races (reported by build-ops) -----------------------------------------


FAST = CollectorSettings(
    stale_after_s=2.0,
    metrics_interval_s=0.05,
    topology_interval_s=0.2,
    request_timeout_s=5,
    housekeeping_s=0.2,
)


async def wait_for(predicate, timeout=10.0):
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not predicate():
        assert loop.time() < deadline, "condition not reached"
        await asyncio.sleep(0.01)


def test_sighup_during_polling_leaves_no_orphaned_router_session(
    mock_router, make_collector, password_file
):
    async def scenario():
        async with mock_router() as router:
            collector = make_collector(router, settings=FAST, clock=SystemClock())
            stop = asyncio.Event()
            task = asyncio.create_task(collector.run(stop))
            await wait_for(lambda: len(router.logins()) == 1 and router.tokens)
            router.password = "new-password-77"
            password_file.write_text("new-password-77\n")  # SIGHUP swaps sessions
            router.delays["Logout.asp"] = 0.3  # jobs keep polling during the swap
            await collector.reload("SIGHUP")
            await wait_for(lambda: len(router.logins()) >= 2)
            await asyncio.sleep(0.3)
            stop.set()
            await asyncio.wait_for(task, timeout=10)
            return router, collector

    router, collector = run(scenario())
    assert router.tokens == set()  # every session that logged in also logged out
    assert router.paths()[-1] == "/Logout.asp"
    assert collector.root.guard.gate() is Gate.OPEN


def test_sighup_with_nothing_to_fix_keeps_the_live_session(mock_router, make_collector):
    async def scenario():
        async with mock_router() as router:
            collector = await polled(make_collector(router))
            before = collector.root
            await collector.reload("SIGHUP")
            await collector.poll_once()
            same = collector.root is before
            await collector.shutdown()
            return router, same

    router, same = run(scenario())
    assert same
    assert len(router.logins()) == 1


def test_a_failure_caused_by_retiring_a_session_does_not_back_off(
    mock_router, make_collector
):
    async def scenario():
        async with mock_router() as router:
            collector = make_collector(router)
            session = collector.root

            async def work(s):
                await s.close()  # retired under the job, as a SIGHUP swap could do
                raise RuntimeError("Session is closed")

            await collector._guarded(session, work)
            await collector.shutdown()
            return session

    session = run(scenario())
    assert session.guard.gate() is Gate.OPEN
    assert session.guard.last_failure is None
