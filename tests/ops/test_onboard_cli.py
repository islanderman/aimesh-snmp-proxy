import copy
import json
import logging
import os
from pathlib import Path

import pytest

from aimesh_snmp_proxy import __main__ as cli
from aimesh_snmp_proxy import ops
from aimesh_snmp_proxy.config import load_config
from aimesh_snmp_proxy.ops import onboard
from aimesh_snmp_proxy.ops.ledger import Ledger, LedgerError
from aimesh_snmp_proxy.ops.snmpget import Identity, SnmpCheckError
from aimesh_snmp_proxy.ports import PortMap

API = "/api/v0/devices"
RECORDED = Path(__file__).resolve().parents[1] / "fixtures" / "librenms_devices.json"
MERLIN_OID = "1.3.6.1.4.1.8072.3.2.10"
MAC_A = "02:00:00:00:00:0a"
MAC_B = "02:00:00:00:00:0b"
HOSTS = {16101: "aimesh-root", 16102: "aimesh-00000a", 16103: "aimesh-00000b"}
APPLY = ["--apply", "--allow-http"]


@pytest.fixture
def make_env(make_config, base_config, fake, tmp_path):
    """A Config whose [onboard] url is the fake; the root plus two pinned nodes."""

    def _make(onboard_table=None, nodes=((MAC_A, ".101"), (MAC_B, ".102")), **doc):
        conf = copy.deepcopy(base_config)
        conf["onboard"] = {"url": fake.url, "token_file": "onboard_token"}
        if onboard_table is not None:
            conf["onboard"] = onboard_table
        conf["override"] = [{"match": "192.168.50.1", "sys_name": "aimesh-root"}]
        conf.update(doc)
        cfg = load_config(make_config(conf), env={})
        pm = PortMap.load(cfg.ports_file, cfg.snmp.port_base, cfg.nodes.expected)
        for mac, ip in nodes:
            pm.assign(mac, ip="192.168.50" + ip)
        cfg.state_dir.mkdir(exist_ok=True)
        return cfg

    return _make


@pytest.fixture
def cfg(make_env):
    return make_env()


def run(cfg, *argv):
    return onboard.cli_onboard(cfg, list(argv))


def ledger_of(cfg):
    return {
        e.hostname: e for e in Ledger.load(cfg.state_dir / "onboarded.json").entries()
    }


def expected_body(port, force=False):
    hostname = HOSTS[port]
    body = {
        "hostname": hostname,
        "display_template": f"AiMesh {'root ' if port == 16101 else ''}{hostname}",
        "overwrite_ip": "127.0.0.1",
        "port": port,
        "transport": "udp",
        "snmpver": "v2c",
        "community": "canary-community-44",
        "os": "asuswrt-merlin",
    }
    if force:
        body["force_add"] = True
    return body


def test_ops_exports_cli_onboard():
    assert ops.cli_onboard is onboard.cli_onboard
    assert set(ops.__all__) == {"cli_onboard", "cli_run", "cli_selftest"}


# --- dry run ---------------------------------------------------------------------


def test_dry_run_is_the_default_and_sends_nothing(cfg, fake, capsys, canaries):
    assert run(cfg, "--allow-http") == 0
    out, err = capsys.readouterr()
    assert fake.requests == []
    assert "dry run" in out
    assert f"GET  {API}/aimesh-00000a" in out
    assert out.count(f"GET  {API}  ") == 1  # the one device list, not one per node
    assert f"POST {API} " in out
    assert '"community": "***"' in out
    assert '"force_add"' not in out
    assert "lnms config:set icmp_check false" in out
    assert "lnms config:set icmp_check true" in out
    assert "--apply" in out
    for value in canaries.values():
        assert value not in out + err
    assert not (cfg.state_dir / "onboarded.json").exists()


def test_dry_run_shows_one_post_body_per_node(cfg, capsys):
    run(cfg, "--dry-run", "--allow-http")
    out = capsys.readouterr().out
    bodies = [
        json.loads(line.strip().split(" ", 2)[2])
        for line in out.splitlines()
        if line.strip().startswith("POST ")
    ]
    masked = [expected_body(p) | {"community": "***"} for p in HOSTS]
    assert bodies == masked


def test_dry_run_with_force_names_the_snmp_get_first(cfg, fake, capsys):
    assert run(cfg, "--force", "--allow-http") == 0
    out = capsys.readouterr().out
    assert fake.requests == []
    assert "SNMP GET sysObjectID.0, sysName.0 from 127.0.0.1:16102" in out
    assert '"force_add": true' in out


def test_dry_run_lists_skipped_nodes_with_the_reason(make_env, capsys):
    cfg = make_env(override=[{"match": MAC_A, "exclude": True}])
    assert run(cfg, "--allow-http") == 0
    out = capsys.readouterr().out
    assert "skipped: excluded by override" in out
    assert "aimesh-root" in out  # the root needs no override to be named


# --- apply -----------------------------------------------------------------------


def test_apply_checks_then_adds_each_node_in_port_order(cfg, fake, capsys):
    assert run(cfg, *APPLY) == 0
    assert fake.calls() == [
        ("GET", API),
        ("GET", f"{API}/aimesh-root"),
        ("POST", API),
        ("GET", f"{API}/aimesh-00000a"),
        ("POST", API),
        ("GET", f"{API}/aimesh-00000b"),
        ("POST", API),
    ]
    posts = [seen.json() for seen in fake.requests if seen.method == "POST"]
    assert posts == [expected_body(p) for p in HOSTS]
    ledger = ledger_of(cfg)
    assert {h: (e.device_id, e.port) for h, e in ledger.items()} == {
        "aimesh-root": (500, 16101),
        "aimesh-00000a": (501, 16102),
        "aimesh-00000b": (502, 16103),
    }
    assert {e.origin for e in ledger.values()} == {fake.url}
    out = capsys.readouterr().out
    assert "added (device 501)" in out
    assert "lnms config:set icmp_check true" in out


def test_existing_devices_are_skipped_and_never_recorded(cfg, fake, capsys):
    fake.add_existing("aimesh-00000a")  # device 500
    assert run(cfg, *APPLY) == 0
    assert [c for c in fake.calls() if c[0] == "POST"] == [("POST", API)] * 2
    assert "aimesh-00000a" not in ledger_of(cfg)
    assert "exists (device 500); left unchanged" in capsys.readouterr().out


def test_the_token_and_community_never_reach_output_or_files(
    cfg, fake, capsys, canaries, tmp_path
):
    leak = f"bad {canaries['snmp_community']} / {canaries['onboard_token']}"
    fake.routes["POST", API] = lambda seen: (
        fake.reply(400, {"message": leak})
        if seen.json()["port"] == 16103
        else fake._add(seen.json())
    )
    assert run(cfg, *APPLY) == 1
    out, err = capsys.readouterr()
    assert "failed: HTTP 400: bad *** / ***" in out
    secret_files = {tmp_path / name for name in canaries}
    written = [p for p in tmp_path.rglob("*") if p.is_file() and p not in secret_files]
    assert cfg.state_dir / "onboarded.json" in written
    for value in (canaries["snmp_community"], canaries["onboard_token"]):
        assert value not in out + err
        for path in written:
            assert value.encode() not in path.read_bytes(), path


def test_a_401_stops_the_run_after_one_request(cfg, fake, capsys):
    fake.token = "another-token"
    assert run(cfg, *APPLY) == 1
    assert len(fake.requests) == 1
    out, err = capsys.readouterr()
    assert "HTTP 401" in out + err
    assert ledger_of(cfg) == {}


def test_a_403_on_create_stops_the_run(cfg, fake, capsys):
    fake.routes["POST", API] = lambda seen: fake.reply(
        403, {"message": "Insufficient permissions to create a device"}
    )
    assert run(cfg, *APPLY) == 1
    assert fake.calls() == [
        ("GET", API),
        ("GET", f"{API}/aimesh-root"),
        ("POST", API),
    ]
    assert "Insufficient permissions" in capsys.readouterr().out


def test_a_dropped_connection_on_create_stops_and_warns(cfg, fake, capsys):
    fake.routes["POST", API] = lambda seen: None
    assert run(cfg, *APPLY) == 1
    assert fake.calls() == [
        ("GET", API),
        ("GET", f"{API}/aimesh-root"),
        ("POST", API),
    ]
    out = capsys.readouterr().out
    assert "may exist" in out
    assert ledger_of(cfg) == {}


def test_failed_checked_adds_suggest_force(cfg, fake, capsys):
    fake.reject_checked_add = True
    assert run(cfg, *APPLY) == 1
    out = capsys.readouterr().out
    assert "already exists as librenms (127.0.0.1)" in out
    assert "--force" in out
    assert ledger_of(cfg) == {}


def test_skipped_nodes_send_nothing(make_env, fake, capsys):
    cfg = make_env(
        override=[
            {"match": "192.168.50.1", "exclude": True},
            {"match": MAC_A, "exclude": True},
        ]
    )
    assert run(cfg, *APPLY) == 0
    assert fake.calls() == [
        ("GET", API),
        ("GET", f"{API}/aimesh-00000b"),
        ("POST", API),
    ]


# --- the endpoint guard: a renamed device is not added again -------------------


def post_ports(fake):
    return [seen.json()["port"] for seen in fake.requests if seen.method == "POST"]


def test_a_renamed_device_at_the_same_endpoint_is_left_unchanged(cfg, fake, capsys):
    fake.add_existing("192.168.50.101", overwrite_ip="127.0.0.1", port=16102)  # 500
    assert run(cfg, *APPLY) == 0
    assert post_ports(fake) == [16101, 16103]
    out = capsys.readouterr().out
    assert "exists as 192.168.50.101 (device 500), same SNMP endpoint" in out
    assert "left unchanged" in out
    assert set(ledger_of(cfg)) == {"aimesh-root", "aimesh-00000b"}


@pytest.mark.parametrize(
    "fields",
    [
        {"overwrite_ip": "127.0.0.1", "port": 16999},
        {"overwrite_ip": "192.168.50.50", "port": 16102},
        {"overwrite_ip": None, "port": 16102},
        {"overwrite_ip": "127.0.0.1", "port": None},
    ],
    ids=["other-port", "other-ip", "no-ip", "no-port"],
)
def test_a_device_at_another_endpoint_does_not_stop_the_add(cfg, fake, fields):
    fake.add_existing("192.168.50.101", **fields)
    assert run(cfg, *APPLY) == 0
    assert post_ports(fake) == [16101, 16102, 16103]


def test_the_recorded_librenms_list_finds_every_renamed_node(cfg, fake, capsys):
    fake.load_recorded(RECORDED)  # .1 and .101 renamed; .109 is another proxy
    assert run(cfg, *APPLY, "--force") == 0
    assert post_ports(fake) == []
    out = capsys.readouterr().out
    assert "exists as 192.168.50.1 (device 11), same SNMP endpoint" in out
    assert "exists as 192.168.50.101 (device 12), same SNMP endpoint" in out
    assert "exists (device 13); left unchanged" in out  # still named by its sysName
    assert "Created 0 device(s)" in out
    assert ledger_of(cfg) == {}
    assert len(fake.devices) == 7


def test_the_device_list_is_read_once_before_the_first_add(cfg, fake):
    assert run(cfg, *APPLY) == 0
    assert fake.calls().count(("GET", API)) == 1
    assert fake.calls()[0] == ("GET", API)


def test_nothing_to_add_reads_no_list(make_env, fake):
    cfg = make_env(
        override=[
            {"match": "192.168.50.1", "exclude": True},
            {"match": MAC_A, "exclude": True},
            {"match": MAC_B, "exclude": True},
        ]
    )
    assert run(cfg, *APPLY) == 0
    assert fake.requests == []


@pytest.mark.parametrize("status", [401, 403, 500])
def test_a_failed_device_list_stops_the_run_before_any_add(cfg, fake, capsys, status):
    fake.routes["GET", API] = lambda seen: fake.reply(
        status, {"status": "error", "message": "no list for you"}
    )
    assert run(cfg, *APPLY) == 1
    assert fake.calls() == [("GET", API)]
    out, err = capsys.readouterr()
    assert f"HTTP {status}" in out + err
    assert "no list for you" in out + err
    assert ledger_of(cfg) == {}


def test_a_device_list_that_is_not_a_list_stops_the_run(cfg, fake, capsys):
    fake.routes["GET", API] = lambda seen: fake.reply(200, {"status": "ok"})
    assert run(cfg, *APPLY) == 1
    assert fake.calls() == [("GET", API)]
    assert "unexpected answer" in capsys.readouterr().out


def test_force_skips_the_snmp_get_for_a_renamed_device(cfg, fake, probes):
    _, calls = probes
    fake.add_existing("192.168.50.1", overwrite_ip="127.0.0.1", port=16101)
    assert run(cfg, *APPLY, "--force") == 0
    assert [port for _, port, _ in calls] == [16102, 16103]


# --- [onboard] hostname = "ip" ---------------------------------------------------

IP_HOSTS = {16101: "192.168.50.1", 16102: "192.168.50.101", 16103: "192.168.50.102"}


@pytest.fixture
def ip_cfg(make_env, fake):
    table = {"url": fake.url, "token_file": "onboard_token", "hostname": "ip"}
    return make_env(onboard_table=table)


def test_ip_mode_posts_each_node_under_its_lan_ip(ip_cfg, fake, capsys):
    assert run(ip_cfg, *APPLY) == 0
    posts = [seen.json() for seen in fake.requests if seen.method == "POST"]
    assert [(b["hostname"], b["port"]) for b in posts] == [
        ("192.168.50.1", 16101),
        ("192.168.50.101", 16102),
        ("192.168.50.102", 16103),
    ]
    # the display name stays the sysName, so the device list stays readable
    assert [b["display_template"] for b in posts] == [
        "AiMesh root aimesh-root",
        "AiMesh aimesh-00000a",
        "AiMesh aimesh-00000b",
    ]
    assert {b["overwrite_ip"] for b in posts} == {"127.0.0.1"}
    assert {h: e.port for h, e in ledger_of(ip_cfg).items()} == {
        "192.168.50.1": 16101,
        "192.168.50.101": 16102,
        "192.168.50.102": 16103,
    }
    assert "added (device 501)" in capsys.readouterr().out


def test_ip_mode_dry_run_shows_the_ip_and_the_served_sysname(ip_cfg, fake, capsys):
    assert run(ip_cfg, "--allow-http") == 0
    out = capsys.readouterr().out
    assert fake.requests == []
    assert f"GET  {API}/192.168.50.101" in out
    assert "add (checked); serves sysName aimesh-00000a" in out


def test_ip_mode_force_compares_the_served_sysname_not_the_hostname(
    ip_cfg, fake, probes, capsys
):
    _, calls = probes
    assert run(ip_cfg, *APPLY, "--force") == 0
    assert [port for _, port, _ in calls] == [16101, 16102, 16103]
    posts = [seen.json() for seen in fake.requests if seen.method == "POST"]
    assert [b["force_add"] for b in posts] == [True, True, True]
    assert [b["hostname"] for b in posts] == list(IP_HOSTS.values())


def test_ip_mode_force_refuses_a_node_that_serves_another_sysname(
    ip_cfg, fake, probes, capsys
):
    answers, _ = probes
    answers[16103] = Identity(MERLIN_OID, "aimesh-other")
    answers[16102] = Identity(MERLIN_OID, "192.168.50.101")  # the hostname is no proof
    assert run(ip_cfg, *APPLY, "--force") == 1
    assert [s.json()["port"] for s in fake.requests if s.method == "POST"] == [16101]
    out = capsys.readouterr().out
    assert "serves sysName 'aimesh-other', not aimesh-00000b" in out
    assert "serves sysName '192.168.50.101', not aimesh-00000a" in out


def test_ip_mode_skips_a_node_it_cannot_name_by_ip(make_env, fake, capsys):
    table = {"url": fake.url, "token_file": "onboard_token", "hostname": "ip"}
    cfg = make_env(onboard_table=table, nodes=((MAC_A, ".101"), (MAC_B, ".240")))
    assert run(cfg, *APPLY) == 0
    out = capsys.readouterr().out
    assert "skipped: no LAN IP to name it by" in out
    assert [s.json()["port"] for s in fake.requests if s.method == "POST"] == [
        16101,
        16102,
    ]


def test_ip_mode_finds_a_device_still_named_by_its_sysname(ip_cfg, fake, capsys):
    fake.add_existing("aimesh-00000a", overwrite_ip="127.0.0.1", port=16102)  # 500
    assert run(ip_cfg, *APPLY) == 0
    assert [s.json()["port"] for s in fake.requests if s.method == "POST"] == [
        16101,
        16103,
    ]
    assert "exists as aimesh-00000a (device 500), same SNMP endpoint" in (
        capsys.readouterr().out
    )


def test_ip_mode_is_off_by_default(cfg, fake):
    assert run(cfg, *APPLY) == 0
    posts = [seen.json()["hostname"] for seen in fake.requests if seen.method == "POST"]
    assert posts == list(HOSTS.values())


# --- --force ---------------------------------------------------------------------


@pytest.fixture
def probes(monkeypatch):
    """Replace the SNMP GET; ``answers[port]`` is an Identity or an exception."""
    answers, calls = {}, []

    def fake_probe(host, port, community):
        calls.append((host, port, community.get_secret_value()))
        answer = answers.get(port, Identity(MERLIN_OID, HOSTS.get(port)))
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(onboard, "get_identity", fake_probe)
    return answers, calls


def test_force_sets_force_add_only_after_a_successful_snmp_get(
    cfg, fake, probes, capsys
):
    answers, calls = probes
    answers[16102] = SnmpCheckError("no SNMP reply from 127.0.0.1:16102")
    assert run(cfg, *APPLY, "--force") == 1
    assert calls == [
        ("127.0.0.1", 16101, "canary-community-44"),
        ("127.0.0.1", 16102, "canary-community-44"),
        ("127.0.0.1", 16103, "canary-community-44"),
    ]
    posts = [seen.json() for seen in fake.requests if seen.method == "POST"]
    assert posts == [expected_body(16101, True), expected_body(16103, True)]
    out = capsys.readouterr().out
    assert "failed: SNMP GET: no SNMP reply from 127.0.0.1:16102; not added" in out
    assert set(ledger_of(cfg)) == {"aimesh-root", "aimesh-00000b"}


def test_force_refuses_a_node_that_serves_another_sysname(cfg, fake, probes, capsys):
    answers, _ = probes
    answers[16103] = Identity(MERLIN_OID, "aimesh-other")
    answers[16102] = Identity(MERLIN_OID, None)
    assert run(cfg, *APPLY, "--force") == 1
    posts = [seen.json()["port"] for seen in fake.requests if seen.method == "POST"]
    assert posts == [16101]
    out = capsys.readouterr().out
    assert "serves sysName 'aimesh-other', not aimesh-00000b" in out
    assert "serves no sysName" in out


def test_force_skips_the_snmp_get_for_devices_that_exist(cfg, fake, probes):
    _, calls = probes
    fake.add_existing("aimesh-root")
    run(cfg, *APPLY, "--force")
    assert [port for _, port, _ in calls] == [16102, 16103]


def test_dry_run_and_apply_are_exclusive(cfg):
    with pytest.raises(SystemExit):
        run(cfg, "--dry-run", "--apply")


# --- refusals before any request ---------------------------------------------------


def test_http_is_refused_without_the_opt_in(cfg, fake, capsys):
    assert run(cfg, "--apply") == onboard.EXIT_CONFIG
    assert fake.requests == []
    assert "--allow-http" in capsys.readouterr().err


def test_a_missing_onboard_section_is_a_config_error(make_env, capsys):
    cfg = make_env()
    cfg = cfg.__class__(**{**vars(cfg), "onboard": None})
    assert run(cfg) == onboard.EXIT_CONFIG
    assert "[onboard]" in capsys.readouterr().err


def test_a_v3_only_config_is_refused(make_env, capsys):
    cfg = make_env()
    snmp = cfg.snmp.__class__(**{**vars(cfg.snmp), "community_file": None})
    cfg = cfg.__class__(**{**vars(cfg), "snmp": snmp})
    assert run(cfg, "--allow-http") == onboard.EXIT_CONFIG
    assert "v2c" in capsys.readouterr().err


def test_a_group_readable_token_file_is_refused(cfg, fake, capsys):
    cfg.onboard.token_file.chmod(0o640)
    assert run(cfg, *APPLY) == onboard.EXIT_CONFIG
    assert fake.requests == []
    assert "onboard.token_file" in capsys.readouterr().err


def test_a_corrupt_ports_json_is_refused(cfg, fake, capsys):
    cfg.ports_file.write_text("{")
    assert run(cfg, *APPLY) == onboard.EXIT_CONFIG
    assert fake.requests == []
    assert "ports.json" in capsys.readouterr().err


def test_a_corrupt_ledger_is_refused_before_any_request(cfg, fake, capsys):
    (cfg.state_dir / "onboarded.json").write_text("[")
    assert run(cfg, *APPLY) == onboard.EXIT_CONFIG
    assert fake.requests == []
    assert "onboarded.json" in capsys.readouterr().err


def test_a_missing_ports_json_warns_and_plans_only_the_root(make_env, fake, capsys):
    cfg = make_env(nodes=())
    assert run(cfg, "--allow-http") == 0
    out = capsys.readouterr().out
    assert "no ports.json" in out
    assert "aimesh-root" in out


def test_an_unwritable_ledger_stops_before_any_request(cfg, fake, monkeypatch, capsys):
    def broken(self):
        raise LedgerError("onboarded.json: cannot write: Read-only file system")

    monkeypatch.setattr(Ledger, "save", broken)
    assert run(cfg, *APPLY) == onboard.EXIT_CONFIG
    assert fake.requests == []
    assert "Read-only file system" in capsys.readouterr().err


def test_a_ledger_failure_after_a_create_stops_the_run(cfg, fake, monkeypatch, capsys):
    def broken(self, entry):
        raise LedgerError("onboarded.json: cannot write: disk full")

    monkeypatch.setattr(Ledger, "record", broken)
    assert run(cfg, *APPLY) == 1
    assert fake.calls() == [
        ("GET", API),
        ("GET", f"{API}/aimesh-root"),
        ("POST", API),
    ]
    out = capsys.readouterr().out
    assert "added device 500 but could not record it" in out


@pytest.fixture
def root_logger():
    """main() installs a JSON log handler; put the root logger back afterwards."""
    root = logging.getLogger()
    saved_level, saved_handlers = root.level, list(root.handlers)
    yield root
    for handler in list(root.handlers):
        if handler not in saved_handlers:
            root.removeHandler(handler)
    root.setLevel(saved_level)
    logging.captureWarnings(False)


def test_main_dispatches_onboard(make_env, capsys, root_logger, monkeypatch):
    for name in list(os.environ):
        if name.startswith("AIMESH_PROXY") or name == "CREDENTIALS_DIRECTORY":
            monkeypatch.delenv(name)
    cfg = make_env()
    assert cli.main(["-c", str(cfg.source), "onboard", "--allow-http"]) == 0
    assert "dry run" in capsys.readouterr().out


def test_dry_run_with_nothing_to_add_says_so(make_env, fake, capsys):
    cfg = make_env(nodes=(), override=[{"match": "192.168.50.1", "exclude": True}])
    assert run(cfg, "--allow-http") == 0
    assert "No node to add." in capsys.readouterr().out
    assert fake.requests == []


def test_a_server_error_on_create_is_a_failure_without_the_force_hint(
    cfg, fake, capsys
):
    fake.routes["POST", API] = lambda seen: fake.reply(500, {"message": "boom"})
    assert run(cfg, *APPLY) == 1
    out = capsys.readouterr().out
    assert out.count("failed: HTTP 500: boom") == 3
    assert "--force" not in out


def test_a_cross_origin_redirect_stops_the_run(cfg, fake, make_fake, capsys):
    other = make_fake()
    target = f"{other.url}{API}/aimesh-root"
    fake.routes["GET", f"{API}/aimesh-root"] = lambda seen: (
        302,
        {"Location": target},
        b"",
    )
    assert run(cfg, *APPLY) == 1
    assert fake.calls() == [("GET", API), ("GET", f"{API}/aimesh-root")]
    assert other.requests == []
    assert "redirect" in capsys.readouterr().out


def test_an_onboard_section_without_token_file_is_a_config_error(
    make_env, fake, capsys
):
    cfg = make_env(onboard_table={"url": fake.url})
    assert run(cfg, *APPLY) == onboard.EXIT_CONFIG
    assert fake.requests == []
    assert "onboard.token_file: required" in capsys.readouterr().err


def test_the_ca_file_from_config_pins_the_librenms_certificate(
    make_env, make_fake, librenms_cert
):
    https = make_fake(librenms_cert)
    cfg = make_env(
        onboard_table={
            "url": https.url,
            "token_file": "onboard_token",
            "ca_file": str(librenms_cert.cert_path),
        }
    )
    assert run(cfg, "--apply") == 0
    assert [m for m, _ in https.calls()].count("POST") == 3


def test_onboard_accepts_a_pinned_self_signed_cert_with_the_ip_only_in_its_cn(
    make_env, make_fake, ip_cn_cert, capsys
):
    https = make_fake(ip_cn_cert)
    table = {"url": https.url, "token_file": "onboard_token"}
    cfg = make_env(onboard_table={**table, "ca_file": str(ip_cn_cert.cert_path)})
    assert run(cfg, "--apply") == 0
    assert [m for m, _ in https.calls()].count("POST") == 3
    assert "TLS" not in capsys.readouterr().err


def test_a_dry_run_creates_no_state(make_env, fake):
    cfg = make_env(nodes=())
    cfg.state_dir.rmdir()
    assert run(cfg, "--allow-http") == 0
    assert not cfg.state_dir.exists()
    assert fake.requests == []
