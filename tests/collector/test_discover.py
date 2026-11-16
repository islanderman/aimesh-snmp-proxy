import asyncio
import io
import json
import os
import ssl
import stat
from types import SimpleNamespace

import pytest

from aimesh_snmp_proxy.collector import cli_discover
from aimesh_snmp_proxy.collector import discover as discover_mod
from aimesh_snmp_proxy.collector.service import Collector, CollectorSettings
from aimesh_snmp_proxy.collector.session import CertFileError, Target
from aimesh_snmp_proxy.config import load_node_ca, load_node_pin, load_router_pin
from aimesh_snmp_proxy.logsafe import SecretStr

PASSWORD = "canary-router-Pa55-1"
END = "-----END CERTIFICATE-----\n"
EXIT_CONFIG = 78


@pytest.fixture
def files(tmp_path, router_cert):
    secret = tmp_path / "asus_password"
    secret.write_text(PASSWORD + "\n")
    secret.chmod(0o600)
    cert = tmp_path / "router.pem"
    cert.write_text(router_cert.cert_pem)
    cert.chmod(0o644)
    return SimpleNamespace(password=secret, cert=cert)


def make_cfg(tmp_path, files, host, port, *, overrides=None, **asus):
    overrides = overrides or {}
    return SimpleNamespace(
        asus=SimpleNamespace(
            host=host,
            port=port,
            username="admin",
            password_file=asus.get("password_file", files.password),
            ca_file=asus.get("ca_file", files.cert),
            use_ssl=True,
        ),
        collector=SimpleNamespace(
            mode="root_only",
            stale_after_s=180.0,
            metrics_interval_s=60.0,
            topology_interval_s=300.0,
            request_timeout_s=5.0,
        ),
        snmp=SimpleNamespace(v3=None, community_file=None, port_base=16101),
        nodes=SimpleNamespace(expected=("192.168.50.101", "192.168.50.102")),
        state_dir=tmp_path / "state",
        ports_file=tmp_path / "state" / "ports.json",
        root_ip=host if host[0].isdigit() else None,
        override_for=lambda mac, ip=None: overrides.get(mac),
        overrides=(),
        onboard=None,
    )


def discover(cfg, argv, answer=""):
    out, err = io.StringIO(), io.StringIO()
    code = cli_discover(cfg, argv, out=out, err=err, ask=lambda _prompt: answer)
    return code, out.getvalue(), err.getvalue()


def in_thread(router_ctx, body):
    """Serve the mock router on one loop; run the CLI (its own loop) in a thread."""

    async def scenario():
        async with router_ctx as router:
            result = await asyncio.to_thread(body, router)
            return router, result

    return asyncio.run(scenario())


# --- listing --------------------------------------------------------------------


def test_discover_lists_nodes_without_secrets_or_client_macs(
    tmp_path, files, mock_router
):
    router, (code, out, err) = in_thread(
        mock_router(),
        lambda r: discover(make_cfg(tmp_path, files, r.host, r.port), []),
    )
    assert code == 0, err
    lines = out.splitlines()
    assert lines[0].split()[:5] == ["role", "sys_name", "port", "model", "firmware"]
    root = next(line for line in lines if line.startswith("router"))
    assert root.split() == [
        "router",
        "aimesh-root",
        "16101",
        "RT-AX88U",
        "3.0.0.4.388.4_0",
        "192.168.50.1",
        "00:53:01",
        "yes",
        "0",
        "-",
    ]
    node = next(line for line in lines if "aimesh-005302" in line)
    assert "wireless 5g2 -54 dBm via 00:53:01" in node
    assert node.split()[2] == "16102"  # expected IP 192.168.50.101 is index 1
    wired = next(line for line in lines if "aimesh-005303" in line)
    assert "wired 1000 Mbit/s via 00:53:01" in wired
    assert wired.split()[2] == "16103"
    assert not (tmp_path / "state" / "ports.json").exists()  # read-only preview
    text = (out + err).lower()
    assert PASSWORD not in text
    assert "00:00:5e:00:53:a1" not in text  # a client MAC
    assert "53:a1" not in text
    assert len(router.logins()) == 1
    assert router.paths()[-1] == "/Logout.asp"


def test_discover_reports_a_refused_login(tmp_path, files, mock_router):
    def body(router):
        router.password = "something-else"
        return discover(make_cfg(tmp_path, files, router.host, router.port), [])

    _, (code, out, err) = in_thread(mock_router(), body)
    assert code == 1
    assert out == ""
    assert "credentials" in err


def test_discover_config_error_exits_78(tmp_path, files):
    files.password.chmod(0o644)
    code, _, err = discover(make_cfg(tmp_path, files, "127.0.0.1", 9), [])
    assert code == EXIT_CONFIG
    assert "asus.password_file" in err


# --- fixtures -----------------------------------------------------------------------


def test_fixture_capture_is_scrubbed_and_replays(tmp_path, files, mock_router, pin):
    out_dir = tmp_path / "captured"
    _, (code, out, err) = in_thread(
        mock_router(),
        lambda r: discover(
            make_cfg(tmp_path, files, r.host, r.port), ["--fixtures", str(out_dir)]
        ),
    )
    assert code == 0, err
    path = out_dir / "fixture.json"
    assert str(path) in out
    text = path.read_text()
    for leak in (PASSWORD, "asus_token", "tok1", "login_authorization", "00:53:A1"):
        assert leak.lower() not in text.lower()
    doc = json.loads(text)

    async def replay():
        async with mock_router(doc) as router:
            target = Target(
                "root", router.host, router.port, "admin", SecretStr(PASSWORD), pin
            )
            collector = Collector(
                target,
                tmp_path / "replay-state",
                settings=CollectorSettings(request_timeout_s=5),
                kdf_n=2,
            )
            await collector.poll_once()
            await collector.shutdown()
            return collector

    collector = asyncio.run(replay())
    snapshots = [
        collector.store.current(i.node_id) for i in collector.store.identities()
    ]
    assert len(snapshots) == 3
    root = next(s for s in snapshots if s.role == "router")
    assert (root.model, root.cpu_pct, root.uptime_s) == ("RT-AX88U", 5, 4162)
    assert root.radio(1).clients == 3
    assert all(s.mac.startswith("02:00:00:00:") for s in snapshots)


# --- pinning ------------------------------------------------------------------------


def test_pin_cert_with_yes_writes_the_presented_certificate(
    tmp_path, files, mock_router, rogue_cert
):
    target = tmp_path / "pins" / "router.pem"
    router, (code, out, _) = in_thread(
        mock_router(cert=rogue_cert),
        lambda r: discover(
            make_cfg(tmp_path, files, r.host, r.port),
            ["--pin-cert", str(target), "--yes"],
        ),
    )
    assert code == 0
    assert rogue_cert.fingerprint in out
    assert router.seen == []  # handshake only, no HTTP and no login
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o644
    assert load_router_pin(target).fingerprints == (rogue_cert.fingerprint,)


@pytest.mark.parametrize(("answer", "code"), [("no", 1), ("", 1), ("YES", 0)])
def test_pin_cert_asks_before_writing(tmp_path, files, mock_router, answer, code):
    target = tmp_path / "router-new.pem"
    _, (got, out, _) = in_thread(
        mock_router(),
        lambda r: discover(
            make_cfg(tmp_path, files, r.host, r.port),
            ["--pin-cert", str(target)],
            answer=answer,
        ),
    )
    assert got == code
    assert target.exists() is (code == 0)
    if code:
        assert "not pinned" in out


def test_pin_cert_reports_an_existing_identical_pin(
    tmp_path, files, mock_router, router_cert
):
    _, (code, out, _) = in_thread(
        mock_router(),
        lambda r: discover(
            make_cfg(tmp_path, files, r.host, r.port),
            ["--pin-cert", str(files.cert), "--yes"],
        ),
    )
    assert code == 0
    assert "already pinned" in out


def test_pin_cert_replaces_a_different_pin_after_confirmation(
    tmp_path, files, mock_router, rogue_cert, router_cert
):
    _, (code, out, _) = in_thread(
        mock_router(cert=rogue_cert),
        lambda r: discover(
            make_cfg(tmp_path, files, r.host, r.port),
            ["--pin-cert", str(files.cert)],
            answer="yes",
        ),
    )
    assert code == 0
    assert router_cert.fingerprint in out  # the old pin is shown for comparison
    assert load_router_pin(files.cert).fingerprints == (rogue_cert.fingerprint,)


def test_pin_cert_unreachable_router(tmp_path, files):
    code, _, err = discover(
        make_cfg(tmp_path, files, "127.0.0.1", 9),
        ["--pin-cert", str(tmp_path / "x.pem")],
    )
    assert code == 1
    assert "cannot fetch" in err


# --- pinning the node CA (asus.node_ca_file) ---------------------------------------


def node_cfg(tmp_path, files, port, *expected):
    cfg = make_cfg(tmp_path, files, "127.0.0.1", port)
    cfg.nodes = SimpleNamespace(expected=expected)
    return cfg


def test_pin_node_ca_saves_the_ca_that_issued_a_node_certificate(
    tmp_path, files, mock_router, node_leaf, node_ca
):
    target = tmp_path / "asus_node_ca.pem"
    router, (code, out, err) = in_thread(
        mock_router(cert=node_leaf),
        lambda r: discover(
            node_cfg(tmp_path, files, r.port, "127.0.0.1"),
            ["--pin-node-ca", str(target), "--yes"],
        ),
    )
    assert code == 0, err
    assert node_ca.fingerprint in out
    assert "issued by CN=AiMesh Root CA" in out
    assert router.seen == []  # handshake only, no HTTP and no login
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o644
    assert load_node_ca(target).fingerprints == (node_ca.fingerprint,)


def test_pin_node_ca_skips_a_silent_node_and_reports_an_existing_pin(
    tmp_path, files, mock_router, node_leaf, node_ca
):
    target = tmp_path / "asus_node_ca.pem"
    target.write_text(node_ca.cert_pem)
    target.chmod(0o644)
    _, (code, out, err) = in_thread(
        mock_router(cert=node_leaf),
        lambda r: discover(
            node_cfg(tmp_path, files, r.port, "127.0.0.9", "127.0.0.1"),
            ["--pin-node-ca", str(target)],
        ),
    )
    assert code == 0
    assert "127.0.0.9" in err  # the first node did not answer; the next one did
    assert "already pinned" in out


def test_pin_node_ca_asks_before_writing(tmp_path, files, mock_router, node_leaf):
    target = tmp_path / "asus_node_ca.pem"
    _, (code, out, _) = in_thread(
        mock_router(cert=node_leaf),
        lambda r: discover(
            node_cfg(tmp_path, files, r.port, "127.0.0.1"),
            ["--pin-node-ca", str(target)],
            answer="no",
        ),
    )
    assert (code, target.exists()) == (1, False)
    assert "not pinned" in out


def test_pin_node_ca_warns_when_the_node_certificate_names_no_ip(
    tmp_path, files, mock_router, nameless_leaf
):
    target = tmp_path / "asus_node_ca.pem"
    _, (code, out, _) = in_thread(
        mock_router(cert=nameless_leaf),
        lambda r: discover(
            node_cfg(tmp_path, files, r.port, "127.0.0.1"),
            ["--pin-node-ca", str(target), "--yes"],
        ),
    )
    assert code == 0
    assert "does not name 127.0.0.1" in out


def test_pin_node_ca_refuses_a_self_signed_node(tmp_path, files, mock_router):
    _, (code, _, err) = in_thread(
        mock_router(),  # router_cert: self-signed, no issuing CA in the chain
        lambda r: discover(
            node_cfg(tmp_path, files, r.port, "127.0.0.1"),
            ["--pin-node-ca", str(tmp_path / "x.pem"), "--yes"],
        ),
    )
    assert code == 1
    assert "no issuing CA" in err


# --- the root's /cert.crt fallback: the live nodes send their leaf alone -----------


@pytest.fixture
def root_ca_file(monkeypatch):
    """Replace the /cert.crt download; record what it was asked for."""
    calls = []

    def _serve(body: bytes | Exception):
        async def fake(host, port, pin, *, timeout_s):
            calls.append((host, port, pin.fingerprints))
            if isinstance(body, Exception):
                raise body
            return body

        monkeypatch.setattr(discover_mod, "fetch_router_ca_file", fake)
        return calls

    return _serve


def pin_root(files, leaf_only, root_leaf):
    files.cert.write_text(leaf_only(root_leaf).cert_pem)  # what --pin-cert saved


def test_pin_node_ca_falls_back_to_the_roots_ca_file(
    tmp_path, files, mock_router, node_leaf, node_ca, root_leaf, leaf_only, root_ca_file
):
    pin_root(files, leaf_only, root_leaf)
    calls = root_ca_file(node_ca.cert_pem.encode())
    target = tmp_path / "asus_node_ca.pem"
    router, (code, out, err) = in_thread(
        mock_router(cert=leaf_only(node_leaf)),
        lambda r: discover(
            node_cfg(tmp_path, files, r.port, "127.0.0.1"),
            ["--pin-node-ca", str(target), "--yes"],
        ),
    )
    assert code == 0, err
    assert calls == [("127.0.0.1", router.port, (root_leaf.fingerprint,))]
    assert "/cert.crt" in out
    assert node_ca.fingerprint in out
    assert load_node_ca(target).fingerprints == (node_ca.fingerprint,)


@pytest.mark.parametrize(
    ("body", "why"),
    [
        ("two", "exactly one"),
        ("html", "exactly one"),
        ("with_key", "private key"),
        ("leaf", "not a CA"),
        ("other_ca", "did not issue the pinned router certificate"),
    ],
)
def test_pin_node_ca_refuses_a_ca_file_that_proves_nothing(
    tmp_path,
    files,
    mock_router,
    node_leaf,
    node_ca,
    root_leaf,
    foreign_leaf,
    leaf_only,
    root_ca_file,
    body,
    why,
):
    pin_root(files, leaf_only, root_leaf)
    other_ca = foreign_leaf.cert_pem.split(END)[1] + END
    bodies = {
        "two": node_ca.cert_pem * 2,
        "html": "<html>login</html>",
        "with_key": node_ca.cert_pem + node_ca.key_pem,
        "leaf": leaf_only(root_leaf).cert_pem,
        "other_ca": other_ca,
    }
    root_ca_file(bodies[body].encode())
    target = tmp_path / "asus_node_ca.pem"
    _, (code, _, err) = in_thread(
        mock_router(cert=leaf_only(node_leaf)),
        lambda r: discover(
            node_cfg(tmp_path, files, r.port, "127.0.0.1"),
            ["--pin-node-ca", str(target), "--yes"],
        ),
    )
    assert (code, target.exists()) == (1, False)
    assert "no issuing CA" in err
    assert why in err


def test_pin_node_ca_refuses_a_root_ca_that_did_not_issue_the_node(
    tmp_path,
    files,
    mock_router,
    foreign_leaf,
    node_ca,
    root_leaf,
    leaf_only,
    root_ca_file,
):
    pin_root(files, leaf_only, root_leaf)
    root_ca_file(node_ca.cert_pem.encode())
    _, (code, _, err) = in_thread(
        mock_router(cert=leaf_only(foreign_leaf)),
        lambda r: discover(
            node_cfg(tmp_path, files, r.port, "127.0.0.1"),
            ["--pin-node-ca", str(tmp_path / "x.pem"), "--yes"],
        ),
    )
    assert code == 1
    assert "did not issue the node certificate" in err


@pytest.mark.parametrize("problem", ["fetch", "no_router_pin"])
def test_pin_node_ca_fallback_needs_the_router_pin_and_the_file(
    tmp_path, files, mock_router, node_leaf, root_leaf, leaf_only, root_ca_file, problem
):
    if problem == "fetch":
        pin_root(files, leaf_only, root_leaf)
        root_ca_file(CertFileError("HTTP 404"))
    else:
        files.cert.unlink()
    _, (code, _, err) = in_thread(
        mock_router(cert=leaf_only(node_leaf)),
        lambda r: discover(
            node_cfg(tmp_path, files, r.port, "127.0.0.1"),
            ["--pin-node-ca", str(tmp_path / "x.pem"), "--yes"],
        ),
    )
    assert code == 1
    assert {"fetch": "HTTP 404", "no_router_pin": "--pin-cert"}[problem] in err


@pytest.mark.parametrize("expected", [(), ("127.0.0.1",)])
def test_pin_node_ca_needs_a_reachable_node_in_nodes_expected(
    tmp_path, files, expected
):
    code, _, err = discover(
        node_cfg(tmp_path, files, 9, *expected),
        ["--pin-node-ca", str(tmp_path / "x.pem")],
    )
    assert code == (EXIT_CONFIG if not expected else 1)
    assert ("nodes.expected" if not expected else "no node answered") in err


# --- pinning one node's own certificate ([[override]] ca_file) ---------------------


def test_pin_cert_node_by_ip_saves_that_nodes_own_leaf(
    tmp_path, files, mock_router, old_node_cert
):
    target = tmp_path / "node-104.pem"
    router, (code, out, err) = in_thread(
        mock_router(cert=old_node_cert),
        lambda r: discover(
            make_cfg(tmp_path, files, "192.168.50.1", r.port),
            ["--pin-cert", str(target), "--node", r.host, "--yes"],
        ),
    )
    assert code == 0, err
    assert f"node {router.host} at {router.host}:{router.port} presents" in out
    assert "set ca_file to this path in the [[override]] for 127.0.0.1" in out
    assert router.seen == []  # handshake only, no HTTP and no login
    pin = load_node_pin(target)
    assert (pin.fingerprints, pin.exact) == ((old_node_cert.fingerprint,), True)


def test_pin_cert_node_by_mac_finds_its_ip_with_one_root_login(
    tmp_path, files, mock_router, old_node_cert, monkeypatch
):
    fetched = []

    async def fake_fetch(host, port, *, timeout_s):
        fetched.append((host, port))
        return ssl.PEM_cert_to_DER_cert(old_node_cert.cert_pem)

    monkeypatch.setattr(discover_mod, "fetch_certificate", fake_fetch)
    target = tmp_path / "node-101.pem"
    router, (code, out, err) = in_thread(
        mock_router(),
        lambda r: discover(
            make_cfg(tmp_path, files, r.host, r.port),
            ["--pin-cert", str(target), "--node", "00-00-5E-00-53-02", "--yes"],
        ),
    )
    assert code == 0, err
    assert fetched == [("192.168.50.101", router.port)]
    assert "node 00:00:5e:00:53:02 at 192.168.50.101" in out
    assert len(router.logins()) == 1
    assert router.paths()[-1] == "/Logout.asp"
    assert load_node_pin(target).fingerprints == (old_node_cert.fingerprint,)


@pytest.mark.parametrize(
    ("node", "error"),
    [
        ("00:00:5e:00:53:01", "00:00:5e:00:53:01 is the root router"),
        ("00:00:5e:00:53:99", "the root reports no node 00:00:5e:00:53:99"),
        ("127.0.0.1", "127.0.0.1 is the root router"),
    ],
)
def test_pin_cert_node_refuses_the_root_and_unknown_nodes(
    tmp_path, files, mock_router, node, error
):
    target = tmp_path / "node.pem"
    _, (code, _, err) = in_thread(
        mock_router(),
        lambda r: discover(
            make_cfg(tmp_path, files, r.host, r.port),
            ["--pin-cert", str(target), "--node", node, "--yes"],
        ),
    )
    assert code == 1
    assert error in err
    assert not target.exists()


def test_pin_cert_node_by_mac_reports_a_refused_login(tmp_path, files, mock_router):
    def body(router):
        router.password = "something-else"
        return discover(
            make_cfg(tmp_path, files, router.host, router.port),
            ["--pin-cert", str(tmp_path / "n.pem"), "--node", "00:00:5e:00:53:02"],
        )

    _, (code, _, err) = in_thread(mock_router(), body)
    assert code == 1
    assert "no AiMesh nodes read from 127.0.0.1: credentials" in err


def test_pin_cert_node_by_ip_unreachable(tmp_path, files):
    code, _, err = discover(
        make_cfg(tmp_path, files, "192.168.50.1", 9),
        ["--pin-cert", str(tmp_path / "n.pem"), "--node", "127.0.0.1"],
    )
    assert code == 1
    assert "cannot fetch the certificate from 127.0.0.1:9" in err


@pytest.mark.parametrize(
    ("problem", "error"),
    [("loose_password", "asus.password_file"), ("no_router_pin", "--pin-cert PATH")],
)
def test_pin_cert_node_by_mac_reports_a_config_error(tmp_path, files, problem, error):
    cfg = make_cfg(tmp_path, files, "127.0.0.1", 9)
    if problem == "loose_password":
        files.password.chmod(0o644)
    else:
        cfg.asus.ca_file = None
    code, _, err = discover(
        cfg, ["--pin-cert", str(tmp_path / "n.pem"), "--node", "00:00:5e:00:53:02"]
    )
    assert code == EXIT_CONFIG
    assert error in err


@pytest.mark.parametrize(
    ("argv", "error"),
    [
        (["--node", "192.168.50.104"], "--node needs --pin-cert"),
        (["--pin-cert", "n.pem", "--node", "node-104"], "a MAC or an IPv4 address"),
    ],
)
def test_node_needs_pin_cert_and_a_mac_or_an_ip(tmp_path, files, capsys, argv, error):
    with pytest.raises(SystemExit) as exited:
        discover(make_cfg(tmp_path, files, "127.0.0.1", 9), argv)
    assert exited.value.code == 2
    assert error in capsys.readouterr().err


def test_discover_without_a_pin_points_to_pin_cert(tmp_path, files):
    cfg = make_cfg(tmp_path, files, "127.0.0.1", 9, ca_file=None)
    code, _, err = discover(cfg, [])
    assert code == EXIT_CONFIG
    assert "--pin-cert" in err


def test_discover_through_main_with_a_real_config(
    make_config, base_config, mock_router, capsys
):
    from aimesh_snmp_proxy.__main__ import main

    def body(router):
        base_config["asus"].update(host=router.host, port=router.port)
        base_config["collector"] = {"request_timeout_s": 5}
        return main(["-c", str(make_config(base_config)), "discover"])

    _, code = in_thread(mock_router(), body)
    out = capsys.readouterr().out
    assert code == 0
    assert "aimesh-005302" in out
    assert listed_ports(out)["aimesh-005302"] == "16102"
    assert "aimesh-root" in out  # found by MAC: asus.host is the mock, not .6


# --- ports ------------------------------------------------------------------------


def listed_ports(out):
    rows = [line.split() for line in out.splitlines()[1:]]
    return {row[1]: row[2] for row in rows}


def test_discover_shows_pinned_ports_and_leaves_ports_json_untouched(
    tmp_path, files, mock_router
):
    ports = tmp_path / "state" / "ports.json"
    ports.parent.mkdir(mode=0o700)
    doc = {"version": 1, "next_index": 6, "nodes": {"00:00:5e:00:53:02": 5}}
    ports.write_text(json.dumps(doc))
    before = ports.read_bytes()
    _, (code, out, err) = in_thread(
        mock_router(),
        lambda r: discover(make_cfg(tmp_path, files, r.host, r.port), []),
    )
    assert code == 0, err
    assert listed_ports(out) == {
        "aimesh-root": "16101",
        "aimesh-005302": "16106",
        "aimesh-005303": "16103",
    }
    assert ports.read_bytes() == before
    assert sorted(p.name for p in ports.parent.iterdir()) == [
        "lockout.json",
        "ports.json",
    ]


def test_discover_override_port_wins(tmp_path, files, mock_router):
    pins = {"00:00:5e:00:53:03": SimpleNamespace(port=16150)}
    _, (code, out, _) = in_thread(
        mock_router(),
        lambda r: discover(
            make_cfg(tmp_path, files, r.host, r.port, overrides=pins), []
        ),
    )
    assert code == 0
    assert listed_ports(out)["aimesh-005303"] == "16150"


def test_discover_lists_nodes_even_when_ports_json_is_corrupt(
    tmp_path, files, mock_router
):
    ports = tmp_path / "state" / "ports.json"
    ports.parent.mkdir(mode=0o700)
    ports.write_text("{broken")
    _, (code, out, err) = in_thread(
        mock_router(),
        lambda r: discover(make_cfg(tmp_path, files, r.host, r.port), []),
    )
    assert code == 0
    assert set(listed_ports(out).values()) == {"-"}
    assert "ports.json" in err
    assert ports.read_text() == "{broken"


def test_port_preview_matches_run_with_pins_new_nodes_and_two_roots(
    make_config, base_config
):
    """Parity with ``ops.run.Engines``: the build-ops repro, plus a second root."""
    from aimesh_snmp_proxy.collector.discover import preview_ports
    from aimesh_snmp_proxy.collector.mapping import MeshNode
    from aimesh_snmp_proxy.collector.store import NodeIdentity
    from aimesh_snmp_proxy.config import default_sys_name, load_config, load_secrets
    from aimesh_snmp_proxy.ops.run import Engines
    from aimesh_snmp_proxy.ports import PortMap

    del base_config["nodes"]  # no expected IPs: every node is new
    base_config["override"] = [
        {"match": "00:00:5e:00:53:02", "port": 16102},
        {"match": "00:00:5e:00:53:04", "port": 16103},
    ]
    cfg = load_config(make_config(base_config), env={})
    nodes = {
        "00:00:5e:00:53:10": MeshNode(
            "00:00:5e:00:53:10", True, "router", 0, "192.168.50.250"
        ),
        "00:00:5e:00:53:20": MeshNode(
            "00:00:5e:00:53:20", True, "node", 1, "192.168.50.1"
        ),
        **{
            f"00:00:5e:00:53:0{n}": MeshNode(
                f"00:00:5e:00:53:0{n}", True, "node", 1, f"192.168.50.20{n}"
            )
            for n in range(1, 5)
        },
    }
    preview = preview_ports(cfg, nodes, io.StringIO())

    class Server:
        def __init__(self):
            self.specs = []

        async def add(self, spec):
            self.specs.append(spec)

    server = Server()
    names = cfg.sys_names(
        [(m, n.ip) for m, n in nodes.items()], root_mac="00:00:5e:00:53:10"
    )
    # Two root candidates hit the sys_names edge reported to build-scaffold: one
    # gets no name, so take the collector's fallback, as the store would
    identities = [
        NodeIdentity(m, m, n.ip, n.role, names.get(m) or default_sys_name(m), None)
        for m, n in nodes.items()
    ]
    ports = PortMap.load(
        cfg.ports_file,
        cfg.snmp.port_base,
        cfg.nodes.expected,
        root_ip=cfg.root_ip,
        read_only=True,
    )
    asyncio.run(Engines(cfg, load_secrets(cfg), ports, server).sync(identities))
    assert preview == {spec.mac: str(spec.port) for spec in server.specs}
    assert preview["00:00:5e:00:53:01"] == "16104"  # MAC order would give 16105
    assert preview["00:00:5e:00:53:03"] == "16105"
    assert "00:00:5e:00:53:20" not in preview  # a second root: run refuses it
