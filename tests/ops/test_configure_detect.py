"""``init --detect``: pin the router certificate, then one login to the mock router."""

import asyncio
import copy
import io
import json
import secrets
import socket
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path

import pytest

from aimesh_snmp_proxy.config import load_config, load_router_pin
from aimesh_snmp_proxy.ops import configure

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


class Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


@dataclass
class Result:
    code: int
    out: str
    err: str
    prompts: list[str]


@pytest.fixture(autouse=True)
def paths(tmp_path, monkeypatch):
    monkeypatch.setattr(configure, "ETC_DIR", tmp_path / "etc")
    monkeypatch.setattr(configure, "STATE_DIR", str(tmp_path / "state"))
    staging = tmp_path / "tmp"
    staging.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(staging))
    return tmp_path


def fixture(name):
    return json.loads((FIXTURES / f"{name}.json").read_text())


def node_ips(data):
    """The AiMesh node IPs a fixture lists, its first entry (the root) left out."""
    nodes = data["pages"]["ajax_onboarding.asp"]["get_cfg_clientlist"][0]
    return tuple(node["ip"] for node in nodes[1:])


def run_init(argv, answers=(), *, password, tty=False):
    replies = iter(answers)
    prompts = []

    def ask(prompt):
        prompts.append(prompt)
        try:
            return next(replies)
        except StopIteration:
            raise EOFError from None

    out, err = io.StringIO(), io.StringIO()
    code = configure.cli_init(
        None,
        argv,
        out=out,
        err=err,
        stdin=Tty() if tty else io.StringIO(password + "\n"),
        ask=ask,
        secret=lambda _prompt: password,
    )
    return Result(code, out.getvalue(), err.getvalue(), prompts)


def in_thread(router_ctx, body):
    """Serve the mock router on one loop; run init (its own loop) in a thread."""

    async def scenario():
        async with router_ctx as router:
            return router, await asyncio.to_thread(body, router)

    return asyncio.run(scenario())


def detect(router, etc, *extra):
    return [
        *("--host", router.host, "--port", str(router.port), "--password-stdin"),
        *("--output-dir", str(etc), "--detect", *extra),
    ]


def test_detect_finds_an_aimesh_root_and_lists_its_nodes(
    paths, mock_router, router_cert
):
    etc = paths / "etc"
    router, result = in_thread(
        mock_router(), lambda r: run_init(detect(r, etc, "--yes"), password=r.password)
    )
    assert result.code == 0, result.err
    cfg = load_config(etc / "config.toml", env={})
    ips = node_ips(fixture("mesh3"))
    password = router.password
    assert cfg.nodes.expected == ips
    assert load_router_pin(cfg.asus.ca_file).fingerprints == (router_cert.fingerprint,)
    assert stat.S_IMODE((etc / "asus_router.pem").stat().st_mode) == 0o644
    assert f"detected: an AiMesh root with {len(ips)} nodes" in result.out
    assert len(router.logins()) == 1
    assert router.paths()[-1] == "/Logout.asp"
    assert not router.tokens  # logged out
    assert "systemctl stop aimesh-snmp-proxy" in result.err
    assert "6 router logins per hour" in result.err
    assert password not in result.out + result.err
    assert result.prompts == []  # --yes: no question
    assert not (paths / "state").exists()  # the service's own state is untouched
    assert "--pin-cert" not in result.out.split("Next steps")[1]  # pinned already


def test_detect_serves_a_standalone_device_as_one(paths, mock_router):
    etc = paths / "etc"
    router, result = in_thread(
        mock_router(fixture("bridge-ac")),
        lambda r: run_init(detect(r, etc, "--yes"), password=r.password),
    )
    assert result.code == 0, result.err
    assert "\n[nodes]" not in (etc / "config.toml").read_text()
    assert "detected: a standalone router, AP or media bridge" in result.out
    assert len(router.logins()) == 1


def test_detect_asks_before_it_pins(paths, mock_router):
    etc = paths / "etc"
    _, result = in_thread(
        mock_router(),
        lambda r: run_init(detect(r, etc), answers=["yes"], password=r.password),
    )
    assert result.code == 0, result.err
    assert result.prompts == ["Type yes to pin this certificate: "]
    assert (etc / "asus_router.pem").exists()


@pytest.mark.parametrize("answers", [["no"], []])
def test_no_pin_means_no_login_and_no_files(paths, mock_router, answers):
    etc = paths / "etc"
    router, result = in_thread(
        mock_router(),
        lambda r: run_init(detect(r, etc), answers=answers, password=r.password),
    )
    assert result.code == 1
    assert "not pinned" in result.out + result.err
    assert router.logins() == []
    assert not etc.exists()


def test_detect_keeps_an_identical_pin_without_asking(paths, mock_router, router_cert):
    etc = paths / "etc"
    etc.mkdir()
    (etc / "asus_router.pem").write_text(router_cert.cert_pem)
    _, result = in_thread(
        mock_router(), lambda r: run_init(detect(r, etc), password=r.password)
    )
    assert result.code == 0, result.err
    assert "already pinned" in result.out
    assert result.prompts == []


def test_a_refused_login_writes_no_config(paths, mock_router):
    etc = paths / "etc"

    def body(router):
        password = router.password
        router.password = secrets.token_hex(8)  # the router now wants another one
        return password, run_init(detect(router, etc, "--yes"), password=password)

    _, (password, result) = in_thread(mock_router(), body)
    assert result.code == 1
    assert "credentials" in result.err
    assert sorted(p.name for p in etc.iterdir()) == ["asus_router.pem"]
    assert password not in result.out + result.err


def test_an_unreachable_router_is_reported(paths):
    with socket.socket() as sock:  # a port nothing listens on
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    etc = paths / "etc"
    argv = [
        *("--host", "127.0.0.1", "--port", str(port), "--password-stdin"),
        *("--output-dir", str(etc), "--detect", "--yes"),
    ]
    result = run_init(argv, password=secrets.token_hex(8))
    assert result.code == 1
    assert "cannot fetch the certificate" in result.err
    assert not etc.exists()


def test_detect_with_dry_run_logs_in_but_writes_nothing(paths, mock_router):
    etc = paths / "etc"
    router, result = in_thread(
        mock_router(),
        lambda r: run_init(detect(r, etc, "--yes", "--dry-run"), password=r.password),
    )
    assert result.code == 0, result.err
    assert len(router.logins()) == 1
    assert not etc.exists()
    assert f'expected = ["{node_ips(fixture("mesh3"))[0]}"' in result.out
    assert list((paths / "tmp").iterdir()) == []


def test_dry_run_compares_with_the_existing_pin(paths, mock_router, router_cert):
    etc = paths / "etc"
    etc.mkdir()
    (etc / "asus_router.pem").write_text(router_cert.cert_pem)
    _, result = in_thread(
        mock_router(),
        lambda r: run_init(detect(r, etc, "--dry-run"), password=r.password),
    )
    assert result.code == 0, result.err
    assert "already pinned" in result.out
    assert result.prompts == []
    assert sorted(p.name for p in etc.iterdir()) == ["asus_router.pem"]


def test_explicit_standalone_mode_wins_with_a_warning(paths, mock_router):
    etc = paths / "etc"
    _, result = in_thread(
        mock_router(),
        lambda r: run_init(
            detect(r, etc, "--yes", "--mode", "standalone"), password=r.password
        ),
    )
    assert result.code == 0, result.err
    assert "\n[nodes]" not in (etc / "config.toml").read_text()
    assert f"lists {len(node_ips(fixture('mesh3')))} AiMesh nodes" in result.err


def test_explicit_aimesh_mode_on_a_standalone_device_warns(paths, mock_router):
    etc = paths / "etc"
    _, result = in_thread(
        mock_router(fixture("bridge-ac")),
        lambda r: run_init(
            detect(r, etc, "--yes", "--mode", "aimesh"), password=r.password
        ),
    )
    assert result.code == 0, result.err
    assert load_config(etc / "config.toml", env={}).nodes.expected == ()
    assert "no AiMesh nodes" in result.err


def test_a_node_without_an_ip_is_left_out_with_a_warning(paths, mock_router):
    data = copy.deepcopy(fixture("mesh3"))
    nodes = data["pages"]["ajax_onboarding.asp"]["get_cfg_clientlist"][0]
    kept = nodes[1]["ip"]
    del nodes[2]["ip"]
    etc = paths / "etc"
    _, result = in_thread(
        mock_router(data),
        lambda r: run_init(detect(r, etc, "--yes"), password=r.password),
    )
    assert result.code == 0, result.err
    assert load_config(etc / "config.toml", env={}).nodes.expected == (kept,)
    assert "has no IP" in result.err


def test_questions_offer_detection(paths, mock_router):
    def body(router):
        # instance, host, port, user, type, detect, sysName, port base, URL, pin
        answers = ["", router.host, str(router.port), "", "", "y", "", "", "", "yes"]
        return run_init([], answers, password=router.password, tty=True)

    router, result = in_thread(mock_router(), body)
    assert result.code == 0, result.err
    cfg = load_config(paths / "etc" / "config.toml", env={})
    assert cfg.nodes.expected == node_ips(fixture("mesh3"))
    assert len(router.logins()) == 1


def test_standalone_mode_and_a_standalone_device_agree_quietly(paths, mock_router):
    etc = paths / "etc"
    _, result = in_thread(
        mock_router(fixture("bridge-ac")),
        lambda r: run_init(
            detect(r, etc, "--yes", "--mode", "standalone"), password=r.password
        ),
    )
    assert result.code == 0, result.err
    assert "AiMesh node" not in result.err


def test_an_unwritable_pin_folder_is_reported(paths, mock_router):
    import os

    if os.geteuid() == 0:
        pytest.skip("root writes anywhere")
    locked = paths / "locked"
    locked.mkdir(mode=0o500)
    try:
        router, result = in_thread(
            mock_router(),
            lambda r: run_init(detect(r, locked / "etc", "--yes"), password=r.password),
        )
    finally:
        locked.chmod(0o700)
    assert result.code == 1
    assert "Permission denied" in result.err
    assert router.logins() == []
