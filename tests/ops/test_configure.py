"""``init``: the config generator, without a router (see test_configure_detect)."""

import io
import os
import re
import secrets
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import pytest

from aimesh_snmp_proxy import __main__ as cli
from aimesh_snmp_proxy.config import load_config, load_router_pin, load_secrets
from aimesh_snmp_proxy.ops import configure

PASSWORD = f"pw-{secrets.token_hex(8)}"  # built at run time: no secret in the source
HOST = "192.168.50.1"
OWNER_ONLY = 0o600


class Tty(io.StringIO):
    """stdin as a terminal."""

    def isatty(self) -> bool:
        return True


@dataclass
class Result:
    code: int
    out: str
    err: str
    prompts: list[str]

    @property
    def text(self) -> str:
        return self.out + self.err


@pytest.fixture(autouse=True)
def paths(tmp_path, monkeypatch):
    """Keep every default path and the staging folder inside tmp_path."""
    monkeypatch.setattr(configure, "ETC_DIR", tmp_path / "etc")
    monkeypatch.setattr(configure, "STATE_DIR", str(tmp_path / "state"))
    staging = tmp_path / "tmp"
    staging.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(staging))
    return tmp_path


@pytest.fixture
def init():
    def run(argv, *, answers=(), password=PASSWORD, tty=False, stdin=None):
        prompts: list[str] = []
        replies = iter(answers)

        def ask(prompt):
            prompts.append(prompt)
            try:
                return next(replies)
            except StopIteration:
                raise EOFError from None

        def secret(prompt):
            prompts.append(prompt)
            return password

        if stdin is None:
            stdin = "" if tty else password + "\n"
        stream = Tty(stdin) if tty else io.StringIO(stdin)
        out, err = io.StringIO(), io.StringIO()
        code = configure.cli_init(
            None, list(argv), out=out, err=err, stdin=stream, ask=ask, secret=secret
        )
        return Result(code, out.getvalue(), err.getvalue(), prompts)

    return run


def flags(etc, *extra):
    return ["--host", HOST, "--password-stdin", "--output-dir", str(etc), *extra]


def load(folder):
    return load_config(Path(folder) / "config.toml", env={})


def mode_of(path):
    return stat.S_IMODE(path.stat().st_mode)


# --- the files ------------------------------------------------------------------------


def test_flags_write_a_config_that_check_config_accepts(
    init, paths, router_cert, capsys
):
    etc = paths / "etc"
    result = init(flags(etc))
    assert result.code == 0, result.err
    cfg = load(etc)
    assert (cfg.asus.host, cfg.asus.port, cfg.asus.username) == (HOST, 8443, "admin")
    assert cfg.asus.ca_file == etc / "asus_router.pem"
    assert cfg.state_dir == paths / "state"
    assert cfg.snmp.port_base == 16101
    assert cfg.nodes.expected == ()
    assert cfg.overrides == ()
    assert cfg.collector.mode == "root_only"
    assert cfg.onboard is None
    loaded = load_secrets(cfg)
    assert loaded.asus_password.get_secret_value() == PASSWORD
    assert re.fullmatch(r"[0-9a-f]{32}", loaded.snmp_community.get_secret_value())
    pin = etc / "asus_router.pem"
    pin.write_text(router_cert.cert_pem)
    pin.chmod(0o644)
    capsys.readouterr()
    assert cli.main(["-c", str(etc / "config.toml"), "check-config"]) == 0
    assert "config ok" in capsys.readouterr().out


def test_files_are_owner_only_whatever_the_umask(init, paths):
    etc = paths / "etc"
    old = os.umask(0o022)
    try:
        result = init(flags(etc))
        assert os.umask(0o022) == 0o022  # restored after the run
    finally:
        os.umask(old)
    assert result.code == 0, result.err
    assert mode_of(etc) == 0o700
    for name in ("config.toml", "asus_password", "snmp_community"):
        assert mode_of(etc / name) == OWNER_ONLY, name
    assert sorted(os.listdir(etc)) == ["asus_password", "config.toml", "snmp_community"]
    assert os.listdir(paths / "tmp") == []  # the staging folder is gone


def test_no_secret_reaches_the_output(init, paths):
    etc = paths / "etc"
    result = init(flags(etc))
    community = (etc / "snmp_community").read_text().strip()
    assert PASSWORD not in result.text
    assert community not in result.text


def test_each_run_draws_a_new_community(init, paths):
    first, second = paths / "a", paths / "b"
    assert init(flags(first)).code == 0
    assert init(flags(second)).code == 0
    assert (first / "snmp_community").read_text() != (
        second / "snmp_community"
    ).read_text()


@pytest.mark.parametrize("name", ["config.toml", "asus_password", "snmp_community"])
def test_refuses_to_replace_any_file_without_force(init, paths, name):
    etc = paths / "etc"
    etc.mkdir()
    (etc / name).write_text("keep me\n")
    result = init(flags(etc))
    assert result.code == 1
    assert name in result.err
    assert "--force" in result.err
    assert sorted(os.listdir(etc)) == [name]
    assert (etc / name).read_text() == "keep me\n"


def test_force_replaces_the_files_and_warns_about_the_community(init, paths):
    etc = paths / "etc"
    assert init(flags(etc)).code == 0
    old = (etc / "snmp_community").read_text()
    result = init(flags(etc, "--force", "--port-base", "16201"))
    assert result.code == 0, result.err
    assert load(etc).snmp.port_base == 16201
    assert (etc / "snmp_community").read_text() != old
    assert "replaced: asus_password, snmp_community, config.toml" in result.out
    assert "LibreNMS" in result.err


def test_dry_run_writes_nothing_and_prints_the_config(init, paths):
    etc = paths / "etc"
    result = init(flags(etc, "--dry-run"))
    assert result.code == 0, result.err
    assert not etc.exists()
    assert "dry run" in result.out
    assert f'host = "{HOST}"' in result.out
    assert "asus_password (0600)" in result.out
    assert PASSWORD not in result.text
    assert os.listdir(paths / "tmp") == []


def test_a_dry_run_prints_neither_the_password_nor_the_community(
    init, paths, monkeypatch
):
    community = secrets.token_hex(16)  # the value init will draw, known to the test
    monkeypatch.setattr(configure.secrets, "token_hex", lambda _nbytes: community)
    argv = flags(paths / "etc", "--dry-run", "--librenms-url", "https://192.168.50.10")
    result = init(argv)
    assert result.code == 0, result.err
    assert "snmp_community (0600): a new random SNMP community" in result.out
    assert PASSWORD not in result.text
    assert community not in result.text


def test_dry_run_still_refuses_an_existing_file(init, paths):
    etc = paths / "etc"
    etc.mkdir()
    (etc / "config.toml").write_text("keep me\n")
    assert init(flags(etc, "--dry-run")).code == 1


def test_a_missing_folder_is_created_owner_only(init, paths):
    etc = paths / "deep" / "etc"
    assert init(flags(etc)).code == 0
    assert mode_of(etc) == 0o700
    assert mode_of(etc.parent) == 0o700


def test_an_unwritable_folder_is_reported(init, paths):
    if os.geteuid() == 0:
        pytest.skip("root writes anywhere")
    locked = paths / "locked"
    locked.mkdir(mode=0o500)
    try:
        result = init(flags(locked / "etc"))
    finally:
        locked.chmod(0o700)
    assert result.code == 1
    assert "run as root" in result.err


# --- instances and port bases ---------------------------------------------------------


def test_an_instance_gets_its_folder_state_dir_and_sys_name(init, paths):
    result = init(["--host", "192.168.50.2", "--password-stdin", "--instance", "lab"])
    assert result.code == 0, result.err
    cfg = load(paths / "etc" / "lab")
    assert cfg.state_dir == Path(f"{paths / 'state'}-lab")
    assert [(o.match, o.sys_name) for o in cfg.overrides] == [
        ("192.168.50.2", "aimesh-lab")
    ]
    assert cfg.root_sys_name() == "aimesh-lab"
    assert "systemctl enable --now aimesh-snmp-proxy@lab" in result.out
    assert "install.sh --instance lab" in result.out


def test_the_main_service_writes_to_the_etc_folder(init, paths):
    result = init(["--host", HOST, "--password-stdin"])
    assert result.code == 0, result.err
    assert load(paths / "etc").snmp.port_base == 16101
    assert "systemctl enable --now aimesh-snmp-proxy\n" in result.out


def write_sibling(etc, name, body):
    folder = etc / name if name else etc
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "config.toml").write_text(body)


@pytest.mark.parametrize(
    ("siblings", "expected"),
    [
        ({}, 16101),
        ({"": 16101}, 16201),
        ({"": 16101, "ap1": 16201}, 16301),
        ({"": None}, 16201),  # no port_base: the default, 16101
        ({"ap1": 16150}, 16301),  # within 100 ports of 16101 and of 16201
        ({"ap1": 16301}, 16101),
        ({"lab": 16101}, 16101),  # its own config is replaced, not a sibling
    ],
)
def test_the_port_base_skips_every_other_services_block(
    init, paths, siblings, expected
):
    etc = paths / "etc"
    for name, base in siblings.items():
        write_sibling(
            etc, name, f"[snmp]\nport_base = {base}\n" if base else "[snmp]\n"
        )
    argv = ["--host", HOST, "--password-stdin", "--instance", "lab", "--force"]
    result = init(argv)
    assert result.code == 0, result.err
    assert load(etc / "lab").snmp.port_base == expected


@pytest.mark.parametrize("given", [16201, 16250, 16152])
def test_an_explicit_port_base_must_not_overlap_another_service(init, paths, given):
    etc = paths / "etc"
    write_sibling(etc, "", "[snmp]\nport_base = 16201\n")
    argv = ["--host", HOST, "--password-stdin", "--instance", "lab"]
    result = init([*argv, "--port-base", str(given)])
    assert result.code == 78
    assert str(etc / "config.toml") in result.err
    assert not (etc / "lab").exists()


def test_an_explicit_free_port_base_is_kept(init, paths):
    etc = paths / "etc"
    write_sibling(etc, "", "[snmp]\nport_base = 16201\n")
    argv = [
        "--host",
        HOST,
        "--password-stdin",
        "--instance",
        "x",
        "--port-base",
        "16301",
    ]
    assert init(argv).code == 0
    assert load(etc / "x").snmp.port_base == 16301


def test_a_sibling_that_is_no_toml_is_skipped_with_a_warning(init, paths):
    etc = paths / "etc"
    write_sibling(etc, "ap1", "not = = toml\n")
    result = init(["--host", HOST, "--password-stdin", "--instance", "lab"])
    assert result.code == 0, result.err
    assert f"{etc / 'ap1' / 'config.toml'}" in result.err
    assert load(etc / "lab").snmp.port_base == 16101


def test_an_unreadable_sibling_needs_an_explicit_port_base(init, paths):
    if os.geteuid() == 0:
        pytest.skip("root reads every file")
    etc = paths / "etc"
    write_sibling(etc, "ap1", "[snmp]\nport_base = 16201\n")
    (etc / "ap1" / "config.toml").chmod(0)
    argv = ["--host", HOST, "--password-stdin", "--instance", "lab"]
    try:
        refused = init(argv)
        given = init([*argv, "--port-base", "16301"])
    finally:
        (etc / "ap1" / "config.toml").chmod(0o600)
    assert refused.code == 1
    assert "--port-base" in refused.err
    assert given.code == 0, given.err
    assert "not checked" in given.err


# --- router type, nodes and names -----------------------------------------------------


def test_aimesh_mode_lists_the_nodes_in_order(init, paths):
    etc = paths / "etc"
    argv = flags(etc, "--mode", "aimesh", "--nodes", "192.168.50.3, 192.168.50.5-6")
    assert init(argv).code == 0
    assert load(etc).nodes.expected == ("192.168.50.3", "192.168.50.5", "192.168.50.6")


def test_nodes_make_auto_mode_an_aimesh_root(init, paths):
    etc = paths / "etc"
    assert init(flags(etc, "--nodes", "192.168.50.2")).code == 0
    assert load(etc).nodes.expected == ("192.168.50.2",)


def test_aimesh_mode_without_nodes_writes_an_empty_list(init, paths):
    etc = paths / "etc"
    assert init(flags(etc, "--mode", "aimesh")).code == 0
    assert "expected = []" in (etc / "config.toml").read_text()
    assert load(etc).nodes.expected == ()


def test_standalone_mode_writes_no_nodes_section(init, paths):
    etc = paths / "etc"
    assert init(flags(etc, "--mode", "standalone")).code == 0
    text = (etc / "config.toml").read_text()
    assert "\n[nodes]" not in text
    assert "standalone" in text


def test_auto_mode_leaves_the_nodes_as_a_comment(init, paths):
    etc = paths / "etc"
    assert init(flags(etc)).code == 0
    text = (etc / "config.toml").read_text()
    assert "# [nodes]" in text
    assert "\n[nodes]" not in text


def test_sys_name_names_the_router(init, paths):
    etc = paths / "etc"
    assert init(flags(etc, "--sys-name", "core-ap")).code == 0
    cfg = load(etc)
    assert [(o.match, o.sys_name) for o in cfg.overrides] == [(HOST, "core-ap")]


def test_the_default_root_name_needs_no_override(init, paths):
    etc = paths / "etc"
    assert init(flags(etc, "--sys-name", "aimesh-root")).code == 0
    assert load(etc).overrides == ()


def test_odd_user_names_survive_the_toml_round_trip(init, paths):
    etc = paths / "etc"
    name = 'ad"m\\in\tx\x7fé'
    assert init(flags(etc, "--username", name)).code == 0
    assert load(etc).asus.username == name


# --- LibreNMS -------------------------------------------------------------------------


def test_librenms_url_adds_an_onboard_section(init, paths):
    etc = paths / "etc"
    assert init(flags(etc, "--librenms-url", "https://192.168.50.10")).code == 0
    cfg = load(etc)
    assert cfg.onboard.url == "https://192.168.50.10"
    assert cfg.onboard.token_file == etc / "librenms_token"
    assert cfg.onboard.ca_file is None
    assert not (etc / "librenms_token").exists()


def test_librenms_ca_is_copied_and_pinned(init, paths, router_cert):
    etc = paths / "etc"
    source = paths / "lnms.pem"
    source.write_text(router_cert.cert_pem)
    source.chmod(0o664)  # a pin source need not be private
    argv = flags(etc, "--librenms-url", "https://192.168.50.10", "--librenms-ca")
    result = init([*argv, str(source)])
    assert result.code == 0, result.err
    cfg = load(etc)
    assert cfg.onboard.ca_file == etc / "librenms.pem"
    assert mode_of(etc / "librenms.pem") == 0o644
    pin = load_router_pin(cfg.onboard.ca_file, "onboard.ca_file")
    assert pin.fingerprints == (router_cert.fingerprint,)


@pytest.mark.parametrize("body", ["not a certificate\n", "PRIVATE KEY"])
def test_librenms_ca_must_be_a_certificate(init, paths, router_cert, body):
    etc = paths / "etc"
    source = paths / "lnms.pem"
    source.write_text(router_cert.key_pem if body == "PRIVATE KEY" else body)
    argv = flags(etc, "--librenms-url", "https://192.168.50.10", "--librenms-ca")
    result = init([*argv, str(source)])
    assert result.code == 78
    assert str(source) in result.err
    assert "aimesh-init-" not in result.err  # never the staging path
    assert not etc.exists()


def test_a_missing_librenms_ca_is_reported(init, paths):
    etc = paths / "etc"
    argv = flags(etc, "--librenms-url", "https://192.168.50.10", "--librenms-ca")
    result = init([*argv, str(paths / "nope.pem")])
    assert result.code == 1
    assert "nope.pem" in result.err
    assert not etc.exists()


# --- usage errors ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        ["--host", "router.example.com"],
        ["--host", "2001:db8::1"],
        ["--host", HOST, "--port", "0"],
        ["--host", HOST, "--port", "65536"],
        ["--host", HOST, "--port-base", "1023"],
        ["--host", HOST, "--port-base", "65281"],
        ["--host", HOST, "--instance", "Office"],
        ["--host", HOST, "--instance", "-ap"],
        ["--host", HOST, "--instance", "a" * 33],
        ["--host", HOST, "--sys-name", "bad name"],
        ["--host", HOST, "--username", ""],
        ["--host", HOST, "--nodes", "192.168.50.300"],
        ["--host", HOST, "--mode", "mesh"],
        ["--host", HOST, "--mode", "standalone", "--nodes", "192.168.50.2"],
        ["--host", HOST, "--detect", "--nodes", "192.168.50.2"],
        ["--host", HOST, "--yes"],
        ["--host", HOST, "--librenms-ca", "x.pem"],
        ["--host", HOST, "--librenms-url", "ftp://192.168.50.10"],
        ["--host", HOST, "--librenms-url", "https://user:pw@192.168.50.10"],
    ],
)
def test_bad_flags_are_usage_errors(init, paths, capsys, argv):
    with pytest.raises(SystemExit) as exc:
        init([*argv, "--password-stdin", "--output-dir", str(paths / "etc")])
    assert exc.value.code == 2
    assert not (paths / "etc").exists()
    assert PASSWORD not in capsys.readouterr().err


def test_host_is_required_without_a_terminal(init, paths):
    result = init(["--password-stdin", "--output-dir", str(paths / "etc")])
    assert result.code == 2
    assert "--host" in result.err


# --- the password ---------------------------------------------------------------------


def test_password_stdin_takes_the_first_line_as_is(init, paths):
    etc = paths / "etc"
    assert init(flags(etc), stdin=" spaced pw \nnext line\n").code == 0
    assert load_secrets(load(etc)).asus_password.get_secret_value() == " spaced pw "


@pytest.mark.parametrize(
    ("stdin", "why"),
    [("\n", "empty"), ("", "empty"), ("a\rb\n", "one line"), ("x" * 4096, "4096")],
)
def test_a_bad_password_is_refused_without_echo(init, paths, stdin, why):
    result = init(flags(paths / "etc"), stdin=stdin)
    assert result.code == 2
    assert why in result.err
    assert not (paths / "etc").exists()


def test_a_password_needs_a_terminal_or_stdin(init, paths):
    result = init(["--host", HOST, "--output-dir", str(paths / "etc")])
    assert result.code == 2
    assert "--password-stdin" in result.err


def test_password_stdin_refuses_a_terminal(init, paths):
    result = init(flags(paths / "etc"), tty=True, stdin=PASSWORD + "\n")
    assert result.code == 2
    assert "terminal" in result.err


def test_a_terminal_asks_for_the_password_without_echo(init, paths):
    etc = paths / "etc"
    result = init(["--host", HOST, "--output-dir", str(etc)], tty=True)
    assert result.code == 0, result.err
    assert result.prompts == ["Router password (not echoed): "]
    assert load_secrets(load(etc)).asus_password.get_secret_value() == PASSWORD


# --- questions on a terminal ----------------------------------------------------------


def test_questions_fill_every_value_no_flag_gave(init, paths):
    answers = [
        "lab",  # instance
        "192.168.50.2",  # router
        "8443",
        "admin",
        "aimesh",
        "n",  # no detection
        "192.168.50.3,192.168.50.4",
        "",  # sysName: the default
        "",  # port base: the free one
        "https://192.168.50.10",
        "",  # no LibreNMS certificate pin
    ]
    result = init([], answers=answers, tty=True)
    assert result.code == 0, result.err
    cfg = load(paths / "etc" / "lab")
    assert cfg.asus.host == "192.168.50.2"
    assert cfg.nodes.expected == ("192.168.50.3", "192.168.50.4")
    assert cfg.root_sys_name() == "aimesh-lab"
    assert cfg.snmp.port_base == 16101
    assert cfg.onboard.url == "https://192.168.50.10"
    assert result.prompts[-1] == "Router password (not echoed): "
    assert len(result.prompts) == len(answers) + 1


def test_empty_answers_take_every_default(init, paths):
    result = init([], answers=[""] * 9, tty=True)
    assert result.code == 0, result.err
    cfg = load(paths / "etc")
    assert (cfg.asus.host, cfg.asus.port, cfg.asus.username) == (HOST, 8443, "admin")
    assert cfg.overrides == ()
    assert cfg.onboard is None


def test_flags_skip_their_questions(init, paths):
    result = init(
        ["--instance", "lab", "--mode", "standalone"], answers=[""] * 6, tty=True
    )
    assert result.code == 0, result.err
    assert not any("Instance" in p or "Router type" in p for p in result.prompts)
    assert not any("detect" in p for p in result.prompts)


def test_a_bad_answer_is_asked_again(init, paths):
    answers = ["", "router.example.com", HOST] + [""] * 7
    result = init([], answers=answers, tty=True)
    assert result.code == 0, result.err
    assert "IPv4" in result.err
    assert result.prompts.count("Router IPv4 address [192.168.50.1]: ") == 2


def test_three_bad_answers_stop(init, paths):
    result = init([], answers=["", "x", "y", "z"], tty=True)
    assert result.code == 2
    assert not (paths / "etc").exists()


def test_end_of_input_stops(init, paths):
    result = init([], answers=[""], tty=True)
    assert result.code == 2
    assert "flags" in result.err


def test_the_existing_files_stop_before_any_more_questions(init, paths):
    etc = paths / "etc"
    etc.mkdir()
    (etc / "config.toml").write_text("keep\n")
    result = init([], answers=[""] * 10, tty=True)
    assert result.code == 1
    assert len(result.prompts) == 1  # only the instance name was asked


# --- through the command line ---------------------------------------------------------


def test_main_runs_init_without_reading_a_config(paths, monkeypatch, capsys):
    monkeypatch.setenv("AIMESH_PROXY_CONFIG", str(paths / "missing.toml"))
    monkeypatch.setattr(sys, "stdin", io.StringIO(PASSWORD + "\n"))
    argv = [
        "init",
        "--host",
        HOST,
        "--password-stdin",
        "--output-dir",
        str(paths / "e"),
    ]
    assert cli.main(argv) == 0
    assert "Next steps" in capsys.readouterr().out
    assert load(paths / "e").asus.host == HOST


def test_main_refuses_a_config_flag_for_init(paths, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["-c", str(paths / "x.toml"), "init", "--host", HOST])
    assert exc.value.code == 2
    assert "--output-dir" in capsys.readouterr().err


def test_help_lists_init(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    assert "init" in capsys.readouterr().out


def test_init_help_names_every_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["init", "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for flag in (
        "--host",
        "--port",
        "--username",
        "--password-stdin",
        "--instance",
        "--port-base",
        "--mode",
        "--nodes",
        "--sys-name",
        "--librenms-url",
        "--librenms-ca",
        "--output-dir",
        "--detect",
        "--yes",
        "--dry-run",
        "--force",
    ):
        assert flag in out, flag


def test_next_steps_walk_through_the_onboarding(init, paths):
    etc = paths / "out"
    result = init(flags(etc, "--librenms-url", "https://192.168.50.10"))
    steps = result.out.split("Next steps")[1]
    order = [
        "install.sh",
        "discover --pin-cert",
        "check-config",
        "selftest",
        "systemctl enable --now",
        "librenms_token",
        "onboard --apply",
    ]
    positions = [steps.index(word) for word in order]
    assert positions == sorted(positions)
    assert f"1. move the files to {paths / 'etc'}" in steps  # what install.sh reads
    assert f"-c {paths / 'etc' / 'config.toml'}" in steps


def test_render_config_is_valid_toml_for_every_mode(paths):
    import tomllib

    for mode in configure.MODES:
        plan = configure.Plan(
            host=HOST,
            port=8443,
            username="admin",
            state_dir="/var/lib/x",
            port_base=16101,
            mode=mode,
            nodes=("192.168.50.2",) if mode == "aimesh" else (),
        )
        doc = tomllib.loads(configure.render_config(plan))
        assert ("nodes" in doc) == (mode == "aimesh")


# --- edges ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [["--port", "x"], ["--librenms-url", "https://[bad"]],
)
def test_unparsable_values_are_usage_errors(init, paths, argv):
    with pytest.raises(SystemExit) as exc:
        init(flags(paths / "etc", *argv))
    assert exc.value.code == 2


def test_install_sh_placeholders_are_replaced_with_force(init, paths):
    etc = paths / "etc"
    etc.mkdir()
    for name in ("config.toml", "asus_password", "snmp_community", "asus_router.pem"):
        (etc / name).touch(mode=0o600)
    result = init(flags(etc, "--force"))
    assert result.code == 0, result.err
    assert (etc / "asus_router.pem").read_text() == ""  # left for discover --pin-cert
    assert "--pin-cert" in result.out


def test_duplicate_nodes_are_a_config_error(init, paths):
    result = init(flags(paths / "etc", "--nodes", "192.168.50.2,192.168.50.2"))
    assert result.code == 78
    assert "nodes.expected" in result.err
    assert not (paths / "etc").exists()


def test_a_check_after_the_install_reports_its_error(init, paths, monkeypatch):
    calls = []
    real = configure.load_secrets

    def load_secrets(cfg):
        calls.append(cfg.source)
        if len(calls) > 1:
            raise configure.ConfigError("asus.password_file: owned by uid 99")
        return real(cfg)

    monkeypatch.setattr(configure, "load_secrets", load_secrets)
    result = init(flags(paths / "etc"))
    assert result.code == 78
    assert "owned by uid 99" in result.err
    assert calls == [
        paths / "tmp" / calls[0].parent.name / "config.toml",
        paths / "etc" / "config.toml",
    ]


def test_a_failed_write_leaves_no_temp_file(init, paths):
    etc = paths / "etc"
    (etc / "snmp_community").mkdir(parents=True)  # a folder where the file goes
    result = init(flags(etc, "--force"))
    assert result.code == 1
    assert "snmp_community" in result.err
    assert not [p for p in etc.iterdir() if p.name.endswith(".tmp")]


@pytest.mark.parametrize("kind", ["folder", "large"])
def test_librenms_ca_must_be_a_small_file(init, paths, kind):
    source = paths / "lnms.pem"
    if kind == "folder":
        source.mkdir()
    else:
        source.write_bytes(b"x" * 70000)
    argv = flags(paths / "etc", "--librenms-url", "https://192.168.50.10")
    result = init([*argv, "--librenms-ca", str(source)])
    assert result.code == 1
    assert str(source) in result.err


def test_an_unreadable_output_folder_is_reported(init, paths):
    if os.geteuid() == 0:
        pytest.skip("root reads every folder")
    locked = paths / "locked"
    locked.mkdir(mode=0)
    try:
        result = init(flags(locked / "etc"))
    finally:
        locked.chmod(0o700)
    assert result.code == 1
    assert "run as root" in result.err


def test_a_clashing_port_base_answer_is_asked_again(init, paths):
    write_sibling(paths / "etc", "", "[snmp]\nport_base = 16101\n")
    # instance, host, port, user, type, detect, sysName, port base x2, URL
    answers = ["ap1", "", "", "", "", "", "", "16150", "16401", ""]
    result = init([], answers=answers, tty=True)
    assert result.code == 0, result.err
    assert "overlaps" in result.err
    assert load(paths / "etc" / "ap1").snmp.port_base == 16401


def test_a_bad_yes_or_no_is_asked_again(init, paths):
    answers = ["", "", "", "", "", "maybe", "n", "", "", ""]
    result = init([], answers=answers, tty=True)
    assert result.code == 0, result.err
    assert "expected y or n" in result.err


def test_a_late_certificate_answer_still_refuses_an_existing_copy(
    init, paths, router_cert
):
    etc = paths / "etc"
    etc.mkdir()
    (etc / "librenms.pem").write_text("keep\n")
    source = paths / "lnms.pem"
    source.write_text(router_cert.cert_pem)
    answers = [
        "",
        "",
        "",
        "",
        "standalone",
        "",
        "",
        "https://192.168.50.10",
        str(source),
    ]
    result = init([], answers=answers, tty=True)
    assert result.code == 1
    assert "librenms.pem" in result.err
    assert (etc / "librenms.pem").read_text() == "keep\n"


def test_a_sibling_whose_snmp_is_no_table_has_the_default_port_base(paths):
    path = paths / "c.toml"
    path.write_text("snmp = 5\n")
    assert configure.port_base_of(path) == 16101
    path.write_text('[snmp]\nport_base = "16101"\n')
    assert configure.port_base_of(path) is None


def test_no_free_port_base_left():
    bases = {Path(str(b)): b for b in range(16101, 65281, 100)}
    with pytest.raises(configure.InitError, match="--port-base"):
        configure.free_port_base(bases)


# --- install.sh's seed ----------------------------------------------------------------

EXAMPLE = Path(__file__).resolve().parents[2] / "config.example.toml"


def seed_folder(folder, instance=None):
    """What install.sh leaves behind: its seeded config.toml, empty secret files."""
    text = EXAMPLE.read_text()
    if instance:
        line = 'state_dir = "/var/lib/aimesh-snmp-proxy"\n'
        assert line in text
        text = text.replace(
            line, f'state_dir = "/var/lib/aimesh-snmp-proxy-{instance}"\n'
        )
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "config.toml").write_text(text)
    for name in ("asus_password", "snmp_community", "asus_router.pem"):
        (folder / name).touch(mode=0o600)


def test_the_seed_digest_matches_the_example():
    digest = configure.seed_digest(EXAMPLE.read_text())
    assert digest in configure.SEED_DIGESTS, (
        f"config.example.toml changed: add {digest} to configure.SEED_DIGESTS"
    )


def test_an_untouched_install_sh_seed_is_replaced_without_force(init, paths):
    etc = paths / "etc"
    seed_folder(etc)
    result = init(flags(etc))
    assert result.code == 0, result.err
    placeholders = "asus_password, snmp_community, config.toml"
    assert f"replaced install.sh's placeholders: {placeholders}" in result.out
    assert "\nreplaced:" not in result.out
    assert "LibreNMS" not in result.err  # no old community to update
    assert load(etc).asus.host == HOST
    assert (etc / "asus_router.pem").read_text() == ""  # left for discover --pin-cert


def test_an_untouched_instance_seed_is_replaced_without_force(init, paths):
    seed_folder(paths / "etc" / "lab", "lab")
    result = init(["--host", HOST, "--password-stdin", "--instance", "lab"])
    assert result.code == 0, result.err
    assert load(paths / "etc" / "lab").state_dir == Path(f"{paths / 'state'}-lab")


def test_a_seed_for_another_instance_is_kept(init, paths):
    seed_folder(paths / "etc" / "lab", "other")
    result = init(["--host", HOST, "--password-stdin", "--instance", "lab"])
    assert result.code == 1
    assert "config.toml" in result.err


@pytest.mark.parametrize(
    ("name", "body"),
    [("config.toml", None), ("asus_password", "filled in\n")],
)
def test_a_touched_seed_still_needs_force(init, paths, name, body):
    etc = paths / "etc"
    seed_folder(etc)
    path = etc / name
    path.write_text(body if body is not None else path.read_text() + "# my note\n")
    result = init(flags(etc))
    assert result.code == 1
    assert f"already holds {name}" in result.err
    assert "--force" in result.err


def test_a_link_to_an_empty_file_is_no_placeholder(init, paths):
    etc = paths / "etc"
    etc.mkdir()
    (paths / "empty").touch()
    (etc / "asus_password").symlink_to(paths / "empty")
    result = init(flags(etc))
    assert result.code == 1
    assert "asus_password" in result.err


def test_a_config_that_is_no_text_is_no_placeholder(init, paths):
    etc = paths / "etc"
    etc.mkdir()
    (etc / "config.toml").write_bytes(b"\xff\xfe not utf-8\n")
    result = init(flags(etc))
    assert result.code == 1
    assert "already holds config.toml" in result.err
