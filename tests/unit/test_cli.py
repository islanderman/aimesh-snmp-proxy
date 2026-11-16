import logging
import os
import subprocess
import sys
import types

import pytest

from aimesh_snmp_proxy import __main__ as cli
from aimesh_snmp_proxy import __version__, logsafe
from aimesh_snmp_proxy.config import Config

END = "-----END CERTIFICATE-----\n"


@pytest.fixture(autouse=True)
def fresh_registry(monkeypatch):
    monkeypatch.setattr(logsafe, "_literals", logsafe._Literals())


@pytest.fixture
def root_logger():
    root = logging.getLogger()
    saved_level, saved_handlers = root.level, list(root.handlers)
    saved_filters = [list(h.filters) for h in saved_handlers]
    yield root
    for handler in list(root.handlers):
        if handler not in saved_handlers:
            root.removeHandler(handler)
    for handler, filters in zip(saved_handlers, saved_filters, strict=True):
        handler.filters[:] = filters
    root.setLevel(saved_level)
    logging.captureWarnings(False)


@pytest.fixture
def config_path(make_config, base_config):
    return make_config(base_config)


@pytest.fixture
def fake_command(monkeypatch):
    """Point the ``run`` command at an in-memory module."""
    module = types.ModuleType("aimesh_snmp_proxy._fake_cmd")
    monkeypatch.setitem(sys.modules, module.__name__, module)
    monkeypatch.setitem(cli.COMMANDS, "run", (module.__name__, "cli_run", "fake"))
    return module


def test_check_config_reports_a_valid_setup(
    config_path, tmp_path, capsys, router_cert, canaries
):
    assert cli.main(["--config", str(config_path), "check-config"]) == 0
    out, err = capsys.readouterr()
    assert out.splitlines() == [
        f"config ok: {config_path}",
        f"router: 192.168.50.1 port 8443 over HTTPS, pin {router_cert.fingerprint}",
        "snmp: 127.0.0.1, root port 16101, v2c community file, v3 off",
        "nodes: 10 expected (ports 16102-16111), 0 override(s)",
        "collector: root_only, stale after 180 s",
        f"state: {tmp_path / 'state'}",
        "ports.json: none pinned yet",
        "secret files: 2 ok (owner-only)",
    ]
    assert err == ""
    for value in canaries.values():
        assert value not in out


def test_check_config_writes_nothing_and_keeps_temp_files(
    make_config, base_config, tmp_path, capsys
):
    path = make_config(base_config)
    assert cli.main(["--config", str(path), "check-config"]) == 0
    assert not (tmp_path / "state").exists()
    state = tmp_path / "state"
    state.mkdir()
    in_flight = state / ".ports.json.w1r2.tmp"
    in_flight.write_text("{")
    assert cli.main(["--config", str(path), "check-config"]) == 0
    assert sorted(p.name for p in state.iterdir()) == [in_flight.name]
    capsys.readouterr()


def test_check_config_mentions_v3_and_explicit_router_port(
    make_config, base_config, v3_table, capsys
):
    del base_config["snmp"]["community_file"]
    base_config["snmp"]["v3"] = v3_table
    base_config["asus"]["port"] = 443
    base_config["override"] = [{"match": "192.168.50.101", "sys_name": "office"}]
    path = make_config(base_config)
    assert cli.main(["-c", str(path), "check-config"]) == 0
    out = capsys.readouterr().out
    assert "router: 192.168.50.1 port 443 over HTTPS" in out
    assert "v2c off, v3 user librenms SHA-256/AES-128" in out
    assert ", 1 override(s)" in out


# --- asus.node_ca_file --------------------------------------------------------------


@pytest.mark.parametrize(
    ("mode", "note"),
    [
        ("per_node", "per_node sessions check each node's IP"),
        ("root_only", "unused: collector.mode is root_only"),
    ],
)
def test_check_config_shows_the_node_ca_pin(
    make_config, base_config, write_file, node_ca, capsys, mode, note
):
    write_file("asus_node_ca.pem", node_ca.cert_pem, 0o644)
    base_config["asus"]["node_ca_file"] = "asus_node_ca.pem"
    base_config["collector"] = {"mode": mode}
    assert cli.main(["-c", str(make_config(base_config)), "check-config"]) == 0
    out = capsys.readouterr().out
    assert f"node CA: {node_ca.fingerprint} ({note})" in out


@pytest.mark.parametrize(
    ("content", "file_mode", "error"),
    [
        (None, 0o644, "file not found"),
        ("node_ca", 0o664, "writable by group or others"),
        ("leaf", 0o644, "is not a CA certificate"),
    ],
)
def test_check_config_refuses_a_bad_node_ca_pin_before_start(
    make_config,
    base_config,
    write_file,
    node_ca,
    node_leaf,
    capsys,
    content,
    file_mode,
    error,
):
    if content is not None:
        pem = {
            "node_ca": node_ca.cert_pem,
            "leaf": node_leaf.cert_pem.split(END)[0] + END,
        }
        write_file("asus_node_ca.pem", pem[content], file_mode)
    base_config["asus"]["node_ca_file"] = "asus_node_ca.pem"
    assert cli.main(["-c", str(make_config(base_config)), "check-config"]) == 78
    out, err = capsys.readouterr()
    assert out == ""
    assert err.startswith("config error: asus.node_ca_file: ")
    assert error in err


@pytest.mark.parametrize(
    ("mode", "note"),
    [
        ("per_node", "per_node: that node's exact certificate, by any name"),
        ("root_only", "unused: collector.mode is root_only"),
    ],
)
def test_check_config_shows_each_override_leaf_pin(
    make_config, base_config, write_file, old_node_cert, capsys, mode, note
):
    write_file("node-104.pem", old_node_cert.cert_pem, 0o644)
    base_config["override"] = [
        {"match": "192.168.50.103", "login": False},
        {"match": "00:00:5e:00:53:44", "ca_file": "node-104.pem"},
    ]
    base_config["collector"] = {"mode": mode}
    assert cli.main(["-c", str(make_config(base_config)), "check-config"]) == 0
    out = capsys.readouterr().out
    assert f"node pin: override[1] {old_node_cert.fingerprint} ({note})" in out
    assert "00:00:5e" not in out  # check-config shows no MACs


@pytest.mark.parametrize(
    ("content", "file_mode", "error"),
    [
        (None, 0o644, "file not found"),
        ("cert", 0o664, "writable by group or others"),
        ("key", 0o644, "contains a private key"),
    ],
)
def test_check_config_refuses_a_bad_override_leaf_pin(
    make_config,
    base_config,
    write_file,
    old_node_cert,
    capsys,
    content,
    file_mode,
    error,
):
    if content is not None:
        pem = old_node_cert.cert_pem + (
            old_node_cert.key_pem if content == "key" else ""
        )
        write_file("node-104.pem", pem, file_mode)
    base_config["override"] = [{"match": "192.168.50.104", "ca_file": "node-104.pem"}]
    assert cli.main(["-c", str(make_config(base_config)), "check-config"]) == 78
    out, err = capsys.readouterr()
    assert out == ""
    assert err.startswith("config error: override[0].ca_file: ")
    assert error in err


def test_check_config_rejects_invalid_config(make_config, base_config, capsys):
    base_config["asus"]["use_ssl"] = False
    path = make_config(base_config)
    assert cli.main(["--config", str(path), "check-config"]) == cli.EXIT_CONFIG
    out, err = capsys.readouterr()
    assert out == ""
    assert err.startswith("config error: asus.use_ssl: must be true")


def test_check_config_refuses_loose_secret_file(
    config_path, tmp_path, capsys, canaries
):
    os.chmod(tmp_path / "snmp_community", 0o640)
    assert cli.main(["--config", str(config_path), "check-config"]) == 78
    err = capsys.readouterr().err
    assert "snmp.community_file" in err
    assert "run chmod 600" in err
    assert canaries["snmp_community"] not in err


def test_check_config_refuses_bad_router_pin(config_path, tmp_path, capsys):
    (tmp_path / "router.pem").write_text("not a cert")
    assert cli.main(["--config", str(config_path), "check-config"]) == 78
    assert "asus.ca_file" in capsys.readouterr().err


def test_check_config_missing_file(tmp_path, capsys):
    assert cli.main(["--config", str(tmp_path / "nope.toml"), "check-config"]) == 78
    assert "config file not found" in capsys.readouterr().err


def test_check_config_takes_no_arguments(config_path, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--config", str(config_path), "check-config", "extra"])
    assert exc.value.code == 2
    assert "unrecognized arguments: extra" in capsys.readouterr().err


def test_config_path_defaults_to_environment(config_path, monkeypatch, capsys):
    monkeypatch.setenv(cli.CONFIG_ENV, str(config_path))
    assert cli.main(["check-config"]) == 0
    assert capsys.readouterr().out.startswith(f"config ok: {config_path}")


def test_config_path_default(monkeypatch):
    monkeypatch.delenv(cli.CONFIG_ENV, raising=False)
    args, _ = cli.build_parser().parse_known_args(["check-config"])
    assert cli.config_path(args) is None
    args, _ = cli.build_parser().parse_known_args(["run", "-c", "/x.toml"])
    assert cli.config_path(args) == cli.Path("/x.toml")


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"aimesh-snmp-proxy {__version__}"


def test_a_command_is_required(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main([])
    assert exc.value.code == 2


def test_lazy_commands_map_to_their_packages():
    modules = {command: module for command, (module, _, _) in cli.COMMANDS.items()}
    assert modules == {
        "init": "aimesh_snmp_proxy.ops.configure",
        "run": "aimesh_snmp_proxy.ops",
        "selftest": "aimesh_snmp_proxy.ops",
        "onboard": "aimesh_snmp_proxy.ops",
        "discover": "aimesh_snmp_proxy.collector",
        "dump-snmprec": "aimesh_snmp_proxy.profiles",
    }
    for command, (_, handler, _) in cli.COMMANDS.items():
        assert handler == "cli_" + command.replace("-", "_")


@pytest.mark.parametrize("command", sorted(cli.COMMANDS))
def test_every_lazy_command_is_on_the_parser(command):
    args, rest = cli.build_parser().parse_known_args([command, "--some-flag", "x"])
    assert args.command == command
    assert rest == ["--some-flag", "x"]


def test_missing_module_means_not_implemented(monkeypatch, capsys):
    monkeypatch.setitem(
        cli.COMMANDS, "run", ("aimesh_snmp_proxy._absent_for_test", "cli_run", "x")
    )
    assert cli.main(["run"]) == cli.EXIT_NOT_IMPLEMENTED == 2
    assert capsys.readouterr().err == "run: not implemented yet\n"


def test_missing_handler_means_not_implemented(fake_command, capsys):
    assert cli.main(["run", "--help"]) == 2
    assert "run: not implemented yet" in capsys.readouterr().err


def test_broken_dependency_is_not_hidden(fake_command, monkeypatch):
    def broken_import(name):
        raise ModuleNotFoundError("No module named 'aiohttp'", name="aiohttp")

    monkeypatch.setattr(cli.importlib, "import_module", broken_import)
    with pytest.raises(ModuleNotFoundError, match="aiohttp"):
        cli.main(["run"])


def test_lazy_command_gets_config_and_its_own_arguments(
    fake_command, config_path, root_logger
):
    calls = []

    def cli_run(config, argv):
        calls.append((config, argv))
        logging.getLogger("t").info("started")
        return 5

    fake_command.cli_run = cli_run
    code = cli.main(["--config", str(config_path), "run", "--once", "-v"])
    assert code == 5
    ((config, argv),) = calls
    assert isinstance(config, Config)
    assert config.source == config_path
    assert argv == ["--once", "-v"]
    assert any(
        isinstance(h.formatter, logsafe.JsonFormatter) for h in root_logger.handlers
    )


def test_lazy_command_with_bad_config_exits_78(fake_command, tmp_path, capsys):
    fake_command.cli_run = lambda config, argv: 0
    assert cli.main(["--config", str(tmp_path / "missing.toml"), "run"]) == 78
    assert capsys.readouterr().err.startswith("config error: config file not found")


def test_python_dash_m_entry_point():
    result = subprocess.run(
        [sys.executable, "-m", "aimesh_snmp_proxy", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == f"aimesh-snmp-proxy {__version__}"


def test_capture_fixtures_is_folded_into_discover(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["capture-fixtures"])
    assert exc.value.code == 2
    assert "invalid choice: 'capture-fixtures'" in capsys.readouterr().err


def test_check_config_counts_pinned_ports_without_touching_temp_files(
    config_path, tmp_path, capsys
):
    from aimesh_snmp_proxy.ports import PortMap

    state = tmp_path / "state"
    pm = PortMap.load(state / "ports.json", 16101, ["192.168.50.101"])
    pm.assign("00:00:5e:00:53:0a", ip="192.168.50.101")
    pm.assign("00:00:5e:00:53:0b", ip="192.168.50.50")
    in_flight = state / ".ports.json.abcd.tmp"
    in_flight.write_text("{}")
    assert cli.main(["-c", str(config_path), "check-config"]) == 0
    out = capsys.readouterr().out
    assert "ports.json: 2 pinned (ports 16102-16103)" in out
    assert "00:00:5e" not in out
    assert in_flight.exists()


def test_check_config_refuses_a_corrupt_ports_file(config_path, tmp_path, capsys):
    state = tmp_path / "state"
    state.mkdir()
    (state / "ports.json").write_text("{broken")
    assert cli.main(["-c", str(config_path), "check-config"]) == 78
    err = capsys.readouterr().err
    assert err.startswith("state error: ")
    assert "ports.json: not valid JSON" in err


def test_config_option_after_the_command(config_path, capsys):
    assert cli.main(["check-config", "--config", str(config_path)]) == 0
    assert capsys.readouterr().out.startswith(f"config ok: {config_path}")


def test_lazy_command_takes_config_after_the_command(
    fake_command, config_path, root_logger
):
    calls = []
    fake_command.cli_run = lambda config, argv: calls.append((config, argv)) or 0
    assert cli.main(["run", "--config", str(config_path), "--once"]) == 0
    ((config, argv),) = calls
    assert config.source == config_path
    assert argv == ["--once"]


def test_config_after_the_command_wins(fake_command, config_path, root_logger):
    calls = []
    fake_command.cli_run = lambda config, argv: calls.append(config) or 0
    assert cli.main(["-c", "/nonexistent.toml", "run", "-c", str(config_path)]) == 0
    assert calls[0].source == config_path


@pytest.fixture
def fake_dump(monkeypatch):
    module = types.ModuleType("aimesh_snmp_proxy._fake_dump")
    calls = []
    module.cli_dump_snmprec = lambda config, argv: calls.append((config, argv)) or 0
    monkeypatch.setitem(sys.modules, module.__name__, module)
    monkeypatch.setitem(
        cli.COMMANDS, "dump-snmprec", (module.__name__, "cli_dump_snmprec", "fake")
    )
    return calls


def test_dump_snmprec_needs_no_config(fake_dump, monkeypatch, root_logger):
    monkeypatch.delenv(cli.CONFIG_ENV, raising=False)
    assert cli.main(["dump-snmprec", "fixture.json"]) == 0
    assert fake_dump == [(None, ["fixture.json"])]


def test_dump_snmprec_loads_an_explicit_config(
    fake_dump, config_path, monkeypatch, root_logger
):
    monkeypatch.delenv(cli.CONFIG_ENV, raising=False)
    assert cli.main(["dump-snmprec", "-c", str(config_path)]) == 0
    monkeypatch.setenv(cli.CONFIG_ENV, str(config_path))
    assert cli.main(["dump-snmprec"]) == 0
    assert [config.source for config, _ in fake_dump] == [config_path, config_path]


def test_dump_snmprec_with_a_bad_explicit_config(fake_dump, tmp_path, capsys):
    assert cli.main(["dump-snmprec", "-c", str(tmp_path / "nope.toml")]) == 78
    assert fake_dump == []


def test_check_config_leaves_onboard_files_to_onboard(make_config, base_config, capsys):
    base_config["onboard"] = {
        "url": "https://192.168.50.10",
        "token_file": "missing_token",
        "ca_file": "missing.pem",
    }
    path = make_config(base_config)
    assert cli.main(["-c", str(path), "check-config"]) == 0
    out = capsys.readouterr().out
    assert (
        "onboard: https://192.168.50.10 (onboard checks its token and ca_file)" in out
    )
    assert "secret files: 2 ok (owner-only)" in out


def test_config_required_commands_fall_back_to_the_default_path(
    fake_command, config_path, monkeypatch, root_logger
):
    monkeypatch.delenv(cli.CONFIG_ENV, raising=False)
    monkeypatch.setattr(cli, "DEFAULT_CONFIG", config_path)
    calls = []
    fake_command.cli_run = lambda config, argv: calls.append(config) or 0
    assert cli.main(["run"]) == 0
    assert calls[0].source == config_path
