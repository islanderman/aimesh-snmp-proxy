"""Static checks of deploy/aimesh-snmp-proxy.service; a dev machine may lack systemd."""

from __future__ import annotations

import re
import shlex
import tomllib
from pathlib import Path

import pytest

from aimesh_snmp_proxy import __main__ as cli
from aimesh_snmp_proxy.config import DEFAULT_STATE_DIR

# Names checked against systemd's load-fragment-gperf.gperf.in. systemd ignores an
# unknown name, so a typo would silently drop a hardening setting.
_KNOWN_NAMES = """After AmbientCapabilities CapabilityBoundingSet Description
    DynamicUser ExecStart IPAddressAllow IPAddressDeny LoadCredential LockPersonality
    MemoryDenyWriteExecute MemoryMax NoNewPrivileges PrivateDevices PrivateTmp
    ProcSubset ProtectClock ProtectControlGroups ProtectHome ProtectHostname
    ProtectKernelLogs ProtectKernelModules ProtectKernelTunables ProtectProc
    ProtectSystem RemoveIPC Restart RestartPreventExitStatus RestartSec
    RestrictAddressFamilies RestrictNamespaces RestrictRealtime RestrictSUIDSGID
    StartLimitBurst StartLimitIntervalSec StateDirectory StateDirectoryMode
    SyslogIdentifier SystemCallArchitectures SystemCallFilter TasksMax
    TimeoutStopSec Type UMask WantedBy Wants"""
KNOWN_DIRECTIVES = frozenset(_KNOWN_NAMES.split())

REQUIRED = {
    "DynamicUser": "yes",
    "StateDirectory": "aimesh-snmp-proxy",
    "Restart": "on-failure",
    "RestartPreventExitStatus": "78",
    "NoNewPrivileges": "yes",
    "CapabilityBoundingSet": "",
    "ProtectSystem": "strict",
    "ProtectHome": "yes",
    "PrivateTmp": "yes",
    "PrivateDevices": "yes",
    "ProtectKernelTunables": "yes",
    "ProtectKernelModules": "yes",
    "ProtectKernelLogs": "yes",
    "ProtectControlGroups": "yes",
    "ProtectProc": "invisible",
    "ProcSubset": "pid",
    "RestrictAddressFamilies": "AF_INET AF_INET6 AF_UNIX",
    "RestrictNamespaces": "yes",
    "LockPersonality": "yes",
    "MemoryDenyWriteExecute": "yes",
    "SystemCallFilter": "@system-service",
    "UMask": "0077",
    "IPAddressDeny": "any",
}

ETC = "/etc/aimesh-snmp-proxy"


@pytest.fixture(scope="module")
def text(deploy_dir: Path) -> str:
    return (deploy_dir / "aimesh-snmp-proxy.service").read_text()


@pytest.fixture(scope="module")
def unit(text, unit_parser):
    return unit_parser(text)


def values(unit, section: str, key: str) -> list[str]:
    return [v for k, v in unit[section] if k == key]


def test_syntax_and_sections(unit):
    assert list(unit) == ["Unit", "Service", "Install"]


def test_every_directive_is_a_known_systemd_name(unit):
    used = {key for entries in unit.values() for key, _ in entries}
    assert used - KNOWN_DIRECTIVES == set()


@pytest.mark.parametrize(("key", "expected"), REQUIRED.items())
def test_required_hardening(unit, key, expected):
    assert values(unit, "Service", key) == [expected]


def test_no_environment_file_anywhere(text):
    assert "EnvironmentFile" not in text


def test_no_secret_in_environment(unit):
    keys = {key for entries in unit.values() for key, _ in entries}
    assert not keys & {"Environment", "PassEnvironment", "SetCredential"}


def test_credentials_cover_every_file_the_example_config_names(unit, repo):
    with (repo / "config.example.toml").open("rb") as fh:
        example = tomllib.load(fh)
    needed = {
        "config.toml",
        example["asus"]["password_file"],
        example["asus"]["ca_file"],
        example["snmp"]["community_file"],
    }
    loaded = {}
    for value in values(unit, "Service", "LoadCredential"):
        name, _, path = value.partition(":")
        loaded[name] = path
    assert set(loaded) == needed
    assert all(path == f"{ETC}/{name}" for name, path in loaded.items())


def test_exec_start_is_accepted_by_the_real_cli(unit, tmp_path):
    (line,) = values(unit, "Service", "ExecStart")
    assert line.startswith("@PREFIX@/venv/bin/python ")
    argv = shlex.split(line.replace("${CREDENTIALS_DIRECTORY}", str(tmp_path)))
    argv = argv[argv.index("-m") + 2 :]
    args, rest = cli.build_parser().parse_known_args(argv)
    assert (args.command, rest) == ("run", [])
    assert args.config == tmp_path / "config.toml"


def test_python_runs_isolated(unit):
    (line,) = values(unit, "Service", "ExecStart")
    flags = line.split(" -m ")[0].split()[1:]
    assert "-I" in flags


def test_restart_prevention_matches_the_cli_config_exit_code(unit):
    assert values(unit, "Service", "RestartPreventExitStatus") == [str(cli.EXIT_CONFIG)]


def test_state_directory_is_the_default_state_dir(unit):
    (name,) = values(unit, "Service", "StateDirectory")
    assert Path("/var/lib") / name == DEFAULT_STATE_DIR


def test_restarts_cannot_hammer_the_router(unit):
    (delay,) = values(unit, "Service", "RestartSec")
    (burst,) = values(unit, "Unit", "StartLimitBurst")
    (window,) = values(unit, "Unit", "StartLimitIntervalSec")
    assert int(delay) >= 30
    assert int(burst) <= 5
    assert int(window) >= 600


def test_only_loopback_and_the_template_slot_may_be_reached(unit):
    assert values(unit, "Service", "IPAddressAllow") == ["@IP_ALLOW@"]


def test_placeholders_are_exactly_prefix_and_ip_allow(text):
    assert set(re.findall(r"@[A-Z_]+@", text)) == {"@PREFIX@", "@IP_ALLOW@"}


def test_no_specifier_that_systemd_before_251_lacks(unit):
    # %d (credentials directory) arrived in systemd 251; credentials in 247.
    found = {
        match
        for entries in unit.values()
        for _, value in entries
        for match in re.findall(r"%[A-Za-z%]", value)
    }
    assert found == set()


def test_exec_start_reads_the_config_from_the_credentials_directory(unit):
    (line,) = values(unit, "Service", "ExecStart")
    assert "--config ${CREDENTIALS_DIRECTORY}/config.toml run" in line


def test_comment_blocks_stay_within_three_lines(text, comment_run_finder):
    assert [run for run in comment_run_finder(text) if run[1] > 3] == []
