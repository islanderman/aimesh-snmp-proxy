"""Static checks of deploy/aimesh-snmp-proxy@.service, the one-instance-per-router unit.

A dev machine may lack systemd, so these read the file the way systemd would and compare
it with the single unit: a template may differ only where an instance needs it to.
"""

from __future__ import annotations

import re
import shlex
import tomllib
from pathlib import Path

import pytest

from aimesh_snmp_proxy import __main__ as cli

ETC = "/etc/aimesh-snmp-proxy"
# What an instance must do differently from the single unit; all else is shared.
DIFFERS = {"StateDirectory", "LoadCredential", "IPAddressAllow", "SyslogIdentifier"}


@pytest.fixture(scope="module")
def text(deploy_dir: Path) -> str:
    return (deploy_dir / "aimesh-snmp-proxy@.service").read_text()


@pytest.fixture(scope="module")
def unit(text, unit_parser):
    return unit_parser(text)


@pytest.fixture(scope="module")
def single(deploy_dir: Path, unit_parser):
    return unit_parser((deploy_dir / "aimesh-snmp-proxy.service").read_text())


def values(unit, section: str, key: str) -> list[str]:
    return [v for k, v in unit[section] if k == key]


def test_syntax_and_sections(unit):
    assert list(unit) == ["Unit", "Service", "Install"]


def test_every_hardening_line_of_the_single_unit_is_kept(unit, single):
    for section in ("Unit", "Service", "Install"):
        for key in {k for k, _ in single[section]} - DIFFERS - {"Description"}:
            assert values(unit, section, key) == values(single, section, key), key


def test_the_template_adds_no_directive_the_single_unit_lacks(unit, single):
    for section in single:
        extra = {k for k, _ in unit[section]} - {k for k, _ in single[section]}
        assert extra == set(), section


def test_each_instance_has_its_own_state_directory(unit):
    (name,) = values(unit, "Service", "StateDirectory")
    # A directory below the single unit's would sit inside a 0700 tree of another user.
    assert name == "aimesh-snmp-proxy-%i"
    assert values(unit, "Service", "DynamicUser") == ["yes"]


def test_each_instance_loads_its_own_credentials(unit, repo):
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
    assert all(path == f"{ETC}/%i/{name}" for name, path in loaded.items())


def test_the_only_specifier_is_the_instance_name(text, unit):
    # %i keeps hyphens as they are; %I would turn each into a slash.
    found = {
        match
        for entries in unit.values()
        for _, value in entries
        for match in re.findall(r"%[A-Za-z%]", value)
    }
    assert found == {"%i"}
    assert "%I" not in text


def test_the_ip_allow_list_starts_at_loopback_and_install_adds_the_router(unit):
    assert values(unit, "Service", "IPAddressDeny") == ["any"]
    assert values(unit, "Service", "IPAddressAllow") == ["localhost"]


def test_the_only_placeholder_is_the_prefix(text):
    assert set(re.findall(r"@[A-Z_]+@", text)) == {"@PREFIX@"}


def test_exec_start_is_accepted_by_the_real_cli(unit, tmp_path):
    (line,) = values(unit, "Service", "ExecStart")
    assert line.startswith("@PREFIX@/venv/bin/python ")
    argv = shlex.split(line.replace("${CREDENTIALS_DIRECTORY}", str(tmp_path)))
    argv = argv[argv.index("-m") + 2 :]
    args, rest = cli.build_parser().parse_known_args(argv)
    assert (args.command, rest) == ("run", [])
    assert args.config == tmp_path / "config.toml"


def test_logs_carry_the_instance_name(unit):
    assert values(unit, "Service", "SyslogIdentifier") == ["aimesh-snmp-proxy-%i"]
    (description,) = values(unit, "Unit", "Description")
    assert "%i" in description


def test_no_environment_file_and_no_secret_in_environment(text, unit):
    assert "EnvironmentFile" not in text
    keys = {key for entries in unit.values() for key, _ in entries}
    assert not keys & {"Environment", "PassEnvironment", "SetCredential"}


def test_comment_blocks_stay_within_three_lines(text, comment_run_finder):
    assert [run for run in comment_run_finder(text) if run[1] > 3] == []
