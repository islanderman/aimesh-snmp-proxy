"""install.sh against a fake host: command stubs, a fake root, a fake bundle.

Nothing here needs root, systemd or a network. The slow test at the end runs the
real venv and pip against local wheels.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from aimesh_snmp_proxy.config import ConfigError, _ip_range, load_config

BASHES = sorted(
    {b for b in (shutil.which("bash"), "/bin/bash") if b and Path(b).exists()}
)
SHELLCHECK = shutil.which("shellcheck")
CANARY = "canary-secret-7f3a91"
EXAMPLE_HOST = "192.168.50.1"
CONFIG = """
[asus]
host = "{host}"
username = "admin"
password_file = "asus_password"
ca_file = "asus_router.pem"

[snmp]
community_file = "snmp_community"

[collector]
mode = "{mode}"

[nodes]
expected = {expected}
"""


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def write_config(
    host, hostname=EXAMPLE_HOST, mode_="root_only", expected='"192.168.50.101-110"'
):
    host.etc.mkdir(parents=True, exist_ok=True)
    text = CONFIG.format(host=hostname, mode=mode_, expected=expected)
    (host.etc / "config.toml").write_text(text)


def allow_line(host) -> str:
    (line,) = [
        ln
        for ln in host.unit.read_text().splitlines()
        if ln.startswith("IPAddressAllow=")
    ]
    return line


def everything_printed(host, result) -> str:
    return (
        result.stdout
        + result.stderr
        + (host.log.read_text() if host.log.exists() else "")
    )


def empty(root: Path) -> bool:
    return not any(root.rglob("*"))


# --- the scripts themselves -------------------------------------------------------


@pytest.mark.parametrize("bash", BASHES)
def test_scripts_parse_on_every_bash(deploy_dir, bash):
    for script in sorted(deploy_dir.glob("*.sh")):
        result = subprocess.run(
            [bash, "-n", str(script)], capture_output=True, text=True
        )
        assert result.returncode == 0, result.stderr


@pytest.mark.skipif(SHELLCHECK is None, reason="shellcheck not installed")
def test_scripts_are_shellcheck_clean(deploy_dir):
    scripts = [str(p) for p in sorted(deploy_dir.glob("*.sh"))]
    result = subprocess.run(
        [SHELLCHECK, "-x", *scripts], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stdout


def test_comment_blocks_stay_within_three_lines(deploy_dir, comment_run_finder):
    for script in sorted(deploy_dir.glob("*.sh")):
        runs = comment_run_finder(script.read_text())
        assert [r for r in runs if r[1] > 3] == [], script.name


def test_help_works_without_a_bundle(deploy_dir):
    result = subprocess.run(
        [BASHES[0], str(deploy_dir / "install.sh"), "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    for flag in ("--prefix", "--python", "--uninstall", "--purge", "--dry-run"):
        assert flag in result.stdout


@pytest.mark.parametrize(
    "args",
    [
        ["--bogus"],
        ["--prefix"],
        ["--purge"],
        ["--prefix", "/opt"],
        ["--prefix", "relative/path"],
        ["--prefix", "/opt/a b"],
        ["--prefix", "/opt/../etc"],
        ["--prefix", "/opt/x;rm"],
        ["--prefix", "/opt/x%y"],
    ],
)
def test_bad_usage_is_refused_before_anything_runs(host, args):
    result = host.run(*args)
    assert result.returncode == 2
    assert empty(host.root)
    assert host.calls() == []


# --- dry run ----------------------------------------------------------------------


@pytest.mark.parametrize("bash", BASHES)
def test_dry_run_changes_nothing_and_needs_no_root(host, bash):
    result = host.run("--dry-run", bash=bash, uid=1000)
    assert result.returncode == 0, result.stderr
    assert empty(host.root)
    assert "DRY RUN" in result.stdout
    assert "would write" in result.stdout
    assert "dry run complete" in result.stdout
    verbs = {c.split()[1] for c in host.calls("systemctl")}
    assert verbs <= {"--version", "is-active", "list-units"}


def test_dry_run_still_fails_the_checks_it_would_fail(host):
    result = host.run(
        "--dry-run", uid=1000, python=str(host.fake_python), FAKE_PYVER="3.9.1"
    )
    assert result.returncode == 1
    assert "3.11" in result.stderr
    assert empty(host.root)


# --- install ----------------------------------------------------------------------


@pytest.mark.parametrize("bash", BASHES)
def test_install_creates_the_expected_tree(host, repo, bash):
    result = host.run(bash=bash)
    assert result.returncode == 0, result.stderr
    assert "STAGING" in result.stdout
    assert mode(host.etc) == 0o700
    for name in ("config.toml", "asus_password", "snmp_community", "asus_router.pem"):
        assert mode(host.etc / name) == 0o600, name
    for name in ("asus_password", "snmp_community", "asus_router.pem"):
        assert (host.etc / name).read_bytes() == b"", name
    assert (host.etc / "config.toml").read_text() == (
        repo / "config.example.toml"
    ).read_text()
    assert mode(host.opt) == 0o755
    assert (host.opt / "venv" / "bin" / "python").exists()
    assert mode(host.unit) == 0o644


def test_install_renders_the_unit_for_this_host(host, unit_parser):
    assert host.run().returncode == 0
    text = host.unit.read_text()
    unit = unit_parser(text)
    service = dict(unit["Service"])
    assert not re.search(r"@[A-Z_]+@", text)
    assert service["ExecStart"].startswith("/opt/aimesh-snmp-proxy/venv/bin/python -I ")
    assert service["IPAddressAllow"] == f"localhost {EXAMPLE_HOST}"
    assert service["DynamicUser"] == "yes"
    assert "--config ${CREDENTIALS_DIRECTORY}/config.toml run" in service["ExecStart"]
    assert "User" not in service


def next_steps(stdout: str) -> list[str]:
    """The closing "Next:" list, one stripped line each."""
    return [line.strip() for line in stdout.split("Next:", 1)[1].strip().splitlines()]


def test_the_next_steps_start_with_init_and_leave_no_hand_edits(host):
    result = host.run()
    assert result.returncode == 0, result.stderr
    steps = next_steps(result.stdout)
    app = "/opt/aimesh-snmp-proxy/venv/bin/aimesh-snmp-proxy"
    assert steps[0] == f"1. sudo {app} init --detect"
    assert steps[2].startswith("2. run this script again (the unit allows only")
    assert steps[3].startswith("3. run check-config and selftest, then systemctl")
    # init replaces only untouched placeholders: a hand edit first would need --force.
    edits = [s for s in steps if "fill " in s or "edit " in s or "asus_password" in s]
    assert edits == []


def test_install_only_reloads_systemd(host):
    assert host.run().returncode == 0
    verbs = [c.split()[1] for c in host.calls("systemctl")]
    assert "daemon-reload" in verbs
    assert set(verbs) <= {"--version", "is-active", "list-units", "daemon-reload"}


def test_install_verifies_the_unit_but_a_warning_does_not_fail_it(host):
    result = host.run()
    assert result.returncode == 0
    assert f"systemd-analyze verify {host.unit}" in host.calls("systemd-analyze")
    assert "Overall exposure level" in result.stdout
    result = host.run(FAKE_VERIFY_FAIL="1")
    assert result.returncode == 0
    assert "reported the problems" in result.stderr


def test_install_hands_the_config_dir_to_root(host):
    assert host.run().returncode == 0
    assert host.calls("chown") == [f"chown -R root:root {host.etc}"]


def test_pip_runs_hash_checked_and_binary_only(host):
    assert host.run().returncode == 0
    (pip,) = [c for c in host.calls("python") if "-m pip install" in c]
    for flag in (
        "--require-hashes",
        "--only-binary=:all:",
        "--no-deps",
        "-r requirements.txt",
    ):
        assert flag in pip
    assert "--no-input" in pip
    assert any("-m pip check" in c for c in host.calls("python"))


def test_rerun_keeps_config_secrets_and_follows_the_config(host):
    assert host.run().returncode == 0
    (host.etc / "asus_password").write_text(CANARY)
    write_config(host, hostname="192.168.50.7")
    result = host.run()
    assert result.returncode == 0, result.stderr
    assert (host.etc / "asus_password").read_text() == CANARY
    assert mode(host.etc / "asus_password") == 0o600
    assert allow_line(host) == "IPAddressAllow=localhost 192.168.50.7"
    assert "kept asus_password" in result.stdout


def test_install_tightens_loose_modes(host):
    assert host.run().returncode == 0
    (host.etc / "asus_password").chmod(0o644)
    host.etc.chmod(0o755)
    assert host.run().returncode == 0
    assert mode(host.etc / "asus_password") == 0o600
    assert mode(host.etc) == 0o700


def test_no_secret_value_is_ever_printed(host):
    assert host.run().returncode == 0
    for name in ("asus_password", "snmp_community", "asus_router.pem"):
        (host.etc / name).write_text(CANARY)
    for args in (
        [],
        ["--dry-run"],
        ["--uninstall"],
        ["--uninstall", "--purge", "--yes"],
    ):
        result = host.run(*args)
        assert CANARY not in everything_printed(host, result), args


@pytest.mark.parametrize(
    ("mode_", "expected", "line"),
    [
        ("root_only", '"192.168.50.101-110"', "localhost 192.168.50.1"),
        (
            "per_node",
            '"192.168.50.101-103"',
            "localhost 192.168.50.1 192.168.50.101 192.168.50.102 192.168.50.103",
        ),
        ("per_node", '["192.168.50.9", "192.168.50.20-21"]', None),
        ("per_node", "[]", "localhost 192.168.50.1"),
    ],
)
def test_allow_list_follows_the_collector_mode(host, mode_, expected, line):
    write_config(host, mode_=mode_, expected=expected)
    assert host.run().returncode == 0
    value = allow_line(host).removeprefix("IPAddressAllow=")
    if line is not None:
        assert value == line
    else:
        assert (
            value == "localhost 192.168.50.1 192.168.50.9 192.168.50.20 192.168.50.21"
        )


def test_allow_list_accepts_an_ipv6_router(host):
    write_config(host, hostname="fd00::1")
    assert host.run().returncode == 0
    assert allow_line(host) == "IPAddressAllow=localhost fd00::1"


@pytest.mark.parametrize(
    "expected",
    [
        "192.168.50.101-110",
        "192.168.50.101",
        "192.168.50.250-255",
        "192.168.50.101-192.168.50.103",
        "198.18.0.250-198.18.1.5",
    ],
)
def test_allow_list_matches_the_apps_range_parser(host, tmp_path, expected):
    write_config(host, mode_="per_node", expected=f'"{expected}"')
    assert host.run().returncode == 0
    ours = allow_line(host).removeprefix("IPAddressAllow=").split()[2:]
    assert tuple(ours) == tuple(_ip_range(expected))
    app = load_config(host.etc / "config.toml")
    assert tuple(ours) == app.nodes.expected


@pytest.mark.parametrize(
    "expected",
    ["192.168.50.200-100", "192.168.50.1-999", "198.18.0.1-198.18.2.1", "x.y"],
)
def test_allow_list_rejects_what_the_app_rejects(host, expected):
    write_config(host, mode_="per_node", expected=f'"{expected}"')
    with pytest.raises(ConfigError):
        load_config(host.etc / "config.toml")
    result = host.run()
    assert result.returncode == 1
    assert "nodes.expected" in result.stderr
    assert not host.opt.exists()


def test_a_hostname_router_is_refused_before_any_change(host):
    write_config(host, hostname="router.asus.com")
    result = host.run()
    assert result.returncode == 1
    assert "asus.host must be an IP address" in result.stderr
    assert not host.opt.exists()
    assert not host.unit.exists()


def test_broken_toml_is_refused_before_any_change(host):
    host.etc.mkdir(parents=True)
    (host.etc / "config.toml").write_text("[asus\nhost = ")
    result = host.run()
    assert result.returncode == 1
    assert "cannot read the config" in result.stderr
    assert not host.opt.exists()


V3_TABLE = """
[snmp.v3]
user = "librenms"
auth_key_file = "snmp_auth_key"
priv_key_file = "snmp_priv_key"
"""


def edit_config(host, old: str = "", new: str = "", append: str = "") -> None:
    write_config(host)
    path = host.etc / "config.toml"
    path.write_text(path.read_text().replace(old, new) + append)


NODE_CA = 'ca_file = "asus_router.pem"\nnode_ca_file = "asus_node_ca.pem"'
NODE_CA_LINE = "asus_node_ca.pem:/etc/aimesh-snmp-proxy/asus_node_ca.pem"


def test_the_node_ca_pin_is_loaded_as_a_credential(host, unit_parser):
    edit_config(host, 'ca_file = "asus_router.pem"', NODE_CA)
    result = host.run()
    assert result.returncode == 0, result.stderr
    loads = [
        v
        for k, v in unit_parser(host.unit.read_text())["Service"]
        if k == "LoadCredential"
    ]
    assert loads[-1] == NODE_CA_LINE  # after the four the template loads
    assert len(loads) == 5
    assert "asus.node_ca_file" in result.stdout


def test_a_dry_run_reports_the_node_ca_credential(host):
    edit_config(host, 'ca_file = "asus_router.pem"', NODE_CA)
    result = host.run("--dry-run", uid=1000)
    assert result.returncode == 0, result.stderr
    assert f"LoadCredential={NODE_CA_LINE}" in result.stdout
    assert not host.unit.exists()


def test_without_a_node_ca_pin_the_unit_loads_only_its_four_credentials(
    host, unit_parser
):
    assert host.run().returncode == 0
    service = unit_parser(host.unit.read_text())["Service"]
    assert len([k for k, _ in service if k == "LoadCredential"]) == 4


@pytest.mark.parametrize("value", ["../asus_node_ca.pem", "a b.pem", "x:y.pem", "-x"])
def test_a_node_ca_value_that_is_no_plain_file_name_is_refused(host, value):
    edit_config(
        host, 'ca_file = "asus_router.pem"', NODE_CA.replace("asus_node_ca.pem", value)
    )
    result = host.run()
    assert result.returncode == 1
    assert "asus.node_ca_file must name a file" in result.stderr
    assert not host.unit.exists()


def test_an_absolute_node_ca_path_is_read_by_the_service_user(host, unit_parser):
    edit_config(
        host,
        'ca_file = "asus_router.pem"',
        NODE_CA.replace('"asus_node_ca', '"/srv/ca'),
    )
    result = host.run()
    assert result.returncode == 0, result.stderr
    assert "asus.node_ca_file is read by the service user" in result.stderr
    service = unit_parser(host.unit.read_text())["Service"]
    assert len([k for k, _ in service if k == "LoadCredential"]) == 4


def test_the_static_user_variant_loads_no_node_ca_credential(host):
    edit_config(host, 'ca_file = "asus_router.pem"', NODE_CA)
    assert host.run(systemd=245).returncode == 0
    assert "LoadCredential=asus_node_ca" not in host.unit.read_text()


LEAF_PINS = """
[[override]]
match = "00:00:5e:00:53:44"
ca_file = "node-104.pem"

[[override]]
match = "192.168.50.107"
ca_file = "/srv/node-107.pem"

[[override]]
match = "192.168.50.108"
ca_file = "asus_node_ca.pem"
"""


def test_each_override_leaf_pin_is_loaded_as_a_credential(host, unit_parser):
    edit_config(host, 'ca_file = "asus_router.pem"', NODE_CA, append=LEAF_PINS)
    result = host.run()
    assert result.returncode == 0, result.stderr
    loads = [
        v
        for k, v in unit_parser(host.unit.read_text())["Service"]
        if k == "LoadCredential"
    ]
    leaf = "node-104.pem:/etc/aimesh-snmp-proxy/node-104.pem"
    assert loads[4:] == [NODE_CA_LINE, leaf]  # each file once, after the four
    assert "override[0].ca_file loads as credential node-104.pem" in result.stdout
    assert "override[1].ca_file is read by the service user" in result.stderr


def test_a_dry_run_reports_each_leaf_pin_credential(host):
    edit_config(host, append=LEAF_PINS)
    result = host.run("--dry-run", uid=1000)
    assert result.returncode == 0, result.stderr
    for name in ("node-104.pem", "asus_node_ca.pem"):
        assert f"LoadCredential={name}:/etc/aimesh-snmp-proxy/{name}" in result.stdout
    assert not host.unit.exists()


@pytest.mark.parametrize("value", ["../node.pem", "a b.pem", "x:y.pem", "-x"])
def test_a_leaf_pin_value_that_is_no_plain_file_name_is_refused(host, value):
    edit_config(host, append=LEAF_PINS.replace("node-104.pem", value))
    result = host.run()
    assert result.returncode == 1
    assert "override[0].ca_file must name a file" in result.stderr
    assert not host.unit.exists()


def test_the_example_config_names_only_loaded_files(host):
    result = host.run()
    assert result.returncode == 0
    assert "not loaded by the unit" not in result.stderr


def test_snmpv3_key_files_need_a_drop_in(host):
    edit_config(host, append=V3_TABLE)
    result = host.run()
    assert result.returncode == 0, result.stderr
    for key in ("snmp.v3.auth_key_file", "snmp.v3.priv_key_file"):
        assert f"{key} is not loaded by the unit" in result.stderr
    assert "LoadCredential=FILE:/etc/aimesh-snmp-proxy/FILE" in result.stderr
    assert "LoadCredential=snmp_" not in result.stderr  # a secret key's value
    assert "= snmp_" not in result.stderr


NAME_CANARY = "Canary-Pa55w0rd-typed-as-a-file-name"


@pytest.mark.parametrize(
    ("key", "example"),
    [
        ("asus.password_file", "asus_password"),
        ("snmp.community_file", "snmp_community"),
        ("snmp.v3.auth_key_file", "snmp_auth_key"),
        ("snmp.v3.priv_key_file", "snmp_priv_key"),
    ],
)
@pytest.mark.parametrize(
    ("value", "note"),
    [
        (NAME_CANARY, "is not loaded by the unit"),
        (f"/{NAME_CANARY}/x", "is read by the service user from an absolute path"),
    ],
    ids=["relative", "absolute"],
)
def test_a_secret_typed_in_as_a_file_name_is_never_printed(
    host, key, example, value, note
):
    edit_config(host, append=V3_TABLE)
    path = host.etc / "config.toml"
    path.write_text(path.read_text().replace(f'"{example}"', f'"{value}"'))
    result = host.run()
    assert result.returncode == 0, result.stderr
    assert NAME_CANARY not in result.stdout + result.stderr
    assert f"{key} {note}" in result.stderr
    hint = f"the value must name a file such as {example}, not the secret itself"
    assert hint in result.stderr


def test_a_renamed_pin_file_is_noticed(host):
    edit_config(host, 'ca_file = "asus_router.pem"', 'ca_file = "router.pem"')
    result = host.run()
    assert result.returncode == 0
    assert "asus.ca_file = router.pem is not loaded" in result.stderr


def test_an_absolute_secret_path_is_noticed(host):
    edit_config(host, 'password_file = "asus_password"', 'password_file = "/root/pw"')
    result = host.run()
    assert result.returncode == 0
    note = "asus.password_file is read by the service user from an absolute path"
    assert note in result.stderr
    assert "/root/pw" not in result.stderr


def test_the_static_user_variant_needs_no_credential_notes(host):
    edit_config(host, append=V3_TABLE)
    result = host.run(systemd=245)
    assert result.returncode == 0
    assert "not loaded by the unit" not in result.stderr


def test_custom_prefix_lands_in_the_unit_and_the_tree(host):
    result = host.run("--prefix", "/srv/aimesh")
    assert result.returncode == 0, result.stderr
    assert (host.root / "srv" / "aimesh" / "venv" / "bin" / "python").exists()
    assert not host.opt.exists()
    assert "ExecStart=/srv/aimesh/venv/bin/python " in host.unit.read_text()


# --- refusals ---------------------------------------------------------------------


def test_non_root_real_run_is_refused(host):
    result = host.run(uid=1000)
    assert result.returncode == 1
    assert "run as root" in result.stderr
    assert empty(host.root)


def test_old_python_is_refused(host):
    result = host.run(FAKE_PYVER="3.10.12")
    assert result.returncode == 1
    assert "no Python >= 3.11" in result.stderr
    assert empty(host.root)


@pytest.mark.parametrize("version", ["3.11.0", "3.12.1", "3.13.1", "3.14.2", "3.15.0"])
def test_python_from_3_11_up_is_accepted(host, version):
    result = host.run(FAKE_PYVER=version)
    assert result.returncode == 0, result.stderr
    assert f"python {version}" in result.stdout


@pytest.mark.parametrize("version", ["2.7.18", "3.9.18", "3.10.14"])
def test_python_below_3_11_is_refused(host, version):
    result = host.run(FAKE_PYVER=version)
    assert result.returncode == 1
    assert "3.11 or newer is needed" in result.stderr
    assert empty(host.root)


def test_the_default_search_finds_python_3_14(host):
    broken = "#!/bin/sh\nexit 1\n"
    for name in ("python3.12", "python3.11", "python3.13"):
        (host.stubs / name).write_text(broken)
        (host.stubs / name).chmod(0o755)
    shutil.copy2(host.fake_python, host.stubs / "python3.14")
    result = host.run(search=True, FAKE_PYVER="3.14.2")
    assert result.returncode == 0, result.stderr
    assert f"python 3.14.2 ({host.stubs}/python3.14)" in result.stdout


@pytest.mark.parametrize(
    ("systemd", "mentioned"), [(259, True), (250, True), (249, False), (247, False)]
)
def test_encrypted_credentials_are_mentioned_from_systemd_250(host, systemd, mentioned):
    result = host.run("--dry-run", uid=1000, systemd=systemd)
    assert result.returncode == 0, result.stderr
    assert ("LoadCredentialEncrypted= is available" in result.stdout) is mentioned


def test_missing_python_is_refused(host):
    result = host.run("--python", "/nonexistent/python3")
    assert result.returncode == 1
    assert "no Python >= 3.11" in result.stderr
    assert empty(host.root)


@pytest.mark.parametrize("state", ["active", "activating"])
def test_running_service_is_not_touched(host, state):
    result = host.run(state=state)
    assert result.returncode == 1
    assert "stop it first" in result.stderr
    assert empty(host.root)


def test_bundle_checksum_mismatch_is_refused(host):
    wheel = next((host.bundle_dir / "wheels").glob("asusrouter*.whl"))
    wheel.write_bytes(wheel.read_bytes() + b"tamper")
    result = host.run()
    assert result.returncode == 1
    assert "checksum mismatch" in result.stderr
    assert empty(host.root)


def test_a_source_checkout_is_not_a_bundle(host):
    (host.bundle_dir / "requirements.txt").unlink()
    result = host.run()
    assert result.returncode == 1
    assert "not a bundle" in result.stderr
    assert empty(host.root)


def test_missing_checksums_only_warn(host):
    (host.bundle_dir / "SHA256SUMS").unlink()
    result = host.run()
    assert result.returncode == 0
    assert "SHA256SUMS" in result.stderr


def test_python_without_venv_needs_uv(host):
    result = host.run(FAKE_NO_VENV="1")
    assert result.returncode == 1
    assert "apt install python3-venv" in result.stderr
    assert "python3.12-venv" in result.stderr
    assert empty(host.root)


def test_python_without_venv_falls_back_to_uv(host):
    host.stub_uv()
    result = host.run(FAKE_NO_VENV="1")
    assert result.returncode == 0, result.stderr
    uv = host.calls("uv")
    assert any(c.startswith("uv venv ") for c in uv)
    (pip,) = [c for c in uv if c.startswith("uv pip install")]
    for flag in ("--require-hashes", "--no-deps", "--only-binary :all:"):
        assert flag in pip
    assert (host.opt / "venv" / "bin" / "python").exists()


# --- failed builds roll back --------------------------------------------------------


def test_failed_build_restores_the_previous_venv(host):
    assert host.run().returncode == 0
    (host.opt / "venv" / "KEEP").write_text("previous install")
    result = host.run(FAKE_PIP_FAIL="1")
    assert result.returncode == 1
    assert "unchanged" in result.stderr
    assert (host.opt / "venv" / "KEEP").read_text() == "previous install"
    assert not (host.opt / "venv.prev").exists()


def test_successful_upgrade_drops_the_previous_venv(host):
    assert host.run().returncode == 0
    (host.opt / "venv" / "KEEP").write_text("previous install")
    assert host.run().returncode == 0
    assert not (host.opt / "venv" / "KEEP").exists()
    assert not (host.opt / "venv.prev").exists()


def test_interrupted_run_leftover_is_restored_or_reported(host):
    assert host.run().returncode == 0
    (host.opt / "venv").rename(host.opt / "venv.prev")
    assert host.run().returncode == 0
    assert not (host.opt / "venv.prev").exists()
    (host.opt / "venv").rename(host.opt / "venv.prev")
    (host.opt / "venv").mkdir()
    result = host.run()
    assert result.returncode == 1
    assert "interrupted" in result.stderr


# --- legacy systemd -----------------------------------------------------------------


def test_old_systemd_gets_a_static_user_variant(host, unit_parser):
    result = host.run(systemd=245)
    assert result.returncode == 0, result.stderr
    assert "no LoadCredential" in result.stderr
    text = host.unit.read_text()
    service = dict(unit_parser(text)["Service"])
    assert service["User"] == service["Group"] == "aimesh-snmp-proxy"
    assert "DynamicUser" not in service
    assert "LoadCredential" not in text.replace("no LoadCredential", "")
    assert "--config /etc/aimesh-snmp-proxy/config.toml run" in service["ExecStart"]
    assert "CREDENTIALS_DIRECTORY" not in service["ExecStart"]
    assert any(c.startswith("useradd --system") for c in host.calls("useradd"))
    assert host.calls("chown") == [
        f"chown -R aimesh-snmp-proxy:aimesh-snmp-proxy {host.etc}"
    ]


def test_old_systemd_reuses_an_existing_user(host):
    result = host.run(systemd=245, FAKE_USER_EXISTS="1")
    assert result.returncode == 0
    assert host.calls("useradd") == []


def test_new_systemd_creates_no_user(host):
    assert host.run(systemd=252).returncode == 0
    assert host.calls("useradd") == []


# --- uninstall ----------------------------------------------------------------------


def seed_state(host) -> None:
    state = host.root / "var" / "lib" / "private" / "aimesh-snmp-proxy"
    state.mkdir(parents=True)
    (state / "ports.json").write_text("{}")
    (host.root / "var" / "lib" / "aimesh-snmp-proxy").symlink_to(state)


def test_uninstall_keeps_config_and_state(host):
    assert host.run().returncode == 0
    seed_state(host)
    result = host.run("--uninstall")
    assert result.returncode == 0, result.stderr
    assert not host.unit.exists()
    assert not (host.opt / "venv").exists()
    assert (host.etc / "config.toml").exists()
    assert (host.root / "var" / "lib" / "aimesh-snmp-proxy" / "ports.json").exists()
    verbs = [c.split()[1] for c in host.calls("systemctl")]
    for verb in ("stop", "disable", "daemon-reload", "reset-failed"):
        assert verb in verbs
    assert not {"start", "enable", "restart"} & set(verbs)


def test_uninstall_twice_is_fine(host):
    assert host.run().returncode == 0
    assert host.run("--uninstall").returncode == 0
    assert host.run("--uninstall").returncode == 0


def test_purge_refuses_without_confirmation(host):
    assert host.run().returncode == 0
    result = host.run("--uninstall", "--purge")
    assert result.returncode == 1
    assert "--yes" in result.stderr
    assert (host.etc / "config.toml").exists()
    assert host.unit.exists()


def test_purge_asks_and_accepts_only_the_word(host):
    assert host.run().returncode == 0
    assert host.run("--uninstall", "--purge", stdin="no\n").returncode == 1
    assert (host.etc / "config.toml").exists()


def test_purge_deletes_what_install_and_the_service_created(host):
    assert host.run().returncode == 0
    seed_state(host)
    (host.unit.parent / "aimesh-snmp-proxy.service.d").mkdir()
    result = host.run("--uninstall", "--purge", "--yes", FAKE_USER_EXISTS="1")
    assert result.returncode == 0, result.stderr
    for path in (
        host.etc,
        host.unit,
        host.unit.parent / "aimesh-snmp-proxy.service.d",
        host.opt,
        host.root / "var" / "lib" / "aimesh-snmp-proxy",
        host.root / "var" / "lib" / "private" / "aimesh-snmp-proxy",
    ):
        assert not os.path.lexists(path), path
    assert host.calls("userdel") == ["userdel aimesh-snmp-proxy"]


def test_purge_leaves_unrelated_files_alone(host):
    assert host.run().returncode == 0
    (host.root / "etc" / "other.conf").write_text("keep")
    (host.opt / "notes.txt").write_text("keep")
    assert host.run("--uninstall", "--purge", "--yes").returncode == 0
    assert (host.root / "etc" / "other.conf").read_text() == "keep"
    assert (host.opt / "notes.txt").read_text() == "keep"


def test_uninstall_dry_run_changes_nothing(host):
    assert host.run().returncode == 0
    before = sorted(str(p) for p in host.root.rglob("*"))
    result = host.run("--uninstall", "--purge", "--dry-run", uid=1000)
    assert result.returncode == 0, result.stderr
    assert sorted(str(p) for p in host.root.rglob("*")) == before
    assert "would run" in result.stdout


def test_uninstall_needs_root(host):
    assert host.run().returncode == 0
    result = host.run("--uninstall", uid=1000)
    assert result.returncode == 1
    assert host.unit.exists()


# --- the real venv and pip, offline ---------------------------------------------------


def test_real_venv_installs_hash_pinned_wheels_readable_by_the_service(
    host, rewrite_sums
):
    pytest.importorskip("ensurepip", reason="this Python cannot build venvs")
    result = host.run(python=sys.executable)
    assert result.returncode == 0, result.stdout + result.stderr
    python = host.opt / "venv" / "bin" / "python"
    probe = subprocess.run(
        [str(python), "-I", "-c", "import aimesh_snmp_proxy, asusrouter, fakedep"],
        capture_output=True,
        text=True,
    )
    assert probe.returncode == 0, probe.stderr
    # The service runs as an unrelated user: every venv file must allow world read.
    site = next((host.opt / "venv" / "lib").glob("python*/site-packages"))
    for path in [
        host.opt,
        host.opt / "venv",
        site,
        *site.glob("aimesh_snmp_proxy/*.py"),
    ]:
        want = 0o005 if path.is_dir() else 0o004
        assert mode(path) & want == want, path
    # A tampered hash must stop the build and leave the working venv in place.
    requirements = host.bundle_dir / "requirements.txt"
    text = requirements.read_text()
    first = text.index("--hash=sha256:") + len("--hash=sha256:")
    requirements.write_text(text[:first] + "0" * 8 + text[first + 8 :])
    rewrite_sums(host.bundle_dir)
    failed = host.run(python=sys.executable)
    assert failed.returncode == 1
    assert "do not match the hashes" in (failed.stdout + failed.stderr).lower()
    again = subprocess.run(
        [str(python), "-I", "-c", "import aimesh_snmp_proxy"], capture_output=True
    )
    assert again.returncode == 0
