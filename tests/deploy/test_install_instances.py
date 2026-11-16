"""install.sh --instance NAME against a fake host: one more service per router.

Same fake host as the single-service tests: command stubs, a fake root, a fake bundle.
An instance has its own config folder, state directory and drop-in; the venv, the
unit template and the service user model are shared.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

BASH = shutil.which("bash") or "/bin/bash"
BASHES = sorted({b for b in (BASH, "/bin/bash") if Path(b).exists()})
CANARY = "canary-secret-7f3a91"
PLACEHOLDERS = ("asus_password", "snmp_community", "asus_router.pem")
CONFIG = """
state_dir = "{state}"

[asus]
host = "{router}"
username = "admin"
password_file = "asus_password"
ca_file = "asus_router.pem"

[snmp]
port_base = {port}
community_file = "snmp_community"

[collector]
mode = "{mode}"

[nodes]
expected = {expected}
"""


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def write_config(host, name, router="192.168.50.109", port=16201, **fields):
    mode_ = fields.get("mode_", "root_only")
    expected = fields.get("expected", "[]")
    etc = host.instance_etc(name)
    etc.mkdir(parents=True, exist_ok=True)
    (etc / "config.toml").write_text(
        CONFIG.format(
            state=f"/var/lib/aimesh-snmp-proxy-{name}",
            router=router,
            port=port,
            mode=mode_,
            expected=expected,
        )
    )


def allow_of(host, name, unit_parser) -> str:
    unit = unit_parser(host.dropin(name).read_text())
    assert unit == {
        "Service": [("IPAddressAllow", ""), ("IPAddressAllow", unit["Service"][1][1])]
    }
    return unit["Service"][1][1]


def everything_printed(host, result) -> str:
    return (
        result.stdout
        + result.stderr
        + (host.log.read_text() if host.log.exists() else "")
    )


def empty(root: Path) -> bool:
    return not any(root.rglob("*"))


def verbs(host) -> list[str]:
    return [c.split()[1] for c in host.calls("systemctl")]


# --- install ----------------------------------------------------------------------


@pytest.mark.parametrize("bash", BASHES)
def test_the_instance_lifecycle_works_on_every_bash(host, bash, unit_parser):
    write_config(host, "ap109", router="192.168.50.109")
    assert host.run("--instance", "ap109", bash=bash).returncode == 0
    assert allow_of(host, "ap109", unit_parser) == "localhost 192.168.50.109"
    assert host.run("--instance", "ap109", bash=bash).returncode == 0
    assert host.run("--instance", "ap109", "--uninstall", bash=bash).returncode == 0
    assert not host.dropin("ap109").exists()
    purge = ("--instance", "ap109", "--uninstall", "--purge", "--yes")
    assert host.run(*purge, bash=bash).returncode == 0
    assert not host.instance_etc("ap109").exists()
    assert host.run("--uninstall", bash=bash).returncode == 0


def test_instance_install_creates_its_own_tree(host, repo):
    result = host.run("--instance", "ap109")
    assert result.returncode == 0, result.stderr
    etc = host.instance_etc("ap109")
    assert mode(host.etc) == 0o700
    assert mode(etc) == 0o700
    for name in ("config.toml", *PLACEHOLDERS):
        assert mode(etc / name) == 0o600, name
    for name in PLACEHOLDERS:
        assert (etc / name).read_bytes() == b"", name
    example = (repo / "config.example.toml").read_text()
    assert (etc / "config.toml").read_text() == example.replace(
        'state_dir = "/var/lib/aimesh-snmp-proxy"',
        'state_dir = "/var/lib/aimesh-snmp-proxy-ap109"',
    )
    assert host.calls("chown") == [
        f"chown -R root:root {etc}",
        f"chown root:root {host.etc}",
    ]


def test_instance_install_shares_the_venv_and_adds_no_single_service(host):
    assert host.run("--instance", "ap109").returncode == 0
    assert (host.opt / "venv" / "bin" / "python").exists()
    assert mode(host.opt) == 0o755
    assert not host.unit.exists()
    assert not (host.etc / "config.toml").exists()
    assert not (host.root / "var" / "lib" / "aimesh-snmp-proxy").exists()


def test_instance_install_only_reloads_systemd(host):
    assert host.run("--instance", "ap109").returncode == 0
    assert "daemon-reload" in verbs(host)
    assert set(verbs(host)) <= {"--version", "is-active", "list-units", "daemon-reload"}
    assert host.calls("useradd") == []


def test_instance_unit_is_the_template_with_the_prefix(host):
    assert host.run("--instance", "ap109").returncode == 0
    text = host.template.read_text()
    assert mode(host.template) == 0o644
    assert not re.search(r"@[A-Z_]+@", text)
    assert "ExecStart=/opt/aimesh-snmp-proxy/venv/bin/python -I " in text
    assert "--config ${CREDENTIALS_DIRECTORY}/config.toml run" in text
    assert not (host.units / "aimesh-snmp-proxy@ap109.service").exists()


def test_instance_drop_in_allows_loopback_and_the_instances_router(host, unit_parser):
    write_config(host, "ap109", router="192.168.50.109")
    assert host.run("--instance", "ap109").returncode == 0
    assert allow_of(host, "ap109", unit_parser) == "localhost 192.168.50.109"
    assert mode(host.dropin("ap109")) == 0o644
    assert mode(host.dropin("ap109").parent) == 0o755


@pytest.mark.parametrize(
    ("mode_", "expected", "line"),
    [
        ("root_only", '"192.168.50.101-110"', "localhost 192.168.50.109"),
        (
            "per_node",
            '"192.168.50.101-102"',
            "localhost 192.168.50.109 192.168.50.101 192.168.50.102",
        ),
        ("per_node", "[]", "localhost 192.168.50.109"),
    ],
)
def test_instance_allow_list_follows_the_collector_mode(
    host, unit_parser, mode_, expected, line
):
    write_config(host, "ap109", mode_=mode_, expected=expected)
    assert host.run("--instance", "ap109").returncode == 0
    assert allow_of(host, "ap109", unit_parser) == line


def test_a_hostname_router_is_refused_before_any_change(host):
    write_config(host, "ap109", router="router.asus.com")
    result = host.run("--instance", "ap109")
    assert result.returncode == 1
    assert "asus.host must be an IP address" in result.stderr
    assert not host.opt.exists()
    assert not host.template.exists()


def test_two_instances_do_not_touch_each_other(host, unit_parser):
    write_config(host, "ap109", router="192.168.50.109", port=16201)
    write_config(host, "ap110", router="192.168.50.110", port=16301)
    assert host.run("--instance", "ap109").returncode == 0
    (host.instance_etc("ap109") / "asus_password").write_text(CANARY)
    before = host.dropin("ap109").read_text()
    assert host.run("--instance", "ap110").returncode == 0
    assert allow_of(host, "ap110", unit_parser) == "localhost 192.168.50.110"
    assert host.dropin("ap109").read_text() == before
    assert (host.instance_etc("ap109") / "asus_password").read_text() == CANARY
    assert not (host.instance_etc("ap110") / "asus_password").read_text()
    seeded = (host.instance_etc("ap110") / "config.toml").read_text()
    assert "aimesh-snmp-proxy-ap109" not in seeded


def test_rerun_keeps_config_and_secrets_and_follows_the_router(host, unit_parser):
    assert host.run("--instance", "ap109").returncode == 0
    (host.instance_etc("ap109") / "asus_password").write_text(CANARY)
    write_config(host, "ap109", router="192.168.50.7")
    result = host.run("--instance", "ap109")
    assert result.returncode == 0, result.stderr
    assert (host.instance_etc("ap109") / "asus_password").read_text() == CANARY
    assert mode(host.instance_etc("ap109") / "asus_password") == 0o600
    assert allow_of(host, "ap109", unit_parser) == "localhost 192.168.50.7"
    assert "kept asus_password" in result.stdout
    assert (
        'state_dir = "/var/lib/aimesh-snmp-proxy-ap109"'
        in (host.instance_etc("ap109") / "config.toml").read_text()
    )


def test_install_tightens_loose_instance_modes(host):
    assert host.run("--instance", "ap109").returncode == 0
    (host.instance_etc("ap109") / "asus_password").chmod(0o644)
    host.instance_etc("ap109").chmod(0o755)
    host.etc.chmod(0o755)
    assert host.run("--instance", "ap109").returncode == 0
    assert mode(host.instance_etc("ap109") / "asus_password") == 0o600
    assert mode(host.instance_etc("ap109")) == 0o700
    assert mode(host.etc) == 0o700


def test_custom_prefix_lands_in_the_template(host):
    assert host.run("--instance", "ap109", "--prefix", "/srv/aimesh").returncode == 0
    assert "ExecStart=/srv/aimesh/venv/bin/python " in host.template.read_text()
    assert (host.root / "srv" / "aimesh" / "venv" / "bin" / "python").exists()


def test_the_bundle_must_carry_the_template(host):
    (host.bundle_dir / "deploy" / "aimesh-snmp-proxy@.service").unlink()
    result = host.run("--instance", "ap109")
    assert result.returncode == 1
    assert "aimesh-snmp-proxy@.service is missing" in result.stderr
    assert empty(host.root)


def test_the_example_must_name_the_state_dir_an_instance_replaces(host, rewrite_sums):
    example = host.bundle_dir / "config.example.toml"
    example.write_text(example.read_text().replace("state_dir", "state_folder"))
    rewrite_sums(host.bundle_dir)
    result = host.run("--instance", "ap109")
    assert result.returncode == 1
    assert "state_dir" in result.stderr
    assert empty(host.root)


def test_old_systemd_cannot_run_instances(host):
    result = host.run("--instance", "ap109", systemd=245)
    assert result.returncode == 1
    assert "instances need systemd 247" in result.stderr
    assert empty(host.root)


def test_instance_credential_notes_name_the_instance_folder(host):
    write_config(host, "ap109")
    path = host.instance_etc("ap109") / "config.toml"
    path.write_text(
        path.read_text()
        + '\n[snmp.v3]\nuser = "librenms"\nauth_key_file = "snmp_auth_key"\n'
        + 'priv_key_file = "snmp_priv_key"\n'
    )
    result = host.run("--instance", "ap109")
    assert result.returncode == 0, result.stderr
    assert "LoadCredential=FILE:/etc/aimesh-snmp-proxy/ap109/FILE" in result.stderr
    assert "snmp.v3.auth_key_file is not loaded by the unit" in result.stderr


def test_the_example_config_names_only_loaded_files_for_an_instance(host):
    result = host.run("--instance", "ap109")
    assert result.returncode == 0
    assert "not loaded by the unit" not in result.stderr
    assert "state_dir" not in result.stderr  # the run itself redirects it


def test_an_instance_config_with_another_state_dir_gets_a_note(host):
    write_config(host, "ap109")
    path = host.instance_etc("ap109") / "config.toml"
    path.write_text(
        path.read_text().replace("aimesh-snmp-proxy-ap109", "aimesh-snmp-proxy")
    )
    result = host.run("--instance", "ap109")
    assert result.returncode == 0, result.stderr
    assert "state_dir is /var/lib/aimesh-snmp-proxy, but the unit" in result.stderr
    assert "write only /var/lib/aimesh-snmp-proxy-ap109" in result.stderr


def test_an_instance_config_without_a_state_dir_gets_no_note(host):
    write_config(host, "ap109")
    path = host.instance_etc("ap109") / "config.toml"
    path.write_text(path.read_text().split("\n", 2)[2])  # drop the state_dir line
    result = host.run("--instance", "ap109")
    assert result.returncode == 0, result.stderr
    assert "state_dir" not in result.stderr


# --- usage ------------------------------------------------------------------------


def test_help_names_the_instance_option(deploy_dir):
    result = subprocess.run(
        [BASH, str(deploy_dir / "install.sh"), "--help"], capture_output=True, text=True
    )
    assert result.returncode == 0
    assert "--instance NAME" in result.stdout


@pytest.mark.parametrize(
    "args",
    [
        ["--instance"],
        ["--instance", ""],
        ["--instance="],
        ["--instance", "A"],
        ["--instance", "Ap109"],
        ["--instance", "-ap"],
        ["--instance", "ap-"],
        ["--instance", "a b"],
        ["--instance", "a/b"],
        ["--instance", "../x"],
        ["--instance", "ap.109"],
        ["--instance", "ap_109"],
        ["--instance", "a;rm"],
        ["--instance", "x" * 33],
        ["--instance", "ap109", "--purge"],
    ],
)
def test_bad_instance_usage_is_refused_before_anything_runs(host, args):
    result = host.run(*args)
    assert result.returncode == 2
    assert empty(host.root)
    assert host.calls() == []


@pytest.mark.parametrize("name", ["a", "ap109", "109", "ap-109", "x" * 32])
def test_good_instance_names_are_accepted(host, name):
    result = host.run("--dry-run", "--instance", name, uid=1000)
    assert result.returncode == 0, result.stderr


# --- dry run ----------------------------------------------------------------------


def test_instance_dry_run_changes_nothing_and_needs_no_root(host):
    result = host.run("--dry-run", "--instance", "ap109", uid=1000)
    assert result.returncode == 0, result.stderr
    assert empty(host.root)
    assert "DRY RUN" in result.stdout
    assert f"would write {host.dropin('ap109')} (0644)" in result.stdout
    assert f"would write {host.template} (0644)" in result.stdout
    assert (
        f"would write {host.instance_etc('ap109')}/config.toml (0600)" in result.stdout
    )
    assert set(verbs(host)) <= {"--version", "is-active", "list-units"}


def test_instance_uninstall_dry_run_changes_nothing(host):
    assert host.run("--instance", "ap109").returncode == 0
    before = sorted(str(p) for p in host.root.rglob("*"))
    result = host.run(
        "--instance", "ap109", "--uninstall", "--purge", "--dry-run", uid=1000
    )
    assert result.returncode == 0, result.stderr
    assert sorted(str(p) for p in host.root.rglob("*")) == before
    assert "would run" in result.stdout


# --- the shared venv: nothing may run while it is rebuilt -------------------------


@pytest.mark.parametrize(
    ("env", "unit"),
    [
        (
            {"FAKE_ACTIVE_UNITS": "aimesh-snmp-proxy.service"},
            "aimesh-snmp-proxy.service",
        ),
        (
            {"FAKE_ACTIVE_UNITS": "aimesh-snmp-proxy@ap110.service"},
            "aimesh-snmp-proxy@ap110.service",
        ),
        (
            {"FAKE_LOADED_UNITS": "aimesh-snmp-proxy@ghost.service"},
            "aimesh-snmp-proxy@ghost.service",
        ),
        (
            {
                "FAKE_LOADED_UNITS": "aimesh-snmp-proxy@ghost.service",
                "FAKE_LOADED_STATE": "activating",
            },
            "aimesh-snmp-proxy@ghost.service",
        ),
    ],
    ids=["single", "known-instance", "loaded-instance", "starting-instance"],
)
@pytest.mark.parametrize("args", [(), ("--instance", "ap109")], ids=["single", "inst"])
def test_install_refuses_while_any_service_runs(host, env, unit, args):
    write_config(host, "ap110", router="192.168.50.110")
    result = host.run(*args, **env)
    assert result.returncode == 1
    assert f"{unit} is " in result.stderr
    assert "stop it first" in result.stderr
    assert not host.opt.exists()
    assert not host.template.exists()


def test_a_stopped_instance_does_not_block_an_install(host):
    write_config(host, "ap110", router="192.168.50.110")
    result = host.run(
        "--instance",
        "ap109",
        FAKE_LOADED_UNITS="aimesh-snmp-proxy@ap110.service",
        FAKE_LOADED_STATE="inactive",
    )
    assert result.returncode == 0, result.stderr
    assert "aimesh-snmp-proxy@ap110.service is not running" in result.stdout


def test_the_single_install_keeps_the_template_current_only_when_it_exists(host):
    assert host.run().returncode == 0
    assert not host.template.exists()
    write_config(host, "ap109", port=16201)
    assert host.run("--instance", "ap109").returncode == 0
    host.template.write_text("stale\n")
    result = host.run()
    assert result.returncode == 0, result.stderr
    assert (
        "ExecStart=/opt/aimesh-snmp-proxy/venv/bin/python -I "
        in host.template.read_text()
    )
    assert host.unit.exists()


# --- two services must not share a port -------------------------------------------


def test_an_instance_seeded_with_the_single_services_port_gets_a_warning(host):
    assert host.run().returncode == 0
    result = host.run("--instance", "ap109")
    assert result.returncode == 0, result.stderr
    assert "snmp.port_base 16101" in result.stderr
    assert "is also the port base of" in result.stderr
    assert "/etc/aimesh-snmp-proxy/config.toml" in result.stderr


def test_a_kept_instance_config_that_shares_a_port_is_refused(host):
    assert host.run().returncode == 0
    assert host.run("--instance", "ap109").returncode == 0
    result = host.run("--instance", "ap109")
    assert result.returncode == 1
    assert "snmp.port_base 16101" in result.stderr
    assert "nothing was changed" in result.stderr
    path = host.instance_etc("ap109") / "config.toml"
    path.write_text(
        path.read_text().replace("port_base = 16101 ", "port_base = 16201 ")
    )
    again = host.run("--instance", "ap109")
    assert again.returncode == 0, again.stderr
    assert "snmp.port_base" not in again.stderr


def test_two_instances_on_one_port_are_refused(host):
    write_config(host, "ap109", port=16201)
    write_config(host, "ap110", router="192.168.50.110", port=16201)
    result = host.run("--instance", "ap110")
    assert result.returncode == 1
    assert "/etc/aimesh-snmp-proxy/ap109/config.toml" in result.stderr
    assert not host.opt.exists()


def test_the_single_install_refuses_a_port_an_instance_holds(host):
    assert host.run().returncode == 0
    write_config(host, "ap109", port=16101)
    result = host.run()
    assert result.returncode == 1
    assert "/etc/aimesh-snmp-proxy/ap109/config.toml" in result.stderr


def test_distinct_ports_raise_no_warning(host):
    assert host.run().returncode == 0
    write_config(host, "ap109", port=16201)
    result = host.run("--instance", "ap109")
    assert result.returncode == 0
    assert "snmp.port_base" not in result.stderr


# --- secrets never show -----------------------------------------------------------


def test_no_secret_value_is_ever_printed(host):
    assert host.run("--instance", "ap109").returncode == 0
    for name in PLACEHOLDERS:
        (host.instance_etc("ap109") / name).write_text(CANARY)
    for args in (
        [],
        ["--dry-run"],
        ["--uninstall"],
        ["--uninstall", "--purge", "--yes"],
    ):
        result = host.run("--instance", "ap109", *args)
        assert CANARY not in everything_printed(host, result), args


# --- uninstall --------------------------------------------------------------------


def seed_state(host, name) -> None:
    private = host.root / "var" / "lib" / "private" / f"aimesh-snmp-proxy-{name}"
    private.mkdir(parents=True)
    (private / "ports.json").write_text("{}")
    host.instance_state(name).symlink_to(private)


def test_instance_uninstall_keeps_config_and_state_and_the_rest(host):
    assert host.run().returncode == 0
    assert host.run("--instance", "ap109").returncode == 0
    write_config(host, "ap110", router="192.168.50.110", port=16301)
    assert host.run("--instance", "ap110").returncode == 0
    seed_state(host, "ap109")
    result = host.run("--instance", "ap109", "--uninstall")
    assert result.returncode == 0, result.stderr
    assert not host.dropin("ap109").exists()
    assert not host.dropin("ap109").parent.exists()
    assert (host.instance_etc("ap109") / "config.toml").exists()
    assert (host.instance_state("ap109") / "ports.json").exists()
    for kept in (
        host.template,
        host.unit,
        host.dropin("ap110"),
        host.etc / "config.toml",
    ):
        assert kept.exists(), kept
    assert (host.opt / "venv" / "bin" / "python").exists()
    stops = [c for c in host.calls("systemctl") if " stop " in c or " disable " in c]
    assert stops == [
        "systemctl stop aimesh-snmp-proxy@ap109.service",
        "systemctl disable aimesh-snmp-proxy@ap109.service",
    ]
    assert not {"start", "enable", "restart"} & set(verbs(host))


def test_instance_uninstall_leaves_a_users_own_drop_ins(host):
    assert host.run("--instance", "ap109").returncode == 0
    (host.dropin("ap109").parent / "override.conf").write_text(
        "[Service]\nMemoryMax=1G\n"
    )
    assert host.run("--instance", "ap109", "--uninstall").returncode == 0
    assert not host.dropin("ap109").exists()
    assert (host.dropin("ap109").parent / "override.conf").exists()


def test_instance_uninstall_twice_or_never_installed_is_fine(host):
    assert host.run("--instance", "ap109", "--uninstall").returncode == 0
    assert host.run("--instance", "ap109").returncode == 0
    assert host.run("--instance", "ap109", "--uninstall").returncode == 0
    assert host.run("--instance", "ap109", "--uninstall").returncode == 0


def with_node_ca(host, name):
    write_config(host, name, mode_="per_node", expected='"192.168.50.101-102"')
    path = host.instance_etc(name) / "config.toml"
    text = path.read_text().replace(
        'ca_file = "asus_router.pem"',
        'ca_file = "asus_router.pem"\nnode_ca_file = "asus_node_ca.pem"',
    )
    path.write_text(text)


def node_ca_dropin(host, name):
    return host.dropin(name).parent / "20-node-ca.conf"


def test_an_instance_loads_its_node_ca_pin_through_a_drop_in(host, unit_parser):
    with_node_ca(host, "ap109")
    result = host.run("--instance", "ap109")
    assert result.returncode == 0, result.stderr
    unit = unit_parser(node_ca_dropin(host, "ap109").read_text())
    assert unit == {
        "Service": [
            (
                "LoadCredential",
                "asus_node_ca.pem:/etc/aimesh-snmp-proxy/ap109/asus_node_ca.pem",
            )
        ]
    }
    assert mode(node_ca_dropin(host, "ap109")) == 0o644
    assert "LoadCredential=asus_node_ca" not in host.template.read_text()


def test_an_instance_dry_run_reports_the_node_ca_drop_in(host):
    with_node_ca(host, "ap109")
    result = host.run("--instance", "ap109", "--dry-run", uid=1000)
    assert result.returncode == 0, result.stderr
    line = (
        "LoadCredential=asus_node_ca.pem:/etc/aimesh-snmp-proxy/ap109/asus_node_ca.pem"
    )
    assert line in result.stdout
    assert not node_ca_dropin(host, "ap109").exists()


def test_the_node_ca_drop_in_goes_with_the_key_and_with_the_instance(host):
    with_node_ca(host, "ap109")
    assert host.run("--instance", "ap109").returncode == 0
    write_config(host, "ap109")  # node_ca_file removed from the config
    assert host.run("--instance", "ap109").returncode == 0
    assert not node_ca_dropin(host, "ap109").exists()
    with_node_ca(host, "ap109")
    assert host.run("--instance", "ap109").returncode == 0
    assert host.run("--instance", "ap109", "--uninstall").returncode == 0
    assert not node_ca_dropin(host, "ap109").exists()


def test_an_instance_loads_override_leaf_pins_in_the_same_drop_in(host, unit_parser):
    with_node_ca(host, "ap109")
    path = host.instance_etc("ap109") / "config.toml"
    path.write_text(
        path.read_text()
        + '\n[[override]]\nmatch = "192.168.50.102"\nca_file = "node-102.pem"\n'
    )
    result = host.run("--instance", "ap109")
    assert result.returncode == 0, result.stderr
    etc = "/etc/aimesh-snmp-proxy/ap109"
    assert unit_parser(node_ca_dropin(host, "ap109").read_text())["Service"] == [
        ("LoadCredential", f"asus_node_ca.pem:{etc}/asus_node_ca.pem"),
        ("LoadCredential", f"node-102.pem:{etc}/node-102.pem"),
    ]
    dry = host.run("--instance", "ap109", "--dry-run", uid=1000)
    assert f"LoadCredential=node-102.pem:{etc}/node-102.pem" in dry.stdout


def test_instance_purge_asks_first(host):
    assert host.run("--instance", "ap109").returncode == 0
    result = host.run("--instance", "ap109", "--uninstall", "--purge")
    assert result.returncode == 1
    assert "--yes" in result.stderr
    assert (host.instance_etc("ap109") / "config.toml").exists()
    assert host.dropin("ap109").exists()
    assert (
        host.run(
            "--instance", "ap109", "--uninstall", "--purge", stdin="no\n"
        ).returncode
        == 1
    )
    assert (host.instance_etc("ap109") / "config.toml").exists()


def test_instance_purge_deletes_only_that_instances_files(host):
    assert host.run().returncode == 0
    assert host.run("--instance", "ap109").returncode == 0
    write_config(host, "ap110", router="192.168.50.110", port=16301)
    assert host.run("--instance", "ap110").returncode == 0
    seed_state(host, "ap109")
    seed_state(host, "ap110")
    (host.root / "etc" / "other.conf").write_text("keep")
    result = host.run("--instance", "ap109", "--uninstall", "--purge", "--yes")
    assert result.returncode == 0, result.stderr
    for gone in (
        host.instance_etc("ap109"),
        host.dropin("ap109").parent,
        host.instance_state("ap109"),
        host.root / "var" / "lib" / "private" / "aimesh-snmp-proxy-ap109",
    ):
        assert not os.path.lexists(gone), gone
    for kept in (
        host.etc / "config.toml",
        host.instance_etc("ap110") / "config.toml",
        host.dropin("ap110"),
        host.instance_state("ap110") / "ports.json",
        host.template,
        host.unit,
        host.root / "etc" / "other.conf",
    ):
        assert kept.exists(), kept
    assert host.calls("userdel") == []


def test_uninstall_needs_root_for_an_instance_too(host):
    assert host.run("--instance", "ap109").returncode == 0
    result = host.run("--instance", "ap109", "--uninstall", uid=1000)
    assert result.returncode == 1
    assert host.dropin("ap109").exists()


# --- the single service must not take its instances down --------------------------


def test_single_uninstall_refuses_while_an_instance_is_installed(host):
    assert host.run().returncode == 0
    write_config(host, "ap109", port=16201)
    assert host.run("--instance", "ap109").returncode == 0
    result = host.run("--uninstall")
    assert result.returncode == 1
    assert "ap109" in result.stderr
    assert "--instance ap109 --uninstall" in result.stderr
    assert host.unit.exists()
    assert (host.opt / "venv" / "bin" / "python").exists()
    assert host.run("--instance", "ap109", "--uninstall").returncode == 0
    assert host.run("--uninstall").returncode == 0
    assert not host.template.exists()
    assert not host.unit.exists()
    assert (host.instance_etc("ap109") / "config.toml").exists()


def test_single_uninstall_refuses_while_an_instance_runs(host):
    assert host.run().returncode == 0
    result = host.run(
        "--uninstall", FAKE_LOADED_UNITS="aimesh-snmp-proxy@ap109.service"
    )
    assert result.returncode == 1
    assert "ap109" in result.stderr
    assert host.unit.exists()


def test_single_purge_refuses_while_instance_config_remains(host):
    assert host.run().returncode == 0
    write_config(host, "ap109", port=16201)
    assert host.run("--instance", "ap109").returncode == 0
    assert host.run("--instance", "ap109", "--uninstall").returncode == 0
    result = host.run("--uninstall", "--purge", "--yes")
    assert result.returncode == 1
    assert "ap109" in result.stderr
    assert "--instance ap109 --uninstall --purge" in result.stderr
    assert (host.instance_etc("ap109") / "config.toml").exists()
    assert (host.etc / "config.toml").exists()
    assert host.unit.exists()
    assert (
        host.run("--instance", "ap109", "--uninstall", "--purge", "--yes").returncode
        == 0
    )
    assert host.run("--uninstall", "--purge", "--yes").returncode == 0
    assert not host.etc.exists()


def test_single_uninstall_with_no_instance_works_as_before(host):
    assert host.run().returncode == 0
    assert host.run("--uninstall").returncode == 0
    assert not host.unit.exists()
    assert (host.etc / "config.toml").exists()
