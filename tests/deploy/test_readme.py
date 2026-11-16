"""The README must stay short, and every command it shows must exist in the CLI."""

from __future__ import annotations

import importlib
import re
import shlex
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest

from aimesh_snmp_proxy import __main__ as cli

MAX_LINES = 150  # 0.3: router types and generic hosts took 6 lines
BASH = shutil.which("bash") or "/bin/bash"
TOPICS = (
    "build-bundle.sh",
    "install.sh --dry-run",
    "--uninstall",
    "--purge",
    "discover --pin-cert",
    "check-config",
    "selftest",
    "onboard",
    "icmp_check",
    "lockout.json",
    "Exit 78",
    "journalctl",
    "LoadCredential=",
    "systemd-analyze verify",
    "systemd-analyze security",
    "/etc/aimesh-snmp-proxy",
    "/var/lib/aimesh-snmp-proxy",
    "/opt/aimesh-snmp-proxy",
    "Python 3.11+",
    "systemd 250+",
    "standalone router",
    "media bridge",
    "/opt/librenms",
    "apt install python3-venv",
    "LoadCredentialEncrypted=",
    "MemoryDenyWriteExecute=no",
    "SIGSYS",
    "make bundle",
    "Authentication Method: HTTPS or Both",
    "`asus.port`",
    "8443",
    "[onboard]",
    "openssl s_client -connect 192.168.50.10:443 -servername 192.168.50.10",
    "sudo openssl x509 -out /etc/aimesh-snmp-proxy/librenms.pem",
    "sudo openssl x509 -in /etc/aimesh-snmp-proxy/librenms.pem",
    "-fingerprint -sha256",
    "install.sh --instance NAME --uninstall",
    "aimesh-snmp-proxy@NAME",
    "/etc/aimesh-snmp-proxy/NAME/",
    "/var/lib/aimesh-snmp-proxy-NAME",
    "snmp.port_base",
    "systemd 247+",
    "systemctl stop 'aimesh-snmp-proxy*'",
    'hostname = "ip"',
    '`"sysname"`, the default',
    "found by id",
    "127.0.0.1:<port>",
    "per_node",
    "asus.node_ca_file",
    "discover --pin-node-ca",
    "/cert.crt",
    "`ca_file` in its `[[override]]` from `--pin-cert PATH --node MAC`",
)
INSTALL_FLAGS = ("--dry-run", "--python", "--instance", "--uninstall", "--purge")


@pytest.fixture(scope="module")
def text(repo: Path) -> str:
    return (repo / "README.md").read_text()


def test_readme_fits_the_line_budget(text):
    assert len(text.splitlines()) <= MAX_LINES


@pytest.mark.parametrize("topic", TOPICS)
def test_readme_covers(text, topic):
    assert topic in " ".join(text.split())  # a topic may wrap across lines


def app_commands(text: str) -> list[list[str]]:
    """Each command run through ``$APP``: its words, minus a leading ``-c FILE``."""
    found = []
    for line in text.splitlines():
        if "$APP" not in line or line.startswith(("APP=", "#")):
            continue
        lexer = shlex.shlex(
            line.replace("$APP", "APP"), posix=True, punctuation_chars=True
        )
        lexer.whitespace_split = True
        words = list(lexer)
        for index, word in enumerate(words):
            if word != "APP":
                continue
            end = next(
                (i for i in range(index, len(words)) if words[i] in ("&&", "|", ";")),
                len(words),
            )
            args = words[index + 1 : end]
            if args[0] in ("-c", "--config"):
                args = args[2:]
            found.append(args)
    return found


def test_readme_shows_the_commands_it_documents(text):
    names = {words[0] for words in app_commands(text)}
    assert {"discover", "check-config", "selftest", "onboard"} <= names


def test_every_command_in_the_readme_exists_and_accepts_its_flags(text):
    known = {"check-config", *cli.COMMANDS}
    for words in app_commands(text):
        command, flags = words[0], words[1:]
        assert command in known, command
        if command == "check-config":
            continue
        module_name, attribute, _ = cli.COMMANDS[command]
        handler = getattr(importlib.import_module(module_name), attribute, None)
        if handler is None:  # not wired yet: the name alone was checked
            continue
        parser_home = importlib.import_module(handler.__module__)
        make_parser = getattr(parser_home, "_parser", None)
        if make_parser is not None:
            make_parser().parse_args(flags)


def test_icmp_is_off_before_onboard_and_on_after(text):
    lnms = "sudo -u librenms /opt/librenms/lnms config:set icmp_check"
    off, on = f"{lnms} false", f"{lnms} true"
    dry_run, apply = (
        text.index("sudo $APP onboard\n"),
        text.index("sudo $APP onboard --apply\n"),
    )
    assert text.index(off) < dry_run < apply < text.index(on)


def fenced_blocks(text: str) -> list[str]:
    return re.findall(r"```sh\n(.*?)```", text, re.DOTALL)


def test_onboard_defaults_to_https_and_http_is_only_a_fallback(text):
    code = "\n".join(fenced_blocks(text))
    assert "--allow-http" not in code
    assert text.count("--allow-http") == 1
    assert set(re.findall(r"http://[^\s`\"']+", text)) == {"http://127.0.0.1"}


def test_the_fallback_flag_exists_in_the_onboard_parser():
    onboard = importlib.import_module("aimesh_snmp_proxy.ops.onboard")
    assert onboard._parser().parse_args(["--allow-http"]).allow_http


def test_onboard_keys_match_the_example_config(text, repo):
    example = (repo / "config.example.toml").read_text()
    for line in (
        'url = "https://192.168.50.10"',
        'token_file = "librenms_token"',
        'ca_file = "librenms.pem"',
    ):
        assert line in text
        assert f"# {line}" in example


def test_the_router_port_key_is_the_one_in_the_example_config(repo):
    example = tomllib.loads((repo / "config.example.toml").read_text())
    assert example["asus"]["port"] == 8443


def test_every_shell_block_parses(text):
    blocks = fenced_blocks(text)
    assert len(blocks) >= 4
    for block in blocks:
        result = subprocess.run(
            [BASH, "-n"], input=block, capture_output=True, text=True, check=False
        )
        assert result.returncode == 0, f"{block}\n{result.stderr}"


def test_no_unprivileged_cd_into_the_root_only_config_dir(text):
    # /etc/aimesh-snmp-proxy is 0700 root: a plain cd there fails, so use sudo paths.
    assert "cd /etc/aimesh-snmp-proxy" not in text


def test_the_readme_avoids_sudoedit_which_sudo_rs_may_lack(text):
    assert "sudoedit" not in text


def test_no_secret_value_appears_in_the_readme(text):
    assert not re.search(r"(password|token|community)\s*=\s*['\"][^'\"]", text, re.I)


def test_the_installer_flags_the_readme_names_exist(text, deploy_dir):
    out = subprocess.run(
        [BASH, str(deploy_dir / "install.sh"), "--help"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    for flag in INSTALL_FLAGS:
        assert flag in text, flag
        assert flag in out, flag


def test_the_onboard_hostname_values_are_the_ones_the_config_accepts(text, repo):
    config = importlib.import_module("aimesh_snmp_proxy.config")
    assert set(config.ONBOARD_HOSTNAMES) == {"sysname", "ip"}
    example = (repo / "config.example.toml").read_text()
    assert '# hostname = "sysname"' in example
    assert 'hostname = "ip"' in text


def test_an_instance_runs_the_cli_on_its_own_config(text):
    assert "sudo $APP -c /etc/aimesh-snmp-proxy/bridge/config.toml selftest" in text
    assert app_commands(text).count(["selftest"]) == 2  # the single service, then it
