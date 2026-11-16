"""The docs stay true: shell examples parse, every command and flag exists, and the
configuration reference names every key and ships an example the loader accepts.
"""

from __future__ import annotations

import importlib
import ipaddress
import re
import shlex
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest

from aimesh_snmp_proxy import __main__ as cli
from aimesh_snmp_proxy import config as config_module
from aimesh_snmp_proxy.config import load_config

ROOT = Path(__file__).resolve().parents[2]
DOCS_DIR = ROOT / "docs"
CONFIG_SOURCE = ROOT / "src" / "aimesh_snmp_proxy" / "config.py"
INSTALLER = ROOT / "deploy" / "install.sh"
EXAMPLE_CONFIG = ROOT / "config.example.toml"
MAX_README_LINES = 150  # an entry page: the details live in docs/
BASH = shutil.which("bash") or "/bin/bash"
# The include pages hold one line each: their text lives in the root file.
PAGES = [
    path
    for path in (
        ROOT / "README.md",
        ROOT / "CONTRIBUTING.md",
        *sorted(DOCS_DIR.rglob("*.md")),
    )
    if path.read_text().strip()
]
GLOBAL_FLAGS = {"--version", "-h", "--help"}
NO_FLAG_COMMANDS = {"check-config", "run", "selftest"}


def names(path: Path) -> str:
    return str(path.relative_to(ROOT))


def read(path: Path) -> str:
    return path.read_text()


FENCE = re.compile(r"^```([^\n]*)\n(.*?)^```", re.DOTALL | re.MULTILINE)
FENCE_LABELS = {"sh", "bash", "text", "toml", "json", "ini"}


def shell_blocks(text: str) -> list[str]:
    return re.findall(r"```(?:sh|bash)\n(.*?)```", text, re.DOTALL)


def logical_lines(block: str) -> list[str]:
    """The lines of a shell block, each trailing backslash joined to the next."""
    return re.sub(r"\\\n\s*", " ", block).splitlines()


def app_commands(text: str) -> list[list[str]]:
    """Each ``$APP`` command: its words, minus a leading ``-c FILE``."""
    found = []
    for block in shell_blocks(text):
        joined = re.sub(r"\\\n\s*", " ", block)  # a trailing backslash joins lines
        for line in joined.splitlines():
            stripped = line.strip()
            if "$APP" not in stripped or stripped.startswith(("APP=", "#")):
                continue
            lexer = shlex.shlex(
                stripped.replace("$APP", "APP"), posix=True, punctuation_chars=True
            )
            lexer.whitespace_split = True
            words = list(lexer)
            for index, word in enumerate(words):
                if word != "APP":
                    continue
                end = next(
                    (
                        i
                        for i in range(index, len(words))
                        if re.fullmatch(r"[<>|&;()]+", words[i])
                    ),
                    len(words),
                )
                args = words[index + 1 : end]
                if args[:1] in (["-c"], ["--config"]):
                    args = args[2:]
                found.append(args)
    return found


@pytest.mark.parametrize("page", PAGES, ids=names)
def test_every_shell_block_parses(page):
    for block in shell_blocks(read(page)):
        result = subprocess.run(
            [BASH, "-n"], input=block, capture_output=True, text=True, check=False
        )
        assert result.returncode == 0, f"{names(page)}:\n{block}\n{result.stderr}"


@pytest.mark.parametrize("page", PAGES, ids=names)
def test_every_command_exists_and_accepts_its_flags(page):
    known = {"check-config", *cli.COMMANDS}
    for words in app_commands(read(page)):
        command, flags = words[0], words[1:]
        if command in GLOBAL_FLAGS:
            continue
        assert command in known, f"{names(page)}: unknown command {command!r}"
        if command in NO_FLAG_COMMANDS:
            assert flags == [], f"{names(page)}: {command} takes no flags"
            continue
        module_name, attribute, _ = cli.COMMANDS[command]
        handler = getattr(importlib.import_module(module_name), attribute)
        parser_home = importlib.import_module(handler.__module__)
        parser_home._parser().parse_args(flags)


def test_the_docs_show_the_core_commands():
    shown = {words[0] for page in PAGES for words in app_commands(read(page))}
    assert {"init", "discover", "check-config", "selftest", "onboard"} <= shown


@pytest.fixture(scope="module")
def installer_help() -> str:
    return subprocess.run(
        [BASH, str(INSTALLER), "--help"], capture_output=True, text=True, check=True
    ).stdout


@pytest.mark.parametrize("page", PAGES, ids=names)
def test_every_installer_option_exists(page, installer_help):
    for block in shell_blocks(read(page)):
        for line in logical_lines(block):
            if "install.sh" not in line:
                continue
            for flag in re.findall(r"(?<![\w-])--[a-z][a-z-]*", line):
                assert flag in installer_help, f"{names(page)}: {flag}"


def test_the_installer_options_are_documented(installer_help):
    text = read(DOCS_DIR / "installation.md")
    for flag in (
        "--dry-run",
        "--python",
        "--prefix",
        "--instance",
        "--uninstall",
        "--purge",
        "--yes",
    ):
        assert f"`{flag}" in text, flag
        assert flag in installer_help, flag


def reference_pages() -> list[Path]:
    return sorted(DOCS_DIR.rglob("configuration.md"))


def config_names() -> set[str]:
    """Every key and table name the config loader reads, from its source."""
    source = read(CONFIG_SOURCE)
    keys = set(
        re.findall(
            r"\.(?:str_|int_|bool_|positive|str_list|table|get)\(\s*\"([a-z0-9_]+)\"",
            source,
        )
    )
    keys |= set(re.findall(r"files\.path\(\s*t,\s*\"([a-z0-9_]+)\"", source))
    return keys


def code_spans(text: str) -> set[str]:
    words: set[str] = set()
    for span in re.findall(r"`([^`\n]+)`", text):
        words.update(word for word in re.split(r"[^a-z0-9_]+", span) if word)
    return words


def test_one_configuration_reference_exists():
    assert len(reference_pages()) == 1


def test_the_reference_names_every_state_file():
    package = ROOT / "src" / "aimesh_snmp_proxy"
    source = "".join(
        read(package / name) for name in ("config.py", "ports.py", "ops/ledger.py")
    )
    state_files = set(re.findall(r'"([a-z_]+\.json)"', source))
    documented = read(reference_pages()[0])
    missing = sorted(name for name in state_files if name not in documented)
    assert state_files, "no state file name found in the source"
    assert not missing, f"undocumented state files: {missing}"


def test_the_reference_names_every_config_key():
    documented = code_spans(read(reference_pages()[0]))
    missing = sorted(config_names() - documented)
    assert not missing, f"undocumented keys: {missing}"


def flatten(table: dict, prefix: str = "") -> set[str]:
    found = set()
    for key, value in table.items():
        found.add(key)
        if isinstance(value, dict):
            found |= flatten(value)
        elif isinstance(value, list) and value and isinstance(value[0], dict):
            for item in value:
                found |= flatten(item)
    return found


def complete_example() -> str:
    section = read(reference_pages()[0]).split("## Complete example", 1)[1]
    block = re.search(r"```toml\n(.*?)```", section, re.DOTALL)
    assert block, "no toml block under the Complete example heading"
    return block.group(1)


def test_the_complete_example_loads(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(complete_example())
    cfg = load_config(path, env={})
    assert cfg.collector.mode == "per_node"
    assert cfg.snmp.v3 is not None
    assert cfg.onboard is not None
    assert [o.exclude for o in cfg.overrides] == [False, True]


def test_the_complete_example_sets_every_key():
    used = flatten(tomllib.loads(complete_example()))
    missing = sorted(config_names() - used)
    assert not missing, f"the example omits: {missing}"


PRIVATE_ADDRESS = re.compile(
    r"(?<![\d.])((?:10|127|172|192|169)\.\d{1,3}\.\d{1,3}\.\d{1,3})(?!\.?\d)"
)
MAC = re.compile(
    r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:])"
)


@pytest.mark.parametrize("page", PAGES, ids=names)
def test_examples_use_placeholder_addresses_only(page):
    text = read(page)
    for match in PRIVATE_ADDRESS.findall(text):
        address = ipaddress.ip_address(match)
        ok = address.is_loopback or address in ipaddress.ip_network("192.168.50.0/24")
        assert ok, f"{names(page)}: {match} is not a placeholder address"
    for mac in MAC.findall(text):
        assert mac.lower().startswith("00:00:5e:00:53:"), f"{names(page)}: {mac}"


SECRET_ASSIGNMENT = re.compile(r"(password|token|community)\s*=\s*['\"][^'\"]", re.I)


@pytest.mark.parametrize("page", PAGES, ids=names)
def test_no_secret_value_appears_in_the_docs(page):
    assert not SECRET_ASSIGNMENT.search(read(page)), names(page)


HTTP_URL = re.compile(r"http://[A-Za-z0-9][^\s`\"'<>)\]]*")


@pytest.mark.parametrize("page", PAGES, ids=names)
def test_cleartext_urls_name_the_loopback_address_only(page):
    for url in HTTP_URL.findall(read(page)):
        assert url.startswith("http://127.0.0.1"), f"{names(page)}: {url}"


def test_no_unprivileged_cd_into_the_root_only_config_dir():
    # /etc/aimesh-snmp-proxy is 0700 root: a plain cd there fails.
    for page in PAGES:
        assert "cd /etc/aimesh-snmp-proxy" not in read(page), names(page)


LNMS = "sudo -u librenms /opt/librenms/lnms config:set icmp_check"
ONBOARD_PAGES = [page for page in PAGES if "sudo $APP onboard --apply\n" in read(page)]


def test_the_pages_that_apply_onboard_are_found():
    found = {names(page) for page in ONBOARD_PAGES}
    assert {"README.md", "docs/librenms.md"} <= found


@pytest.mark.parametrize("page", ONBOARD_PAGES, ids=names)
def test_icmp_is_off_before_onboard_and_on_after(page):
    text = read(page)
    steps = {
        "ICMP off": f"{LNMS} false",
        "dry run": "sudo $APP onboard\n",
        "apply": "sudo $APP onboard --apply\n",
        "ICMP on": f"{LNMS} true",
    }
    at = {step: text.find(line) for step, line in steps.items()}
    assert min(at.values()) >= 0, f"{names(page)} lacks a step: {at}"
    assert list(at.values()) == sorted(at.values()), f"{names(page)}: {at}"


def test_onboard_http_is_only_a_documented_fallback():
    assert "--allow-http" in read(DOCS_DIR / "librenms.md")  # explained in prose
    for page in PAGES:
        for block in shell_blocks(read(page)):
            assert "--allow-http" not in block, names(page)


def test_the_onboard_hostname_values_are_the_ones_the_config_accepts():
    config = importlib.import_module("aimesh_snmp_proxy.config")
    assert set(config.ONBOARD_HOSTNAMES) == {"sysname", "ip"}
    text = read(DOCS_DIR / "instances.md")
    assert 'hostname = "ip"' in text


def test_the_readme_stays_an_entry_page():
    assert len(read(ROOT / "README.md").splitlines()) <= MAX_README_LINES


def test_the_fallback_flag_exists_in_the_onboard_parser():
    onboard = importlib.import_module("aimesh_snmp_proxy.ops.onboard")
    assert onboard._parser().parse_args(["--allow-http"]).allow_http


def test_the_onboard_example_matches_the_example_config():
    text, example = read(DOCS_DIR / "librenms.md"), read(EXAMPLE_CONFIG)
    for line in (
        'url = "https://192.168.50.10"',
        'token_file = "librenms_token"',
        'ca_file = "librenms.pem"',
    ):
        assert line in text, line
        assert f"# {line}" in example, line


def test_the_documented_router_port_is_the_example_port():
    assert tomllib.loads(read(EXAMPLE_CONFIG))["asus"]["port"] == 8443
    assert "8443" in read(DOCS_DIR / "installation.md")


SUDOEDIT = re.compile(r"sudoedit|sudo\s+(?:-\w*e\w*|--edit)\b")


@pytest.mark.parametrize("page", PAGES, ids=names)
def test_the_docs_avoid_sudoedit(page):
    # sudo-rs may lack it, and `sudo -e` is the same thing: use `systemctl edit`.
    assert not SUDOEDIT.search(read(page)), names(page)


@pytest.mark.parametrize("page", PAGES, ids=names)
def test_every_code_block_has_a_known_label(page):
    # The shell checks read sh and bash blocks only: a new label must be added above.
    labels = {match.group(1).strip() for match in FENCE.finditer(read(page))}
    assert labels <= FENCE_LABELS, f"{names(page)}: {sorted(labels - FENCE_LABELS)}"


@pytest.mark.parametrize("page", PAGES, ids=names)
def test_every_toml_block_parses(page):
    for match in FENCE.finditer(read(page)):
        if match.group(1).strip() == "toml":
            try:
                tomllib.loads(match.group(2))
            except tomllib.TOMLDecodeError as error:
                pytest.fail(f"{names(page)}: {error}\n{match.group(2)}")


@pytest.mark.parametrize("page", PAGES, ids=names)
def test_app_is_defined_before_a_block_uses_it(page):
    defined = False
    for block in shell_blocks(read(page)):
        for line in block.splitlines():
            if line.startswith("APP="):
                defined = True
            elif "$APP" in line and not line.lstrip().startswith("#"):
                assert defined, f"{names(page)}: $APP before APP=: {line.strip()}"


def command_parser(command: str):
    module_name, attribute, _ = cli.COMMANDS[command]
    handler = getattr(importlib.import_module(module_name), attribute)
    return getattr(importlib.import_module(handler.__module__), "_parser", None)


PARSED_COMMANDS = [name for name in sorted(cli.COMMANDS) if command_parser(name)]


@pytest.mark.parametrize("command", PARSED_COMMANDS)
def test_the_cli_reference_documents_every_flag(command):
    reference = read(DOCS_DIR / "reference" / "cli.md")
    section = reference.split(f"\n## `{command}`", 1)[1].split("\n## ", 1)[0]
    flags = sorted(
        {
            option
            for action in command_parser(command)()._actions
            for option in action.option_strings
            if option.startswith("--") and option != "--help"
        }
    )
    missing = [
        flag
        for flag in flags
        if not re.search(rf"^\| `{re.escape(flag)}[ `]", section, re.MULTILINE)
    ]
    assert not missing, f"reference/cli.md `{command}` has no table row for: {missing}"


def key_paths(table: dict, prefix: str = "") -> set[tuple[str, str]]:
    """``(table path, key)`` for every key of a parsed TOML file, tables included."""
    found = set()
    for key, value in table.items():
        found.add((prefix, key))
        items = value if isinstance(value, list) else [value]
        for item in items:
            if isinstance(item, dict):
                found |= key_paths(item, f"{prefix}.{key}".lstrip("."))
    return found


def test_the_complete_example_sets_every_key_in_every_table(tmp_path, monkeypatch):
    # The name check above passes when a name such as ca_file is set in one table only.
    read: set[tuple[str, str]] = set()
    real_get = config_module._Table.get

    def spy(self, name, default=config_module._MISSING):
        read.add((re.sub(r"\[\d+\]", "", self.path), name))
        return real_get(self, name, default)

    monkeypatch.setattr(config_module._Table, "get", spy)
    path = tmp_path / "config.toml"
    path.write_text(complete_example())
    load_config(path, env={})
    missing = sorted(read - key_paths(tomllib.loads(complete_example())))
    assert not missing, f"the example omits: {missing}"
