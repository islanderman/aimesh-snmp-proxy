"""``init``: write a config.toml and its secret files for one ASUS router.

Flags answer every question, so automation needs no terminal; on a terminal,
``init`` without ``--host`` asks for each value no flag gave. The router password
comes from getpass or ``--password-stdin``, never from argv; the SNMP community
is random. Files are written 0600 under umask 077 (certificates 0644), and none
is replaced without ``--force``. The loader ``check-config`` uses validates the
result before anything is written.

``--detect`` pins the router certificate as ``discover --pin-cert`` does, then
logs in once to tell an AiMesh root, whose node IPs fill ``nodes.expected``,
from a standalone router, AP or media bridge, which is served as one device.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import getpass
import hashlib
import ipaddress
import os
import re
import secrets
import shlex
import shutil
import stat
import sys
import tempfile
import tomllib
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, TextIO
from urllib.parse import urlsplit

from aimesh_snmp_proxy import __version__
from aimesh_snmp_proxy.collector.discover import pin_certificate
from aimesh_snmp_proxy.collector.mapping import MeshNode
from aimesh_snmp_proxy.collector.service import Collector, Overrides
from aimesh_snmp_proxy.config import (  # the loader's own rules check each answer
    _SYS_NAME,
    DEFAULT_PORT_BASE,
    MAX_CERT_BYTES,
    MAX_PORT,
    MAX_SECRET_BYTES,
    MIN_PORT,
    ROOT_SYS_NAME,
    Config,
    ConfigError,
    _ip_range,
    load_config,
    load_router_pin,
    load_secrets,
)
from aimesh_snmp_proxy.logsafe import SecretStr
from aimesh_snmp_proxy.ports import MAX_INDEX

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_CONFIG = 78  # sysexits EX_CONFIG, as in __main__

ETC_DIR = Path("/etc/aimesh-snmp-proxy")
STATE_DIR = "/var/lib/aimesh-snmp-proxy"
SERVICE = "aimesh-snmp-proxy"
APP = "/opt/aimesh-snmp-proxy/venv/bin/aimesh-snmp-proxy"  # install.sh's --prefix
DEFAULT_HOST = "192.168.50.1"  # the ASUS factory default, offered on a terminal only
DEFAULT_ROUTER_PORT = 8443
DEFAULT_USERNAME = "admin"
PORT_STRIDE = 100  # one block of ports per service: 16101, 16201, 16301, ...
MODES = ("auto", "aimesh", "standalone")
_INSTANCE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?\Z")  # install.sh NAME_RE
CONFIG_FILE = "config.toml"
PASSWORD_FILE = "asus_password"  # noqa: S105 - a file name, not a secret
COMMUNITY_FILE = "snmp_community"
PIN_FILE = "asus_router.pem"
LIBRENMS_CA_FILE = "librenms.pem"
TOKEN_FILE = "librenms_token"  # noqa: S105 - a file name, not a secret
OWNER_ONLY_MODE = 0o600
PUBLIC_MODE = 0o644
QUESTION_TRIES = 3
SEED_STATE_DIR = "/var/lib/aimesh-snmp-proxy"  # install.sh's STATE_LINE
MAX_SEED_BYTES = 65536
# config.example.toml as install.sh seeds it (seed_digest). A test fails when the
# example changes: add the new digest, keep the old ones for older bundles.
SEED_DIGESTS = frozenset(
    {
        "8bca861e2d0cd8a496d3e0e1efdada1b0c1bb28efe2bf0f4c42775418546a150",
    }
)


class InitError(Exception):
    """Stops ``init`` with a one-line message; ``code`` is the exit status."""

    def __init__(self, message: str, code: int = EXIT_FAILED) -> None:
        super().__init__(message)
        self.code = code


# --- answers ---------------------------------------------------------------------


def check_host(text: str) -> str:
    try:
        return str(ipaddress.IPv4Address(text.strip()))
    except ValueError:
        raise ValueError(
            "expected the router's IPv4 address, such as 192.168.50.1"
        ) from None


def _number(text: str, lo: int, hi: int, what: str) -> int:
    try:
        value = int(text, 10)
    except ValueError:
        raise ValueError(f"expected {what} from {lo} to {hi}") from None
    if not lo <= value <= hi:
        raise ValueError(f"expected {what} from {lo} to {hi}")
    return value


def check_port(text: str) -> int:
    return _number(text, 1, MAX_PORT, "a port")


def check_port_base(text: str) -> int:
    return _number(text, MIN_PORT, MAX_PORT - MAX_INDEX, "a port base")


def check_username(text: str) -> str:
    if not text or any(ch in text for ch in "\r\n\0"):
        raise ValueError("expected one non-empty line")
    text.encode()  # a UnicodeEncodeError is a ValueError
    return text


def check_instance(text: str) -> str:
    if not _INSTANCE.match(text):
        raise ValueError(
            "expected 1-32 lower-case letters, digits or '-', not at either end"
        )
    return text


def check_sys_name(text: str) -> str:
    if not _SYS_NAME.match(text):
        raise ValueError("expected 1-63 letters, digits, '.', '_' or '-'")
    return text


def check_nodes(text: str) -> tuple[str, ...]:
    """Comma-separated IPv4 addresses or ranges, kept as typed."""
    items = tuple(item.strip() for item in text.split(",") if item.strip())
    for item in items:
        try:
            _ip_range(item)
        except ValueError:
            raise ValueError(
                "expected IPv4 addresses or ranges like 192.168.50.2-5"
            ) from None
    return items


def check_mode(text: str) -> str:
    if text not in MODES:
        raise ValueError(f"expected one of {', '.join(MODES)}")
    return text


def check_url(text: str) -> str:
    """The loader's ``[onboard] url`` rule, checked before any question follows."""
    try:
        parts = urlsplit(text)
        valid = parts.scheme in ("http", "https") and bool(parts.hostname)
        userinfo = parts.username is not None or parts.password is not None
    except ValueError:
        valid, userinfo = False, False
    if not valid:
        raise ValueError("expected an http or https URL, such as https://192.168.50.10")
    if userinfo:
        raise ValueError("must hold no credentials: onboard reads token_file")
    return text


def check_yes_no(text: str) -> bool:
    answer = text.strip().lower()
    if answer not in ("y", "yes", "n", "no"):
        raise ValueError("expected y or n")
    return answer.startswith("y")


def _optional(check: Callable[[str], Any]) -> Callable[[str], Any]:
    """An empty answer is None; anything else must pass ``check``."""
    return lambda text: check(text) if text else None


def _arg(check: Callable[[str], Any]) -> Callable[[str], Any]:
    """An argparse type that reports ``check``'s message."""

    def convert(text: str) -> Any:
        try:
            return check(text)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(str(exc)) from None

    return convert


def check_password(value: str) -> bytes:
    """The password file's bytes; refuse what read_secret would, never echoing it."""
    if not value:
        raise InitError("the router password is empty", EXIT_USAGE)
    if any(ch in value for ch in "\r\n\0"):
        raise InitError("the router password must be one line", EXIT_USAGE)
    data = (value + "\n").encode("utf-8", "surrogateescape")
    if len(data) > MAX_SECRET_BYTES:
        raise InitError(
            f"the router password must be under {MAX_SECRET_BYTES} bytes", EXIT_USAGE
        )
    return data


# --- config.toml --------------------------------------------------------------------


@dataclass(frozen=True)
class Plan:
    """Everything config.toml says; :func:`render_config` writes it."""

    host: str
    port: int
    username: str
    state_dir: str
    port_base: int
    mode: str  # aimesh, standalone, or auto while nothing told them apart
    nodes: tuple[str, ...] = ()
    sys_name: str | None = None
    librenms_url: str | None = None
    librenms_ca: bool = False


def _toml(value: str) -> str:
    """A TOML basic string that tomllib reads back as ``value``."""
    out = []
    for ch in value:
        if ch in '"\\':
            out.append("\\" + ch)
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def _nodes_lines(plan: Plan) -> list[str]:
    if plan.mode == "aimesh":
        nodes = ", ".join(_toml(node) for node in plan.nodes)
        return [
            "[nodes]",
            "# The AiMesh node IPs, in order: the Nth serves port_base + N.",
            f"expected = [{nodes}]",
        ]
    if plan.mode == "standalone":
        return ["# A standalone router, AP or media bridge is one device: no [nodes]."]
    return [
        "# An AiMesh root serves its nodes too. To keep their ports in IP order,",
        "# list them (discover shows them):",
        "# [nodes]",
        '# expected = ["192.168.50.2", "192.168.50.3"]',
    ]


def render_config(plan: Plan) -> str:
    lines = [
        f"# Written by aimesh-snmp-proxy init {__version__}; check it: check-config.",
        "# Relative *_file paths resolve against $CREDENTIALS_DIRECTORY (systemd",
        "# LoadCredential=), else this file's folder. Secret files must be chmod 600.",
        "",
        "# Must survive restarts: ports.json (port pins), counters.json, lockout.json.",
        f"state_dir = {_toml(plan.state_dir)}",
        "",
        "[asus]",
        f"host = {_toml(plan.host)}",
        f"port = {plan.port}",
        "use_ssl = true  # must stay true: HTTP sends the login in cleartext",
        f"username = {_toml(plan.username)}",
        f"password_file = {_toml(PASSWORD_FILE)}",
        f"ca_file = {_toml(PIN_FILE)}  # the router certificate: discover --pin-cert",
        "",
        *_nodes_lines(plan),
        "",
        "[snmp]",
        'bind = "127.0.0.1"  # the only accepted value',
        f"port_base = {plan.port_base}  # root port; node N serves port_base + N",
        'profile = "asuswrt-merlin"',
        f"community_file = {_toml(COMMUNITY_FILE)}",
        "",
        "[collector]",
        'mode = "root_only"  # per_node adds one router login per node',
        "",
        "[logging]",
        'level = "INFO"',
    ]
    if plan.sys_name is not None:
        lines += [
            "",
            "# The sysName LibreNMS shows for this router.",
            "[[override]]",
            f"match = {_toml(plan.host)}",
            f"sys_name = {_toml(plan.sys_name)}",
        ]
    if plan.librenms_url is not None:
        lines += [
            "",
            "# Only onboard reads [onboard]: a one-shot token file, revoked after use.",
            "[onboard]",
            f"url = {_toml(plan.librenms_url)}",
            f"token_file = {_toml(TOKEN_FILE)}",
        ]
        if plan.librenms_ca:
            lines.append(f"ca_file = {_toml(LIBRENMS_CA_FILE)}  # the LibreNMS pin")
    return "\n".join(lines) + "\n"


# --- port bases -----------------------------------------------------------------------


def port_base_of(path: Path) -> int | None:
    """``snmp.port_base`` as install.sh reads it: unset is the default, and a file
    that is no TOML gives None. A file that cannot be read raises OSError.
    """
    try:
        doc = tomllib.loads(path.read_bytes().decode())
    except (UnicodeDecodeError, tomllib.TOMLDecodeError):
        return None
    snmp = doc.get("snmp")
    if not isinstance(snmp, dict):
        return DEFAULT_PORT_BASE
    base = snmp.get("port_base", DEFAULT_PORT_BASE)
    return base if isinstance(base, int) and not isinstance(base, bool) else None


def other_services(root: Path, own: Path, err: TextIO) -> dict[Path, int]:
    """The port base of the main config and of every instance's in ``root``."""
    try:
        with os.scandir(root) as entries:
            folders = sorted(entry.name for entry in entries if entry.is_dir())
    except FileNotFoundError:
        return {}
    bases = {}
    for path in [root / CONFIG_FILE, *(root / name / CONFIG_FILE for name in folders)]:
        if path == own:
            continue
        try:
            base = port_base_of(path)
        except FileNotFoundError:
            continue
        if base is None:
            print(
                f"warning: {path} is no valid TOML; its port base is skipped", file=err
            )
        else:
            bases[path] = base
    return bases


def overlap(base: int, bases: dict[Path, int]) -> str | None:
    """Why ``base`` clashes with another service's block, or None."""
    for path, other in bases.items():
        if abs(base - other) < PORT_STRIDE:
            return (
                f"snmp.port_base {base} overlaps {path} (port_base {other}): give "
                f"each service its own block of {PORT_STRIDE} (16101, 16201, ...)"
            )
    return None


def free_port_base(bases: dict[Path, int]) -> int:
    for base in range(DEFAULT_PORT_BASE, MAX_PORT - MAX_INDEX + 1, PORT_STRIDE):
        if overlap(base, bases) is None:
            return base
    raise InitError("no free snmp.port_base is left: pass --port-base", EXIT_CONFIG)


# --- detection ----------------------------------------------------------------------


def _is_root(node: MeshNode, root_ip: str | None) -> bool:
    return node.role == "router" or (root_ip is not None and node.ip == root_ip)


def _ip_order(node: MeshNode) -> tuple[int, int, str]:
    try:
        return 0, int(ipaddress.IPv4Address(node.ip or "")), node.mac
    except ValueError:
        return 1, 0, node.mac


async def detect_nodes(cfg: Config, out: TextIO, err: TextIO) -> list[MeshNode]:
    """One root login, as ``discover`` does: the AiMesh nodes beside the root."""
    collector = Collector.from_config(
        cfg,
        load_secrets(cfg),
        load_router_pin(cfg.asus.ca_file),
        overrides=Overrides(),
        node_pin=None,
    )
    try:
        await collector.topology()
    finally:
        await collector.shutdown(persist=False)
    nodes = list(collector.nodes.values())
    if not nodes:
        guard = collector.root.guard
        why = guard.last_failure
        reason = f"{why.outcome} ({why.detail})" if why else f"login {guard.gate()}"
        raise InitError(f"detect: nothing read from {cfg.asus.host}: {reason}")
    mesh = sorted((n for n in nodes if not _is_root(n, cfg.root_ip)), key=_ip_order)
    if mesh:
        count = f"{len(mesh)} node{'s' if len(mesh) > 1 else ''}"
        print(f"detected: an AiMesh root with {count}", file=out)
    else:
        print("detected: a standalone router, AP or media bridge", file=out)
    roots = [n for n in nodes if _is_root(n, cfg.root_ip)]
    for node in [*roots, *mesh]:
        role = "root" if node in roots else "node"
        state = "online" if node.online else "offline"
        print(f"  {role}  {node.ip or '-'}  {node.model or '-'}  {state}", file=out)
    return mesh


# --- files ----------------------------------------------------------------------------


def _write(path: Path, data: bytes, mode: int) -> None:
    """Atomic write: a temp file in the same folder, then a rename."""
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _read_certificate(path: Path) -> bytes:
    """The ``--librenms-ca`` file's bytes; the loader checks them once staged.

    A non-blocking open, so a FIFO cannot hang init.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as exc:
        raise InitError(f"--librenms-ca: cannot read {path}: {exc.strerror}") from None
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise InitError(f"--librenms-ca: {path} is not a regular file")
    with os.fdopen(fd, "rb") as fh:
        data = fh.read(MAX_CERT_BYTES + 1)
    if len(data) > MAX_CERT_BYTES:
        raise InitError(f"--librenms-ca: {path} is larger than {MAX_CERT_BYTES} bytes")
    return data


def seed_digest(text: str, instance: str | None = None) -> str:
    """SHA-256 of a config install.sh seeded, its instance's state_dir line undone."""
    lines = text.splitlines()
    if instance:
        own = f'state_dir = "{SEED_STATE_DIR}-{instance}"'
        seeded = f'state_dir = "{SEED_STATE_DIR}"'
        lines = [seeded if line == own else line for line in lines]
    return hashlib.sha256("\n".join([*lines, ""]).encode()).hexdigest()


def _placeholder(path: Path, instance: str | None) -> bool:
    """An empty file, or config.toml just as install.sh seeded it: nothing to lose."""
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_SEED_BYTES:
            return False
        if st.st_size == 0:
            return True
        if path.name != CONFIG_FILE:
            return False
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False
    return seed_digest(text, instance) in SEED_DIGESTS


def _quote(path: Path) -> str:
    return shlex.quote(str(path))


def _exists(path: Path) -> bool:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise InitError(
            f"cannot check {path}: {exc.strerror}; run as root, or pass --output-dir"
        ) from None
    return True


def _validate(folder: Path, *, pin: bool = False) -> Config:
    """Load the config and its files the way check-config does (environment aside)."""
    cfg = load_config(folder / CONFIG_FILE, env={})
    load_secrets(cfg)
    if pin:
        load_router_pin(cfg.asus.ca_file)
    if cfg.onboard is not None and cfg.onboard.ca_file is not None:
        load_router_pin(cfg.onboard.ca_file, "onboard.ca_file")
    return cfg


# --- the command ----------------------------------------------------------------------


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aimesh-snmp-proxy init",
        description="Write config.toml and its secret files for one ASUS router. "
        "On a terminal, run it without --host to be asked for each value.",
    )
    add = parser.add_argument
    add("--host", type=_arg(check_host), help="router LAN IPv4 address")
    add("--port", type=_arg(check_port), help="router HTTPS port (default 8443)")
    add(
        "--username",
        type=_arg(check_username),
        help="router admin user (default admin)",
    )
    add(
        "--password-stdin",
        action="store_true",
        help="read the router password from the first line of stdin",
    )
    add(
        "--instance",
        type=_arg(check_instance),
        metavar="NAME",
        help="one more router: unit aimesh-snmp-proxy@NAME, folder "
        f"{ETC_DIR}/NAME, its own port block",
    )
    add(
        "--port-base",
        type=_arg(check_port_base),
        help="root SNMP port (default: the first block no other service uses)",
    )
    add(
        "--mode",
        type=_arg(check_mode),
        help="auto (default), aimesh (an AiMesh root), or standalone (a router, "
        "AP or media bridge without AiMesh nodes)",
    )
    add(
        "--nodes",
        type=_arg(check_nodes),
        metavar="IPS",
        help="AiMesh node IPs for nodes.expected, comma-separated; ranges like "
        "192.168.50.2-5 work",
    )
    add(
        "--sys-name",
        type=_arg(check_sys_name),
        help="the sysName LibreNMS shows for the router (default aimesh-root, "
        "or aimesh-NAME with --instance)",
    )
    add(
        "--librenms-url",
        type=_arg(check_url),
        metavar="URL",
        help="LibreNMS URL for onboard, such as https://192.168.50.10",
    )
    add(
        "--librenms-ca",
        type=Path,
        metavar="PATH",
        help="the LibreNMS certificate to pin for onboard (copied as librenms.pem)",
    )
    add(
        "--output-dir",
        type=Path,
        metavar="DIR",
        help=f"where to write (default {ETC_DIR}, or {ETC_DIR}/NAME)",
    )
    add(
        "--detect",
        action="store_true",
        help="pin the router certificate, then log in once to tell an AiMesh root "
        "(listing its nodes) from a standalone device; stop the service first",
    )
    add(
        "--yes",
        action="store_true",
        help="with --detect: pin the router certificate without asking",
    )
    add("--dry-run", action="store_true", help="check and print; write nothing")
    add("--force", action="store_true", help="replace existing files")
    return parser


def _parse(argv: list[str]) -> argparse.Namespace:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.yes and not args.detect:
        parser.error("--yes needs --detect")
    if args.detect and args.nodes is not None:
        parser.error("--nodes and --detect both fill nodes.expected: use one")
    if args.mode == "standalone" and args.nodes:
        parser.error("--nodes lists AiMesh nodes, but --mode is standalone")
    if args.librenms_ca is not None and args.librenms_url is None:
        parser.error("--librenms-ca needs --librenms-url")
    return args


@dataclass
class _Answers:
    instance: str | None
    output: Path
    plan: Plan
    detect: bool
    password: bytes
    librenms_ca: Path | None


class _Init:
    def __init__(
        self,
        args: argparse.Namespace,
        *,
        out: TextIO,
        err: TextIO,
        stdin: TextIO,
        ask: Callable[[str], str],
        secret: Callable[[str], str],
    ) -> None:
        self.args = args
        self.out = out
        self.err = err
        self.stdin = stdin
        self.ask = ask
        self.secret = secret
        self.interactive = args.host is None and stdin.isatty()

    # --- questions ------------------------------------------------------------------

    def question(self, prompt: str, default: str, check: Callable[[str], Any]) -> Any:
        shown = f" [{default}]" if default else ""
        for _ in range(QUESTION_TRIES):
            try:
                text = self.ask(f"{prompt}{shown}: ").strip()
            except EOFError:
                raise InitError(
                    "no answer: pass the values as flags instead", EXIT_USAGE
                ) from None
            try:
                return check(text or default)
            except ValueError as exc:
                print(f"  {exc}", file=self.err)
        raise InitError(f"no valid answer to: {prompt}", EXIT_USAGE)

    def value(
        self, given: Any, prompt: str, default: str, check: Callable[[str], Any]
    ) -> Any:
        """A flag's value, else the answer on a terminal, else ``default``."""
        if given is not None:
            return given
        if self.interactive:
            return self.question(prompt, default, check)
        return check(default)

    def password(self) -> bytes:
        if self.args.password_stdin:
            if self.stdin.isatty():
                raise InitError(
                    "--password-stdin reads a pipe, not a terminal: drop it to be "
                    "asked without echo",
                    EXIT_USAGE,
                )
            text = self.stdin.readline().rstrip("\r\n")
        elif self.stdin.isatty():
            text = self.secret("Router password (not echoed): ")
        else:
            raise InitError(
                "no terminal to ask for the router password: pipe it in with "
                "--password-stdin",
                EXIT_USAGE,
            )
        SecretStr(text)  # registered for log redaction
        return check_password(text)

    def port_base(self, given: int | None, output: Path, instance: str | None) -> int:
        root = output.parent if instance else output
        try:
            bases = other_services(root, output / CONFIG_FILE, self.err)
        except OSError as exc:
            where = exc.filename or root
            if given is None:
                raise InitError(
                    f"cannot read {where} to pick a free snmp.port_base "
                    f"({exc.strerror}): run as root, or pass --port-base"
                ) from None
            print(
                f"warning: cannot read {where} ({exc.strerror}): the port base is "
                "not checked against the other services; install.sh checks it",
                file=self.err,
            )
            bases = {}
        if given is not None:
            problem = overlap(given, bases)
            if problem:
                raise InitError(problem, EXIT_CONFIG)
            return given

        def check(text: str) -> int:
            base = check_port_base(text)
            problem = overlap(base, bases)
            if problem:
                raise ValueError(problem)
            return base

        return self.value(None, "SNMP port base", str(free_port_base(bases)), check)

    def gather(self) -> _Answers:
        a = self.args
        if a.host is None and not self.interactive:
            raise InitError(
                "--host is required without a terminal (run init on one to be asked)",
                EXIT_USAGE,
            )
        instance = self.value(
            a.instance,
            "Instance name, for one more router (empty: the main service)",
            "",
            _optional(check_instance),
        )
        output = (
            a.output_dir or (ETC_DIR / instance if instance else ETC_DIR)
        ).absolute()
        if not a.force:
            self.refuse_existing(output, a.librenms_ca, instance)
        host = self.value(a.host, "Router IPv4 address", DEFAULT_HOST, check_host)
        port = self.value(
            a.port, "Router HTTPS port", str(DEFAULT_ROUTER_PORT), check_port
        )
        username = self.value(
            a.username, "Router admin user", DEFAULT_USERNAME, check_username
        )
        mode = self.value(
            a.mode or ("aimesh" if a.nodes else None),
            "Router type: auto, aimesh or standalone",
            "auto",
            check_mode,
        )
        detect = a.detect
        if not detect and self.interactive and mode != "standalone" and a.nodes is None:
            detect = self.question(
                "Log in once now to detect the type and the AiMesh nodes (y/n)",
                "n",
                check_yes_no,
            )
        nodes = a.nodes
        if nodes is None and mode == "aimesh" and not detect and self.interactive:
            nodes = self.question(
                "AiMesh node IPs, comma-separated (empty: list them later)",
                "",
                check_nodes,
            )
        name = f"aimesh-{instance}" if instance else ROOT_SYS_NAME
        sys_name = self.value(
            a.sys_name, "sysName LibreNMS shows for this router", name, check_sys_name
        )
        port_base = self.port_base(a.port_base, output, instance)
        url = self.value(
            a.librenms_url,
            "LibreNMS URL for onboard (empty: skip)",
            "",
            _optional(check_url),
        )
        ca = a.librenms_ca
        if ca is None and url is not None and self.interactive:
            ca = self.question(
                "LibreNMS certificate to pin (empty: the system trust store)",
                "",
                _optional(Path),
            )
        if not a.force:
            self.refuse_existing(output, ca, instance)
        plan = Plan(
            host=host,
            port=port,
            username=username,
            state_dir=f"{STATE_DIR}-{instance}" if instance else STATE_DIR,
            port_base=port_base,
            mode=mode,
            nodes=nodes or (),
            sys_name=None if sys_name == ROOT_SYS_NAME else sys_name,
            librenms_url=url,
            librenms_ca=ca is not None,
        )
        return _Answers(instance, output, plan, detect, self.password(), ca)

    def refuse_existing(
        self, output: Path, librenms_ca: Path | None, instance: str | None
    ) -> None:
        """Refuse to replace a file that holds anything but install.sh's seed."""
        names = [CONFIG_FILE, PASSWORD_FILE, COMMUNITY_FILE]
        if librenms_ca is not None:
            names.append(LIBRENMS_CA_FILE)
        existing = [
            name
            for name in names
            if _exists(output / name) and not _placeholder(output / name, instance)
        ]
        if existing:
            raise InitError(
                f"{output} already holds {', '.join(existing)}: pass --force to replace"
            )

    # --- the run ---------------------------------------------------------------------

    def run(self) -> int:
        answers = self.gather()
        with tempfile.TemporaryDirectory(prefix="aimesh-init-") as tmp:
            return self.build(answers, Path(tmp))

    def build(self, answers: _Answers, stage: Path) -> int:
        community = secrets.token_hex(16)
        SecretStr(community)  # registered for log redaction
        files = [
            (PASSWORD_FILE, answers.password, OWNER_ONLY_MODE),
            (COMMUNITY_FILE, f"{community}\n".encode(), OWNER_ONLY_MODE),
        ]
        if answers.librenms_ca is not None:
            files.append(
                (LIBRENMS_CA_FILE, _read_certificate(answers.librenms_ca), PUBLIC_MODE)
            )
        for name, data, mode in files:
            _write(stage / name, data, mode)
        plan = answers.plan
        pinned = False
        if answers.detect:
            plan = self.detect(plan, stage, answers)
            pinned = True
        text = render_config(plan)
        _write(stage / CONFIG_FILE, text.encode(), OWNER_ONLY_MODE)
        self.check(stage, answers.librenms_ca)
        names = [name for name, _, _ in files] + [CONFIG_FILE]
        if self.args.dry_run:
            self.show(answers, text, names)
            return EXIT_OK
        replaced, seeds = self.install(answers, stage, names, pinned=pinned)
        self.report(answers, plan, names, (replaced, seeds), pinned)
        return EXIT_OK

    def detect(self, plan: Plan, stage: Path, answers: _Answers) -> Plan:
        _write(stage / CONFIG_FILE, render_config(plan).encode(), OWNER_ONLY_MODE)
        cfg = self.check(stage, answers.librenms_ca)
        output = answers.output
        unit = f"{SERVICE}@{answers.instance}" if answers.instance else SERVICE
        print(
            f"warning: --detect logs in to {plan.host} once, and the router takes "
            f"one admin session: stop the service that polls it first (systemctl "
            f"stop {unit})",
            file=self.err,
        )
        print(
            "warning: the proxy keeps to 6 router logins per hour; detect, discover "
            "and selftest each spend one",
            file=self.err,
        )
        pin = output / PIN_FILE  # pinning creates the folder, 0700 under our umask
        if self.args.dry_run:  # the pin goes to the stage, compared with the kept one
            pin = stage / PIN_FILE
            with contextlib.suppress(FileNotFoundError):
                shutil.copyfile(output / PIN_FILE, pin)
        # The service's own state_dir is left alone: no lockout.json is written there.
        cfg = replace(
            cfg, state_dir=stage / "state", asus=replace(cfg.asus, ca_file=pin)
        )
        code = asyncio.run(
            pin_certificate(cfg, pin, self.args.yes, self.out, self.err, self.ask)
        )
        if code != EXIT_OK:
            raise InitError("the router certificate is not pinned: no login, no config")
        mesh = asyncio.run(detect_nodes(cfg, self.out, self.err))
        return self.use_detection(plan, mesh)

    def use_detection(self, plan: Plan, mesh: list[MeshNode]) -> Plan:
        for node in mesh:
            if not node.ip:
                print(
                    f"warning: the node {node.model or node.mac[-8:]} has no IP: it is "
                    "left out of nodes.expected and takes the next free port",
                    file=self.err,
                )
        ips = tuple(dict.fromkeys(node.ip for node in mesh if node.ip))
        count = f"{len(mesh)} AiMesh node{'s' if len(mesh) > 1 else ''}"
        if plan.mode == "standalone":
            if mesh:
                print(
                    f"warning: the router lists {count}: they are served too, on the "
                    "next free ports, as nodes.expected stays unset",
                    file=self.err,
                )
            return plan
        if not mesh:
            if plan.mode == "aimesh":
                print(
                    "warning: the router lists no AiMesh nodes: it is served as one "
                    "device",
                    file=self.err,
                )
                return plan
            return replace(plan, mode="standalone")
        return replace(plan, mode="aimesh", nodes=ips)

    def check(self, stage: Path, librenms_ca: Path | None) -> Config:
        """Validate the staged files; name the user's certificate, not the stage."""
        try:
            return _validate(stage)
        except ConfigError as exc:
            message = str(exc)
            if librenms_ca is not None:
                message = message.replace(
                    str(stage / LIBRENMS_CA_FILE), str(librenms_ca)
                )
            raise InitError(f"config error: {message}", EXIT_CONFIG) from None

    def install(
        self, answers: _Answers, stage: Path, names: list[str], *, pinned: bool
    ) -> tuple[list[str], list[str]]:
        """Copy the staged files in, config.toml last: it names the others.

        A pin is checked only when this run made it: install.sh's empty
        placeholder waits for discover --pin-cert.
        """
        output = answers.output
        try:
            output.mkdir(mode=0o700, parents=True, exist_ok=True)
            present = [name for name in names if _exists(output / name)]
            seeds = [n for n in present if _placeholder(output / n, answers.instance)]
            replaced = [name for name in present if name not in seeds]
            for name in names:
                source = stage / name
                _write(
                    output / name,
                    source.read_bytes(),
                    stat.S_IMODE(source.stat().st_mode),
                )
        except OSError as exc:
            raise InitError(
                f"cannot write {exc.filename or output}: {exc.strerror}; run as root, "
                "or pass --output-dir"
            ) from None
        try:
            _validate(output, pin=pinned)
        except ConfigError as exc:
            raise InitError(f"config error: {exc}", EXIT_CONFIG) from None
        return replaced, seeds

    def show(self, answers: _Answers, text: str, names: list[str]) -> None:
        what = {
            PASSWORD_FILE: "the router password",
            COMMUNITY_FILE: "a new random SNMP community",
            LIBRENMS_CA_FILE: f"a copy of {answers.librenms_ca}",
        }
        print(f"dry run: nothing written. {answers.output} would get:", file=self.out)
        for name in names[:-1]:
            mode = PUBLIC_MODE if name == LIBRENMS_CA_FILE else OWNER_ONLY_MODE
            print(f"  {name} ({mode:04o}): {what[name]}", file=self.out)
        print(f"  {CONFIG_FILE} ({OWNER_ONLY_MODE:04o}):", file=self.out)
        print(text, end="", file=self.out)
        print("config ok: check-config's loader accepts it", file=self.out)

    def report(
        self,
        answers: _Answers,
        plan: Plan,
        names: list[str],
        replaced_and_seeds: tuple[list[str], list[str]],
        pinned: bool,
    ) -> None:
        output = answers.output
        replaced, seeds = replaced_and_seeds
        print(f"wrote {output}: {', '.join(names)}", file=self.out)
        if replaced:
            print(f"replaced: {', '.join(replaced)}", file=self.out)
        if seeds:
            print(
                f"replaced install.sh's placeholders: {', '.join(seeds)}", file=self.out
            )
        if COMMUNITY_FILE in replaced:
            print(
                "warning: snmp_community is new: LibreNMS devices onboarded before "
                "need it",
                file=self.err,
            )
        print(
            f"config ok: snmp.port_base {plan.port_base} (node N serves "
            f"{plan.port_base} + N), state_dir {plan.state_dir}",
            file=self.out,
        )
        for line in self.next_steps(answers, plan, pinned):
            print(line, file=self.out)

    def next_steps(self, answers: _Answers, plan: Plan, pinned: bool) -> list[str]:
        """The onboarding steps, with the paths install.sh and the unit read."""
        instance = answers.instance
        output = ETC_DIR / instance if instance else ETC_DIR
        unit = f"{SERVICE}@{instance}" if instance else SERVICE
        installer = "deploy/install.sh" + (
            f" --instance {instance}" if instance else ""
        )
        app = f"sudo $APP -c {_quote(output / CONFIG_FILE)}"
        steps = [
            f"sudo {installer}  (again if it ran before: the unit reads asus.host)"
        ]
        if not pinned:
            steps.append(
                f"{app} discover --pin-cert {_quote(output / PIN_FILE)}  (compare the "
                "fingerprint with the router's)"
            )
        steps += [
            f"{app} discover  (one router login: lists the nodes and their ports)",
            f"{app} check-config",
            f"{app} selftest  (with the service stopped)",
            f"sudo systemctl enable --now {unit}",
        ]
        if plan.librenms_url is not None:
            steps.append(
                f"put a LibreNMS API token in {_quote(output / TOKEN_FILE)} (0600), "
                f"then {app} onboard, then onboard --apply"
            )
        else:
            steps.append(
                f"add [onboard] (or re-run init with --librenms-url), then {app} "
                "onboard --apply"
            )
        if answers.output != output:
            steps.insert(0, f"move the files to {_quote(output)} (0700, owned by root)")
        lines = ["", f"Next steps (APP={APP}):"]
        lines += [f"  {number}. {step}" for number, step in enumerate(steps, 1)]
        return lines


def cli_init(
    cfg: Any,
    argv: list[str],
    *,
    out: TextIO | None = None,
    err: TextIO | None = None,
    stdin: TextIO | None = None,
    ask: Callable[[str], str] = input,
    secret: Callable[[str], str] = getpass.getpass,
) -> int:
    """Entry point for ``aimesh-snmp-proxy init``; it never reads a config."""
    del cfg
    args = _parse(argv)
    session = _Init(
        args,
        out=out or sys.stdout,
        err=err or sys.stderr,
        stdin=stdin or sys.stdin,
        ask=ask,
        secret=secret,
    )
    umask = os.umask(0o077)
    try:
        return session.run()
    except InitError as exc:
        print(f"init: {exc}", file=session.err)
        return exc.code
    except OSError as exc:  # a folder or file the user cannot read or write
        print(f"init: {exc.filename or 'a file'}: {exc.strerror}", file=session.err)
        return EXIT_FAILED
    finally:
        os.umask(umask)
