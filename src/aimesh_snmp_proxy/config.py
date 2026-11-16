"""Load and validate the TOML configuration; read owner-only secret files.

Nodes come from the AiMesh list (none for a standalone router); ``[[override]]``
entries rename, pin, or exclude them. Secrets live only in files: a relative
``*_file`` path resolves against ``$CREDENTIALS_DIRECTORY`` (systemd
``LoadCredential=``) when set, else the config file's directory.
``AIMESH_PROXY__<SECTION>__<KEY>`` overrides any key but ``[[override]]``
entries. Errors name keys and paths, never values; a
secret file's errors name its key and directory only, as its configured name
may be the secret itself, typed in by mistake.

``state_dir`` holds the files that must survive restarts: ``ports.json``
(:mod:`aimesh_snmp_proxy.ports`), ``counters.json`` (derived octet counters)
and ``lockout.json`` (router refusal latch); the collector owns the last two.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import math
import os
import pwd
import re
import ssl
import stat
import struct
import tomllib
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography import x509

from aimesh_snmp_proxy.logsafe import LEVELS, SecretStr, register_secret
from aimesh_snmp_proxy.model import normalize_mac
from aimesh_snmp_proxy.ports import MAX_INDEX, PORTS_FILE

ENV_PREFIX = "AIMESH_PROXY__"
DEFAULT_STATE_DIR = Path("/var/lib/aimesh-snmp-proxy")
DEFAULT_PROFILE = "asuswrt-merlin"
DEFAULT_PORT_BASE = 16101
DEFAULT_ONBOARD_URL = "http://127.0.0.1"
ONBOARD_HOSTNAMES = ("sysname", "ip")
ROOT_SYS_NAME = "aimesh-root"
SNMP_BIND = "127.0.0.1"  # LibreNMS polls over loopback on this host
COUNTERS_FILE = "counters.json"
LOCKOUT_FILE = "lockout.json"
AUTH_PROTOCOLS = ("SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512")
PRIV_PROTOCOLS = ("AES-128",)
COLLECTOR_MODES = ("root_only", "per_node")
MIN_PORT = 1024
MAX_PORT = 65535
MAX_SECRET_BYTES = 4096
MAX_CERT_BYTES = 65536
MIN_USM_KEY_CHARS = 8  # RFC 3414 passphrase minimum
SCHEDULE_JITTER = 0.10  # collector cadence jitter, design section 3

_TOP_KEYS = ("state_dir",)
_SECTIONS = ("asus", "nodes", "snmp", "collector", "logging", "onboard")
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_HOSTNAME = re.compile(rf"(?=.{{1,253}}\Z){_LABEL}(?:\.{_LABEL})*\Z")
_SYS_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}\Z")
_PROFILE = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}\Z")
_USM_USER = re.compile(r"[A-Za-z0-9._-]{1,32}\Z")
_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off"})


class ConfigError(ValueError):
    """Invalid configuration. Messages name keys and paths, never secret values."""


@dataclass(frozen=True)
class AsusConfig:
    """The router link is HTTPS only, pinned to ``ca_file`` (security H1).

    ``node_ca_file`` is the CA that issued the AiMesh nodes' certificates; with
    it, per_node mode verifies each node session by that CA and the node IP.
    """

    host: str
    username: str
    password_file: Path
    ca_file: Path
    port: int | None = None
    use_ssl: bool = True
    node_ca_file: Path | None = None


@dataclass(frozen=True)
class NodesConfig:
    expected: tuple[str, ...] = ()


@dataclass(frozen=True)
class V3Config:
    user: str
    auth_key_file: Path
    priv_key_file: Path
    auth: str = "SHA-256"
    priv: str = "AES-128"


@dataclass(frozen=True)
class SnmpConfig:
    bind: str = SNMP_BIND
    port_base: int = DEFAULT_PORT_BASE
    profile: str = DEFAULT_PROFILE
    community_file: Path | None = None
    v3: V3Config | None = None


@dataclass(frozen=True)
class CollectorConfig:
    mode: str = "root_only"
    stale_after_s: float = 180.0
    metrics_interval_s: float = 60.0
    topology_interval_s: float = 300.0
    request_timeout_s: float = 10.0


@dataclass(frozen=True)
class LoggingConfig:
    level: str = "INFO"


@dataclass(frozen=True)
class OnboardConfig:
    """Read only by ``onboard``; its files are checked when it runs.

    ``hostname`` names the LibreNMS device: the served sysName, or the node's LAN IP.
    """

    url: str = DEFAULT_ONBOARD_URL
    token_file: Path | None = None
    ca_file: Path | None = None
    hostname: str = "sysname"


@dataclass(frozen=True)
class Override:
    """Per-node settings; ``match`` is a normalized MAC or an IPv4 address."""

    match: str
    sys_name: str | None = None
    port: int | None = None
    login: bool = True
    location: str | None = None
    exclude: bool = False
    ca_file: Path | None = None


def default_sys_name(mac: str) -> str:
    """``aimesh-`` plus the last 6 hex digits of the MAC."""
    return "aimesh-" + mac.replace(":", "")[-6:]


def _ipv4_or_none(text: str | None) -> str | None:
    """Canonical IPv4 text, or None; router data is untrusted, so never raise."""
    if text is None:
        return None
    try:
        return str(ipaddress.IPv4Address(text))
    except ValueError:
        return None


@dataclass(frozen=True)
class Config:
    source: Path
    state_dir: Path
    asus: AsusConfig
    snmp: SnmpConfig
    nodes: NodesConfig = field(default_factory=NodesConfig)
    overrides: tuple[Override, ...] = ()
    collector: CollectorConfig = field(default_factory=CollectorConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    onboard: OnboardConfig | None = None

    @property
    def ports_file(self) -> Path:
        return self.state_dir / PORTS_FILE

    @property
    def counters_file(self) -> Path:
        return self.state_dir / COUNTERS_FILE

    @property
    def lockout_file(self) -> Path:
        return self.state_dir / LOCKOUT_FILE

    def secret_files(self, *, onboard: bool = False) -> dict[str, Path]:
        """The daemon's secret files by config key; ``onboard`` adds its token."""
        files = {"asus.password_file": self.asus.password_file}
        if self.snmp.community_file is not None:
            files["snmp.community_file"] = self.snmp.community_file
        if self.snmp.v3 is not None:
            files["snmp.v3.auth_key_file"] = self.snmp.v3.auth_key_file
            files["snmp.v3.priv_key_file"] = self.snmp.v3.priv_key_file
        if onboard and self.onboard is not None and self.onboard.token_file:
            files["onboard.token_file"] = self.onboard.token_file
        return files

    @property
    def root_ip(self) -> str | None:
        """The root router's IPv4 address, when ``asus.host`` is one."""
        return _ipv4_or_none(self.asus.host)

    def override_for(self, mac: str, ip: str | None = None) -> Override | None:
        """The override matching the node's MAC, else its IP, else None."""
        key = normalize_mac(mac)
        for override in self.overrides:
            if override.match == key:
                return override
        address = _ipv4_or_none(ip)
        for override in self.overrides:
            if address is not None and override.match == address:
                return override
        return None

    def root_sys_name(self) -> str | None:
        """The root's sysName without a router login; None if it is excluded."""
        override = self.override_for("", self.root_ip)
        if override is not None and override.exclude:
            return None
        if override is not None and override.sys_name:
            return override.sys_name
        return ROOT_SYS_NAME

    def sys_names(
        self, nodes: Iterable[tuple[str, str | None]], *, root_mac: str | None = None
    ) -> dict[str, str]:
        """A unique sysName per served ``(mac, ip)``; excluded nodes are skipped.

        Override names win. The root (its IP is ``asus.host``, or its MAC is
        ``root_mac``) is ``aimesh-root``; others get ``aimesh-<6 hex>``. A name
        that clashes falls back to the full MAC, so LibreNMS never sees twins.
        """
        root_key = normalize_mac(root_mac) if root_mac else None
        names: dict[str, str] = {}
        generated: list[str] = []
        root_default: str | None = None
        for mac, ip in nodes:
            key = normalize_mac(mac)
            if key is None:
                raise ValueError("not a MAC address")
            override = self.override_for(key, ip)
            if override is not None and override.exclude:
                continue
            if override is not None and override.sys_name:
                names[key] = override.sys_name
            elif key == root_key or (
                self.root_ip is not None and _ipv4_or_none(ip) == self.root_ip
            ):
                root_default = key
            else:
                generated.append(key)
        taken = {name.lower() for name in names.values()}
        if root_default is not None:
            name = ROOT_SYS_NAME
            if name in taken:
                name = "aimesh-" + root_default.replace(":", "")
            names[root_default] = name
            taken.add(name)
        short = Counter(default_sys_name(mac) for mac in generated)
        for mac in generated:
            name = default_sys_name(mac)
            if short[name] > 1 or name in taken:
                name = "aimesh-" + mac.replace(":", "")
            names[mac] = name
            taken.add(name)
        return names


# --- raw TOML access ---------------------------------------------------------


class _EnvValue(str):
    """A raw string from an environment override; getters coerce it."""

    var: str


_MISSING: Any = object()


def _kind(value: object) -> str:
    for typ, name in (
        (bool, "boolean"),
        (int, "integer"),
        (float, "number"),
        (str, "string"),
        (list, "list"),
        (dict, "table"),
    ):
        if isinstance(value, typ):
            return name
    return type(value).__name__


class _Table:
    """Typed, strict access to one TOML table; unread keys are errors."""

    def __init__(self, data: Mapping[str, Any], path: str) -> None:
        self.data = data
        self.path = path
        self.read: set[str] = set()

    def key(self, name: str) -> str:
        return f"{self.path}.{name}" if self.path else name

    def where(self, name: str) -> str:
        var = getattr(self.data.get(name), "var", None)
        return f"{self.key(name)} (from ${var})" if var else self.key(name)

    def error(self, name: str, problem: str) -> ConfigError:
        return ConfigError(f"{self.where(name)}: {problem}")

    def get(self, name: str, default: Any = _MISSING) -> Any:
        self.read.add(name)
        if name in self.data:
            return self.data[name]
        if default is _MISSING:
            raise ConfigError(f"{self.key(name)}: required")
        return default

    def str_(self, name: str, default: Any = _MISSING) -> Any:
        value = self.get(name, default)
        if name in self.data and not isinstance(value, str):
            raise self.error(name, f"expected a string, got {_kind(value)}")
        return value

    def int_(self, name: str, default: Any, lo: int, hi: int) -> Any:
        value = self.get(name, default)
        if name not in self.data:
            return value
        if isinstance(value, _EnvValue):
            try:
                value = int(value, 10)
            except ValueError:
                raise self.error(name, "expected an integer") from None
        elif isinstance(value, bool) or not isinstance(value, int):
            raise self.error(name, f"expected an integer, got {_kind(value)}")
        if not lo <= value <= hi:
            raise self.error(name, f"must be between {lo} and {hi}")
        return value

    def positive(self, name: str, default: float) -> float:
        value = self.get(name, default)
        if name not in self.data:
            return value
        if isinstance(value, _EnvValue):
            try:
                value = float(value)
            except ValueError:
                raise self.error(name, "expected a number") from None
        elif isinstance(value, bool) or not isinstance(value, int | float):
            raise self.error(name, f"expected a number, got {_kind(value)}")
        if not math.isfinite(value):
            raise self.error(name, "expected a number")
        if value <= 0:
            raise self.error(name, "must be a positive number")
        return value

    def bool_(self, name: str, default: bool) -> bool:
        value = self.get(name, default)
        if isinstance(value, _EnvValue):
            if value.strip().lower() in _TRUE | _FALSE:
                return value.strip().lower() in _TRUE
            raise self.error(name, "expected true or false")
        if not isinstance(value, bool):
            raise self.error(name, f"expected true or false, got {_kind(value)}")
        return value

    def str_list(self, name: str, default: list[str]) -> list[str]:
        """A string or a list of strings; env values split on commas."""
        value = self.get(name, default)
        if isinstance(value, _EnvValue):
            return [item.strip() for item in value.split(",") if item.strip()]
        if isinstance(value, str):
            return [value]
        if not isinstance(value, list):
            raise self.error(name, f"expected a list, got {_kind(value)}")
        if not all(isinstance(item, str) for item in value):
            raise self.error(name, "expected a list of strings")
        return value

    def table(self, name: str, *, required: bool = False) -> _Table | None:
        value = self.get(name, _MISSING if required else None)
        if value is None:
            return None
        if not isinstance(value, dict):
            raise self.error(name, "expected a table")
        return _Table(value, self.key(name))

    def done(self) -> None:
        """Reject keys no getter asked for; flag inline secrets without echo."""
        for name in sorted(set(self.data) - self.read):
            if f"{name}_file" in self.read:
                raise self.error(
                    name, f"inline secrets are not allowed; use {name}_file"
                )
            if self.path and name in _TOP_KEYS:
                raise self.error(
                    name, f"{name} belongs at the top of the file, before any [section]"
                )
            raise self.error(name, "unknown key")


class _Files:
    """Resolves ``*_file`` keys: relative paths use the credentials directory."""

    def __init__(self, config_dir: Path, credentials_dir: str | None) -> None:
        self.base = Path(credentials_dir) if credentials_dir else config_dir

    def path(self, table: _Table, name: str, *, required: bool = True) -> Any:
        value = table.str_(name, _MISSING if required else None)
        if value is None:
            return None
        if not value or "\0" in value:
            raise table.error(name, "expected a file path")
        path = Path(value)
        return path if path.is_absolute() else self.base / path


# --- environment overrides ---------------------------------------------------


def _apply_env(raw: dict[str, Any], env: Mapping[str, str]) -> None:
    for var in sorted(env):
        if not var.startswith(ENV_PREFIX):
            continue
        parts = var[len(ENV_PREFIX) :].lower().split("__")
        if not all(parts) or (len(parts) == 1 and parts[0] not in _TOP_KEYS):
            raise ConfigError(f"${var}: expected {ENV_PREFIX}<SECTION>__<KEY>")
        if parts[0] == "override":
            raise ConfigError(f"${var}: [[override]] entries cannot be set from env")
        if len(parts) > 1 and parts[0] not in _SECTIONS:
            raise ConfigError(f"${var}: unknown section {parts[0]!r}")
        table = raw
        for depth, part in enumerate(parts[:-1], start=1):
            child = table.setdefault(part, {})
            if not isinstance(child, dict):
                raise ConfigError(f"${var}: {'.'.join(parts[:depth])} is not a table")
            table = child
        if isinstance(table.get(parts[-1]), dict):
            raise ConfigError(f"${var}: cannot replace table {'.'.join(parts)}")
        value = _EnvValue(env[var])
        value.var = var
        table[parts[-1]] = value


# --- sections ----------------------------------------------------------------


def _valid_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return _HOSTNAME.match(host) is not None
    return True


def _parse_asus(t: _Table, files: _Files) -> AsusConfig:
    host = t.str_("host")
    if not _valid_host(host):
        raise t.error("host", "expected a hostname or IP address")
    username = t.str_("username")
    if not username or any(ch in username for ch in "\r\n\0"):
        raise t.error("username", "expected one non-empty line")
    if not t.bool_("use_ssl", True):
        raise t.error(
            "use_ssl", "must be true; plain HTTP sends the admin login in cleartext"
        )
    cfg = AsusConfig(
        host=host,
        username=username,
        password_file=files.path(t, "password_file"),
        ca_file=files.path(t, "ca_file"),
        port=t.int_("port", None, 1, MAX_PORT),
        node_ca_file=files.path(t, "node_ca_file", required=False),
    )
    t.done()
    return cfg


def _ip_range(item: str) -> list[str]:
    """``a.b.c.d``, ``a.b.c.d-e`` (last octet), or ``a.b.c.d-a.b.c.e``."""
    first, sep, last = item.strip().partition("-")
    start = ipaddress.IPv4Address(first.strip())
    if not sep:
        return [str(start)]
    last = last.strip()
    if last.isdigit():
        end = ipaddress.IPv4Address(int(start) - int(start) % 256 + int(last))
        if int(last) > 255:
            raise ValueError(item)
    else:
        end = ipaddress.IPv4Address(last)
    if end < start or int(end) - int(start) >= MAX_INDEX:
        raise ValueError(item)
    return [str(ipaddress.IPv4Address(n)) for n in range(int(start), int(end) + 1)]


def _parse_nodes(t: _Table | None) -> NodesConfig:
    if t is None:
        return NodesConfig()
    expected: list[str] = []
    for item in t.str_list("expected", []):
        try:
            expected += _ip_range(item)
        except ValueError:
            raise t.error(
                "expected", "expected IPv4 addresses or ranges like 192.168.50.101-110"
            ) from None
    if len(set(expected)) != len(expected):
        raise t.error("expected", "lists an address twice")
    if len(expected) > MAX_INDEX:
        raise t.error("expected", f"at most {MAX_INDEX} addresses")
    t.done()
    return NodesConfig(expected=tuple(expected))


def _parse_snmp(t: _Table, files: _Files) -> SnmpConfig:
    bind = t.str_("bind", SNMP_BIND)
    if bind != SNMP_BIND:
        raise t.error(
            "bind", f"must be {SNMP_BIND}: LibreNMS polls over loopback on this host"
        )
    profile = t.str_("profile", DEFAULT_PROFILE)
    if not _PROFILE.match(profile):
        raise t.error("profile", "expected a profile name like asuswrt-merlin")
    cfg = SnmpConfig(
        bind=bind,
        port_base=t.int_(
            "port_base", DEFAULT_PORT_BASE, MIN_PORT, MAX_PORT - MAX_INDEX
        ),
        profile=profile,
        community_file=files.path(t, "community_file", required=False),
        v3=_parse_v3(t.table("v3"), files),
    )
    if cfg.community_file is None and cfg.v3 is None:
        raise ConfigError(f"{t.path}: set community_file (v2c) or add [snmp.v3]")
    t.done()
    return cfg


def _parse_v3(t: _Table | None, files: _Files) -> V3Config | None:
    if t is None:
        return None
    user = t.str_("user")
    if not _USM_USER.match(user):
        raise t.error("user", "expected 1-32 letters, digits, '.', '_' or '-'")
    auth = t.str_("auth", "SHA-256").upper()
    if auth not in AUTH_PROTOCOLS:
        raise t.error("auth", f"must be one of {', '.join(AUTH_PROTOCOLS)}")
    priv = t.str_("priv", "AES-128").upper()
    if priv not in PRIV_PROTOCOLS:
        raise t.error("priv", f"must be one of {', '.join(PRIV_PROTOCOLS)}")
    cfg = V3Config(
        user=user,
        auth_key_file=files.path(t, "auth_key_file"),
        priv_key_file=files.path(t, "priv_key_file"),
        auth=auth,
        priv=priv,
    )
    t.done()
    return cfg


def _parse_collector(t: _Table | None) -> CollectorConfig:
    if t is None:
        return CollectorConfig()
    mode = t.str_("mode", "root_only")
    if mode not in COLLECTOR_MODES:
        raise t.error("mode", f"must be one of {', '.join(COLLECTOR_MODES)}")
    d = CollectorConfig()
    cfg = CollectorConfig(
        mode=mode,
        stale_after_s=t.positive("stale_after_s", d.stale_after_s),
        metrics_interval_s=t.positive("metrics_interval_s", d.metrics_interval_s),
        topology_interval_s=t.positive("topology_interval_s", d.topology_interval_s),
        request_timeout_s=t.positive("request_timeout_s", d.request_timeout_s),
    )
    if cfg.stale_after_s <= cfg.metrics_interval_s * (1 + SCHEDULE_JITTER):
        raise t.error(
            "stale_after_s",
            "must exceed metrics_interval_s plus 10% jitter, "
            "or every node goes silent between polls",
        )
    t.done()
    return cfg


def _parse_logging(t: _Table | None) -> LoggingConfig:
    if t is None:
        return LoggingConfig()
    level = t.str_("level", "INFO").upper()
    if level not in LEVELS:
        raise t.error("level", f"must be one of {', '.join(LEVELS)}")
    t.done()
    return LoggingConfig(level=level)


def _parse_onboard(t: _Table | None, files: _Files) -> OnboardConfig | None:
    if t is None:
        return None
    url = t.str_("url", DEFAULT_ONBOARD_URL)
    try:
        parts = urlsplit(url)
        valid = parts.scheme in ("http", "https") and bool(parts.hostname)
        has_userinfo = parts.username is not None or parts.password is not None
    except ValueError:
        valid = False
    if not valid:
        raise t.error("url", "expected an http or https URL")
    if has_userinfo:
        raise t.error("url", "must not contain credentials; use token_file")
    hostname = t.str_("hostname", "sysname")
    if hostname not in ONBOARD_HOSTNAMES:
        raise t.error("hostname", 'must be "sysname" or "ip"')
    cfg = OnboardConfig(
        url=url,
        token_file=files.path(t, "token_file", required=False),
        ca_file=files.path(t, "ca_file", required=False),
        hostname=hostname,
    )
    t.done()
    return cfg


def _parse_override(
    t: _Table, port_base: int, root_ip: str | None, files: _Files
) -> Override:
    raw = t.str_("match")
    try:
        match = str(ipaddress.IPv4Address(raw))
    except ValueError:
        match = normalize_mac(raw)
        if match is None:
            raise t.error("match", "expected an IPv4 or MAC address") from None
    sys_name = t.str_("sys_name", None)
    if sys_name is not None and not _SYS_NAME.match(sys_name):
        raise t.error("sys_name", "expected 1-63 letters, digits, '.', '_' or '-'")
    location = t.str_("location", None)
    if location is not None and len(location) > 255:
        raise t.error("location", "at most 255 characters")
    override = Override(
        match=match,
        sys_name=sys_name,
        port=t.int_("port", None, port_base + 1, port_base + MAX_INDEX),
        login=t.bool_("login", True),
        location=location,
        exclude=t.bool_("exclude", False),
        ca_file=files.path(t, "ca_file", required=False),
    )
    others = ("sys_name", "port", "login", "location", "ca_file")
    if override.exclude and any(key in t.data for key in others):
        raise ConfigError(f"{t.path}: an excluded node takes no other settings")
    if override.ca_file is not None and not override.login:
        raise t.error("ca_file", "pins a node session, which login = false turns off")
    claims_root_name = sys_name is not None and sys_name.lower() == ROOT_SYS_NAME
    other_ip = _ipv4_or_none(match) is not None and match != root_ip
    if claims_root_name and other_ip and root_ip is not None:
        raise t.error("sys_name", f"{ROOT_SYS_NAME} is reserved for the root router")
    t.done()
    return override


def _parse_overrides(
    raw: Any, port_base: int, root_ip: str | None, files: _Files
) -> tuple[Override, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list) or not all(isinstance(o, dict) for o in raw):
        raise ConfigError("override: expected [[override]] tables")
    seen: dict[tuple[str, str], int] = {}
    overrides = []
    for index, item in enumerate(raw):
        path = f"override[{index}]"
        override = _parse_override(_Table(item, path), port_base, root_ip, files)
        claims = [("match", override.match)]
        if override.sys_name:
            claims.append(("sys_name", override.sys_name.lower()))
        if override.port is not None:
            claims.append(("port", str(override.port)))
        for claim in claims:
            if claim in seen:
                raise ConfigError(
                    f"{path}: duplicate {claim[0]} (same as override[{seen[claim]}])"
                )
            seen[claim] = index
        overrides.append(override)
    return tuple(overrides)


# --- entry point -------------------------------------------------------------


def load_config(
    path: str | os.PathLike[str], env: Mapping[str, str] | None = None
) -> Config:
    """Parse, override from ``env`` (default ``os.environ``), and validate."""
    env = os.environ if env is None else env
    source = Path(path).absolute()
    try:
        with source.open("rb") as fh:
            raw = tomllib.load(fh)
    except FileNotFoundError:
        raise ConfigError(f"config file not found: {source}") from None
    except OSError as exc:
        raise ConfigError(f"cannot read config file {source}: {exc.strerror}") from None
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {source}: {exc}") from None
    _apply_env(raw, env)
    files = _Files(source.parent, env.get("CREDENTIALS_DIRECTORY"))
    top = _Table(raw, "")
    state_default = env.get("STATE_DIRECTORY", "").split(":")[0] or DEFAULT_STATE_DIR
    state_dir = Path(top.str_("state_dir", str(state_default)))
    if not state_dir.is_absolute():
        raise top.error("state_dir", "must be an absolute path")
    asus = _parse_asus(top.table("asus", required=True), files)
    snmp = _parse_snmp(top.table("snmp", required=True), files)
    cfg = Config(
        source=source,
        state_dir=state_dir,
        asus=asus,
        snmp=snmp,
        nodes=_parse_nodes(top.table("nodes")),
        overrides=_parse_overrides(
            top.get("override", None),
            snmp.port_base,
            _ipv4_or_none(asus.host),
            files,
        ),
        collector=_parse_collector(top.table("collector")),
        logging=_parse_logging(top.table("logging")),
        onboard=_parse_onboard(top.table("onboard"), files),
    )
    top.done()
    return cfg


# --- secret and certificate files ----------------------------------------------

_ACL_XATTR = "system.posix_acl_access"
_ACL_USER, _ACL_GROUP_OBJ, _ACL_GROUP, _ACL_MASK, _ACL_OTHER = 2, 4, 8, 16, 32
_PEM_CERT = re.compile(
    r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.DOTALL
)
# The example config's file name per secret key, for the hint in file errors.
SECRET_FILE_EXAMPLES = {
    "asus.password_file": "asus_password",
    "snmp.community_file": "snmp_community",
    "snmp.v3.auth_key_file": "snmp_auth_key",
    "snmp.v3.priv_key_file": "snmp_priv_key",
    "onboard.token_file": "librenms_token",
}


@dataclass(frozen=True)
class Secrets:
    """Secret values read from files; ``repr`` shows only ``***``."""

    asus_password: SecretStr
    snmp_auth_key: SecretStr | None = None
    snmp_priv_key: SecretStr | None = None
    snmp_community: SecretStr | None = None


@dataclass(frozen=True)
class RouterPin:
    """A pinned certificate set: the only certificates a session trusts.

    The router's own exported certificate skips the hostname check; a node CA
    pin (``check_hostname``) also requires the node certificate to name its IP.
    An ``exact`` pin (a node's own leaf) accepts only those very certificates.
    """

    pem: str
    fingerprints: tuple[str, ...]
    check_hostname: bool = False
    exact: bool = False

    def ssl_context(self) -> ssl.SSLContext:
        """A TLS client context that verifies the peer against the pin only.

        Without ``check_hostname`` the router cert need not name its LAN
        address: trust comes from the pin. Callers must never fall back to HTTP.
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = self.check_hostname
        ctx.verify_mode = ssl.CERT_REQUIRED
        if not self.check_hostname:  # the exported leaf itself is the anchor
            ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
        ctx.load_verify_locations(cadata=self.pem)
        if self.exact:
            ctx.sslobject_class, ctx.sslsocket_class = _exact_leaf(self.fingerprints)
        return ctx


def _exact_leaf(
    fingerprints: tuple[str, ...],
) -> tuple[type[ssl.SSLObject], type[ssl.SSLSocket]]:
    """TLS classes that accept a verified peer only if its leaf is pinned.

    A pinned CA:TRUE cert would also anchor any cert it signed; this stops that.
    """
    pinned = frozenset(fingerprints)

    def check(der: bytes | None) -> None:
        presented = fingerprint(der) if der else "none"
        if presented not in pinned:  # raised before any request byte is sent
            exc = ssl.SSLCertVerificationError(
                ssl.SSL_ERROR_SSL, f"certificate {presented} is not the pinned leaf"
            )
            exc.verify_message = "certificate is not the pinned leaf"
            raise exc

    class ExactObject(ssl.SSLObject):  # asyncio and aiohttp
        def do_handshake(self) -> None:
            super().do_handshake()
            check(self.getpeercert(binary_form=True))

    class ExactSocket(ssl.SSLSocket):  # blocking sockets
        def do_handshake(self, block: bool = False) -> None:
            super().do_handshake(block)
            check(self.getpeercert(binary_form=True))

    return ExactObject, ExactSocket


def _posix_acl(fd: int) -> bytes | None:
    """The file's POSIX access ACL (Linux only), or None when it has none."""
    getxattr = getattr(os, "getxattr", None)
    if getxattr is None:
        return None
    try:
        return getxattr(fd, _ACL_XATTR)
    except OSError:
        return None


def _acl_foreign_bits(raw: bytes, euid: int) -> int:
    """The rwx bits an ACL grants to anyone but the owner and ``euid``.

    systemd ``LoadCredential=`` files are root-owned 0400 plus a read entry for
    the service user, so their mode shows the ACL mask in the group bits.
    """
    if len(raw) < 4 or (len(raw) - 4) % 8 or raw[:4] != b"\x02\x00\x00\x00":
        return 0o7
    mask, granted, other = 0o7, 0, 0
    for tag, perm, qualifier in struct.iter_unpack("<HHI", raw[4:]):
        if tag == _ACL_MASK:
            mask = perm
        elif tag == _ACL_OTHER:
            other = perm
        elif tag in (_ACL_GROUP_OBJ, _ACL_GROUP) or (
            tag == _ACL_USER and qualifier != euid
        ):
            granted |= perm
    return ((granted & mask) | other) & 0o7


def _foreign_bits(fd: int, mode: int, euid: int) -> int:
    acl = _posix_acl(fd)
    if acl is None:
        return ((mode >> 3) | mode) & 0o7
    return _acl_foreign_bits(acl, euid)


def _secret_dir(path: Path) -> str:
    """The deepest existing directory above a secret file, so an error names no
    part of its configured value that does not exist (a secret typed in by mistake).
    """
    for parent in Path(os.path.normpath(path)).parents:
        if os.path.isdir(parent):
            return str(parent)
    return path.anchor or "."


def _misnamed_hint(label: str) -> str:
    example = SECRET_FILE_EXAMPLES.get(label)
    such_as = f" such as {example}" if example else ""
    return f"; the value must name a file{such_as}, not the secret itself"


def _read_protected(path: Path, label: str, *, secret: bool, limit: int) -> bytes:
    """Read a small regular file after checking who else may read or write it.

    Non-blocking open plus fstat checks the opened file itself, so a FIFO
    cannot hang startup and a swapped path cannot dodge the checks.
    """
    if secret:  # the file name may be the secret itself: show only its directory
        folder = _secret_dir(path)
        shown, at, hint = (
            f"the file in {folder}",
            f" in {folder}",
            _misnamed_hint(label),
        )
    else:
        shown, at, hint = str(path), f": {path}", ""
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        raise ConfigError(f"{label}: file not found{at}{hint}") from None
    except OSError as exc:
        raise ConfigError(
            f"{label}: cannot open {shown}: {exc.strerror}{hint}"
        ) from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ConfigError(f"{label}: not a regular file{at}{hint}")
        euid = os.geteuid()
        if st.st_uid not in (euid, 0):
            raise ConfigError(
                f"{label}: {shown} is owned by uid {st.st_uid}; "
                f"it must belong to the service user or root{hint}"
            )
        mode = f"{stat.S_IMODE(st.st_mode):04o}"
        foreign = _foreign_bits(fd, st.st_mode, euid)
        if secret and foreign:
            raise ConfigError(
                f"{label}: {shown} is accessible to group or others "
                f"(mode {mode}); run chmod 600{hint}"
            )
        if foreign & 0o2:
            raise ConfigError(
                f"{label}: {shown} is writable by group or others "
                f"(mode {mode}); run chmod 644"
            )
        data = b""
        while len(data) <= limit:
            chunk = os.read(fd, limit + 1 - len(data))
            if not chunk:
                break
            data += chunk
    finally:
        os.close(fd)
    if len(data) > limit:
        raise ConfigError(f"{label}: {shown} is larger than {limit} bytes")
    return data


def read_secret(path: Path, label: str) -> SecretStr:
    """Read one owner-only, one-line secret file; never echo its value or name."""
    data = _read_protected(path, label, secret=True, limit=MAX_SECRET_BYTES)
    shown = f"the file in {_secret_dir(path)}"
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ConfigError(f"{label}: {shown} is not UTF-8 text") from None
    text = text.rstrip("\r\n")
    if not text:
        raise ConfigError(f"{label}: {shown} is empty")
    if any(ch in text for ch in "\r\n\0"):
        raise ConfigError(f"{label}: {shown} must hold one line")
    return SecretStr(text)


def _usm_key(path: Path, label: str) -> SecretStr:
    key = read_secret(path, label)
    if len(key.get_secret_value()) < MIN_USM_KEY_CHARS:
        raise ConfigError(
            f"{label}: the file in {_secret_dir(path)} must hold at least "
            f"{MIN_USM_KEY_CHARS} characters"
        )
    return key


def load_secrets(cfg: Config) -> Secrets:
    """Read the daemon's secret files and register each value for redaction.

    The onboard token is not among them: only :func:`load_onboard_token` reads it.
    """
    password = read_secret(cfg.asus.password_file, "asus.password_file")
    login = f"{cfg.asus.username}:{password.get_secret_value()}"
    register_secret(base64.b64encode(login.encode()).decode())  # login_authorization
    auth = priv = community = None
    if cfg.snmp.v3 is not None:
        auth = _usm_key(cfg.snmp.v3.auth_key_file, "snmp.v3.auth_key_file")
        priv = _usm_key(cfg.snmp.v3.priv_key_file, "snmp.v3.priv_key_file")
    if cfg.snmp.community_file is not None:
        community = read_secret(cfg.snmp.community_file, "snmp.community_file")
    return Secrets(password, auth, priv, community)


def load_onboard_token(cfg: Config) -> SecretStr:
    """Read the LibreNMS API token; only the ``onboard`` command needs it."""
    if cfg.onboard is None:
        raise ConfigError("onboard: add an [onboard] section with token_file")
    if cfg.onboard.token_file is None:
        raise ConfigError("onboard.token_file: required")
    return read_secret(cfg.onboard.token_file, "onboard.token_file")


def fingerprint(der: bytes) -> str:
    """``SHA256:AA:BB:...`` of a DER certificate, the format errors and logs show."""
    return "SHA256:" + ":".join(f"{b:02X}" for b in hashlib.sha256(der).digest())


def load_router_pin(path: Path, label: str = "asus.ca_file") -> RouterPin:
    """Load the pinned router certificate; refuse keys and group-writable files."""
    data = _read_protected(path, label, secret=False, limit=MAX_CERT_BYTES)
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise ConfigError(f"{label}: {path} is not a PEM certificate") from None
    if "PRIVATE KEY" in text:
        raise ConfigError(
            f"{label}: {path} contains a private key; export the certificate only"
        )
    blocks = _PEM_CERT.findall(text)
    if not blocks:
        raise ConfigError(f"{label}: {path} holds no PEM certificate")
    try:
        fingerprints = tuple(fingerprint(ssl.PEM_cert_to_DER_cert(b)) for b in blocks)
        pin = RouterPin("\n".join(blocks) + "\n", fingerprints)
        pin.ssl_context()
    except (ValueError, ssl.SSLError):
        raise ConfigError(f"{label}: {path} is not a valid certificate") from None
    return pin


def load_node_ca(path: Path, label: str = "asus.node_ca_file") -> RouterPin:
    """Load the CA that issued the AiMesh node certificates, as a hostname pin."""
    pin = load_router_pin(path, label)
    for block in _PEM_CERT.findall(pin.pem):
        cert = x509.load_pem_x509_certificate(block.encode())
        try:
            is_ca = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        except x509.ExtensionNotFound:
            is_ca = None
        if is_ca is None or not is_ca.value.ca:
            raise ConfigError(
                f"{label}: {path} is not a CA certificate; pin the CA that issued "
                "the node certificates (discover --pin-node-ca)"
            )
    return replace(pin, check_hostname=True)


def load_node_pin(path: Path, label: str = "override.ca_file") -> RouterPin:
    """Load a node's own exported leaf: an exact match, by any name, like ca_file."""
    return replace(load_router_pin(path, label), exact=True)


# --- service account -----------------------------------------------------------


def assert_unprivileged_user(forbidden_names: Iterable[str] = ("librenms",)) -> None:
    """Refuse UID 0 and named accounts such as ``librenms`` (security H2).

    Root, or the account LibreNMS runs as, would expose the router login to
    far more code; the systemd unit runs the daemon under DynamicUser= instead.
    """
    if os.getuid() == 0 or os.geteuid() == 0:
        raise ConfigError(
            "refusing to run as root (uid 0); use the service's DynamicUser"
        )
    try:
        name = pwd.getpwuid(os.geteuid()).pw_name
    except KeyError:  # an anonymous UID is not a named account
        return
    if name in set(forbidden_names):
        raise ConfigError(
            f"refusing to run as user {name!r}: "
            "a compromise of that account would expose the router login"
        )
