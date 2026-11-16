"""JSON log output behind a redaction filter that keeps secrets out of every record.

The filter masks registered secret values (every :class:`SecretStr`), asusrouter
``ARSensitive`` objects (their ``str()`` may be raw), sensitive ``key=value``
pairs (passwords, tokens, Wi-Fi PSKs, VPN accounts), auth headers, URL
passwords, and the device half of MAC addresses.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, TextIO

MASK = "***"
LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")

# Router nvram adds wl<u>_wpa_psk, wgs_psk, ap<n>_security, wl<u>_key1-4,
# vpn_serverx_clientlist (user>password rows), and WireGuard private keys.
_KEY_WORDS = (
    r"passw(?:or)?d|passphrase|pwd|secret|token|cookie|authorization"
    r"|auth_?key|priv_?key|private_?key|community|api_?key|session_?id"
    r"|psk|security|clientlist|_key[1-4]"
)
# Keys ending in _file, _path, or _dir name a location, not a secret.
_KEY = r"[\w.-]*?(?:" + _KEY_WORDS + r")[\w.-]*(?<!_file)(?<!_path)(?<!_dir)"
_KEY_RE = re.compile(_KEY, re.IGNORECASE)
_KEY_PREFIX = r"(?<![\w.-])(?P<q>[\"']?)" + _KEY + r"(?P=q)\s*[:=]\s*"

_SCHEME = re.compile(
    r"\b(?P<s>basic|bearer)\s+(?=[\w.~+/=-]*[0-9+/=.~-])[\w.~+/=-]+", re.IGNORECASE
)
_HEADER = re.compile(
    r"^(?P<h>[ \t]*(?:proxy-authorization|authorization|set-cookie|cookie"
    r"|x-auth-token))[ \t]*:.*$",
    re.IGNORECASE | re.MULTILINE,
)
_USERINFO = re.compile(r"\b(?P<u>[a-z][a-z0-9+.-]*://[^\s/:@]+:)[^\s/@]+@", re.I)
_QUOTED = re.compile(
    r"(?P<k>" + _KEY_PREFIX + r"b?)(?P<v>\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*')",
    re.IGNORECASE,
)
_UNQUOTED = re.compile(
    r"(?P<k>" + _KEY_PREFIX + r")(?!\*\*\*)[^\s\"',;&)}\]]+", re.IGNORECASE
)
_MAC = re.compile(
    r"(?<![0-9A-Fa-f])(?<![0-9A-Fa-f][:-])"
    r"(?P<oui>[0-9A-Fa-f]{2}(?P<sep>[:-])[0-9A-Fa-f]{2}(?P=sep)[0-9A-Fa-f]{2})"
    r"(?:(?P=sep)[0-9A-Fa-f]{2}){3}(?![:-]?[0-9A-Fa-f])"
)

_STANDARD_ATTRS = frozenset(vars(logging.LogRecord("", 0, "", 0, "", (), None))) | {
    "message",
    "asctime",
    "taskName",
}
_REDACTED_FLAG = "_logsafe_redacted"
_HANDLER_FLAG = "_logsafe_handler"
_MAX_DEPTH = 8
_CONTAINERS = (Mapping, list, tuple, set, frozenset)


class _Literals:
    """Registered secret values plus one compiled pattern, swapped as a unit."""

    __slots__ = ("pattern", "values")

    def __init__(self, values: frozenset[str] = frozenset()) -> None:
        self.values = values
        ordered = sorted(values, key=len, reverse=True)
        self.pattern = re.compile("|".join(map(re.escape, ordered))) if values else None


_literals = _Literals()


def register_secret(value: str) -> None:
    """Mask every later occurrence of ``value`` in log output.

    Meant for long-lived secrets; rotating session tokens rely on key patterns.
    """
    global _literals  # one atomic reference swap; readers never lock
    current = _literals
    if value and value not in current.values:
        _literals = _Literals(current.values | {value})


class SecretStr:
    """A secret string whose ``repr`` and ``str`` never show the value."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value
        register_secret(value)

    def get_secret_value(self) -> str:
        """Return the raw secret; pass it straight to the consumer, never log it."""
        return self._value

    def __repr__(self) -> str:
        return f"SecretStr('{MASK}')"

    def __str__(self) -> str:
        return MASK


def _mask_mac(match: re.Match[str]) -> str:
    sep = match["sep"]
    return match["oui"] + f"{sep}**" * 3


def redact(text: str) -> str:
    """Return ``text`` with secrets and the device half of MAC addresses masked."""
    pattern = _literals.pattern
    if pattern is not None:
        text = pattern.sub(MASK, text)
    text = _SCHEME.sub(lambda m: f"{m['s']} {MASK}", text)
    text = _HEADER.sub(lambda m: f"{m['h']}: {MASK}", text)
    text = _USERINFO.sub(lambda m: f"{m['u']}{MASK}@", text)
    text = _QUOTED.sub(lambda m: f"{m['k']}{m['v'][0]}{MASK}{m['v'][0]}", text)
    text = _UNQUOTED.sub(lambda m: f"{m['k']}{MASK}", text)
    return _MAC.sub(_mask_mac, text)


def _is_sensitive_key(key: str) -> bool:
    return _KEY_RE.fullmatch(key) is not None


def _is_router_sensitive(value: object) -> bool:
    """True for asusrouter ``ARSensitive`` objects, without importing asusrouter."""
    return any(
        cls.__name__ == "ARSensitive" and cls.__module__.startswith("asusrouter.")
        for cls in type(value).__mro__
    )


def _unwrap(value: Any, depth: int = 0) -> Any:
    """Replace asusrouter sensitive objects with MASK; rebuild only what changed."""
    if _is_router_sensitive(value):
        return MASK
    if depth >= _MAX_DEPTH:  # too deep to inspect: fail closed
        return MASK if isinstance(value, _CONTAINERS) else value
    if isinstance(value, Mapping):
        items = {k: _unwrap(v, depth + 1) for k, v in value.items()}
        changed = any(items[k] is not v for k, v in value.items())
        return items if changed else value
    if isinstance(value, list | tuple | set | frozenset):
        items = [_unwrap(v, depth + 1) for v in value]
        if all(new is old for new, old in zip(items, value, strict=True)):
            return value
        return tuple(items) if isinstance(value, tuple) else items
    return value


def _scrub(value: Any, depth: int = 0) -> Any:
    """Copy ``value`` as JSON-ready data with secrets masked."""
    if _is_router_sensitive(value):
        return MASK
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        return redact(value)
    if depth >= _MAX_DEPTH and isinstance(value, _CONTAINERS):
        return MASK
    if isinstance(value, Mapping):
        return {
            str(k): MASK if _is_sensitive_key(str(k)) else _scrub(v, depth + 1)
            for k, v in value.items()
        }
    if isinstance(value, list | tuple | set | frozenset):
        return [_scrub(v, depth + 1) for v in value]
    return redact(str(value))


_EXC_FORMATTER = logging.Formatter()


def _redact_record(record: logging.LogRecord) -> None:
    if getattr(record, _REDACTED_FLAG, False):
        return
    record.msg = _unwrap(record.msg)
    record.args = _unwrap(record.args)
    try:
        message = record.getMessage()
    except Exception:  # a bad format string must not crash the logging caller
        message = f"{record.msg} {record.args!r}"
    record.msg = redact(message)
    record.args = ()
    for key, value in list(vars(record).items()):
        if key in _STANDARD_ATTRS or key.startswith("_"):
            continue
        setattr(record, key, MASK if _is_sensitive_key(key) else _scrub(value))
    if record.exc_info:
        record.exc_text = _EXC_FORMATTER.formatException(record.exc_info)
        record.exc_info = None
    if record.exc_text:
        record.exc_text = redact(record.exc_text)
    if record.stack_info:
        record.stack_info = redact(record.stack_info)
    setattr(record, _REDACTED_FLAG, True)


class RedactionFilter(logging.Filter):
    """Mask secrets in the message, arguments, extras, and traceback of a record."""

    def filter(self, record: logging.LogRecord) -> bool:
        _redact_record(record)
        return True


class JsonFormatter(logging.Formatter):
    """One JSON object per line; redacts again so it is safe without the filter."""

    def format(self, record: logging.LogRecord) -> str:
        _redact_record(record)
        ts = datetime.fromtimestamp(record.created, tz=UTC)
        payload: dict[str, Any] = {
            "ts": ts.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, value in vars(record).items():
            if key not in _STANDARD_ATTRS and not key.startswith("_"):
                payload.setdefault(key, value)
        if record.exc_text:
            payload["exc"] = record.exc_text
        if record.stack_info:
            payload["stack"] = record.stack_info
        return json.dumps(payload, ensure_ascii=False, default=str)


def setup_logging(level: str = "INFO", stream: TextIO | None = None) -> logging.Handler:
    """Send all root-logger output as redacted JSON lines to ``stream`` (stderr).

    Existing root handlers also get the redaction filter. pysnmp debug output,
    which hexdumps decrypted PDUs, stays off at every level.
    """
    name = str(level).upper()
    if name not in LEVELS:
        raise ValueError(f"log level must be one of {', '.join(LEVELS)}")
    root = logging.getLogger()
    for handler in list(root.handlers):
        if getattr(handler, _HANDLER_FLAG, False):
            root.removeHandler(handler)
        elif not any(isinstance(f, RedactionFilter) for f in handler.filters):
            handler.addFilter(RedactionFilter())
    handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
    handler.addFilter(RedactionFilter())
    handler.setFormatter(JsonFormatter())
    setattr(handler, _HANDLER_FLAG, True)
    root.addHandler(handler)
    root.setLevel(name)
    logging.getLogger("pysnmp").setLevel(max(logging.INFO, root.level))
    logging.captureWarnings(True)
    return handler
