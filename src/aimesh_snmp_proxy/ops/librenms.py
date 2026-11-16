"""Small LibreNMS API v0 client for ``onboard``: list, get, add, and delete devices.

The token travels only in ``X-Auth-Token`` and only to the configured origin:
TLS is verified (system trust plus the hostname, or, with ``ca_file``, that pin
alone: its certificates are the only anchors and the peer's leaf must match one
by SHA-256), ``http://`` needs an explicit opt-in, proxy variables are ignored,
redirects are followed only for GET within the same origin, and nothing is
retried. Raw answers never reach a message: only a scrubbed, truncated server
``message``.
"""

from __future__ import annotations

import http.client
import json
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aimesh_snmp_proxy import __version__
from aimesh_snmp_proxy.config import (
    ConfigError,
    RouterPin,
    fingerprint,
    load_router_pin,
)
from aimesh_snmp_proxy.logsafe import MASK, SecretStr, redact

TIMEOUT_S = 10.0
MAX_BODY_BYTES = 1 << 20
MAX_LIST_BYTES = 8 << 20  # a device row is about 2 KB, and the list holds them all
MAX_ERROR_BYTES = 64 * 1024
MAX_REDIRECTS = 3
MAX_MESSAGE_CHARS = 200
API_ROOT = "/api/v0"
_DEFAULT_PORTS = {"http": 80, "https": 443}
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


class ApiError(RuntimeError):
    """A request failed. The message never holds the token or a known secret."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class AuthError(ApiError):
    """HTTP 401 or 403: the token is wrong or lacks a permission; stop at once."""


class TransportError(ApiError):
    """No usable LibreNMS answer: network, TLS, timeout, redirect, or not JSON."""


class _RedirectRefusedError(Exception):
    pass


class PinMismatchError(ssl.SSLError):
    """The peer's leaf certificate is not a pinned one; no request was sent."""

    def __init__(self, presented: str) -> None:
        super().__init__(f"leaf certificate {presented} is not pinned")
        self.presented = presented


@dataclass(frozen=True)
class Device:
    """The fields onboard keeps from a device answer; the rest is dropped.

    ``overwrite_ip`` and ``port`` are the SNMP endpoint, None when LibreNMS says none.
    """

    device_id: int
    hostname: str
    overwrite_ip: str | None = None
    port: int | None = None


def parse_base_url(url: str, *, allow_http: bool) -> tuple[str, str]:
    """Return the base URL without a trailing slash and its ``scheme://host:port``."""
    try:
        parts = urllib.parse.urlsplit(url.strip())
        port = parts.port
    except ValueError:
        raise ConfigError("[onboard] url is not a valid URL") from None
    if parts.scheme not in _DEFAULT_PORTS or not parts.hostname:
        raise ConfigError("[onboard] url must look like https://host[:port]")
    if parts.username is not None or parts.query or parts.fragment:
        raise ConfigError(
            "[onboard] url must not hold credentials, a query, or a fragment"
        )
    if parts.scheme == "http" and not allow_http:
        raise ConfigError(
            "[onboard] url uses http://, so the token would travel in cleartext; "
            "use https or pass --allow-http"
        )
    base = f"{parts.scheme}://{parts.netloc}{parts.path.rstrip('/')}"
    port = port or _DEFAULT_PORTS[parts.scheme]
    origin = f"{parts.scheme}://{parts.hostname.lower()}:{port}"
    return base, origin


def _origin_of(url: str) -> str | None:
    try:
        return parse_base_url(url, allow_http=True)[1]
    except ConfigError:
        return None


class _SameOriginRedirects(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only for GET and only within the configured origin.

    urllib copies every header to the redirect target, ``X-Auth-Token`` too,
    and turns a redirected POST into a GET that could look like success.
    """

    max_redirections = MAX_REDIRECTS

    def __init__(self, origin: str) -> None:
        self._origin = origin

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if req.get_method() != "GET" or _origin_of(newurl) != self._origin:
            raise _RedirectRefusedError(
                f"refused a {code} redirect of {req.get_method()}"
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _leaf_pinned_socket(fingerprints: tuple[str, ...]) -> type[ssl.SSLSocket]:
    """An SSLSocket class that accepts a verified peer only if its leaf is pinned."""
    pinned = frozenset(fingerprints)

    class LeafPinnedSocket(ssl.SSLSocket):
        def do_handshake(self, block: bool = False) -> None:
            super().do_handshake(block)
            der = self.getpeercert(binary_form=True)
            presented = fingerprint(der) if der else "none"
            if presented not in pinned:  # raised before any request byte is sent
                raise PinMismatchError(presented)

    return LeafPinnedSocket


def tls_context(pin: RouterPin | None) -> ssl.SSLContext:
    """System trust and a hostname match; with ``pin``, that pin alone decides.

    The pin may name an IP only in its CN (no SAN), which a hostname match
    refuses; an exact leaf match is stricter than the name.
    """
    if pin is None:
        return ssl.create_default_context()
    ctx = pin.ssl_context()  # the pin's certificates only, CERT_REQUIRED, no name
    ctx.sslsocket_class = _leaf_pinned_socket(pin.fingerprints)
    return ctx


def presented_fingerprint(host: str, port: int, timeout: float) -> str | None:
    """The leaf a server presents, from a bare handshake: no HTTP, no token.

    Verification is off on purpose: the result is only shown to an operator,
    who compares it with the pin out of band; it is never trusted.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with (
            socket.create_connection((host, port), timeout=timeout) as raw,
            ctx.wrap_socket(raw, server_hostname=host) as tls,
        ):
            der = tls.getpeercert(binary_form=True)
    except OSError:
        return None
    return fingerprint(der) if der else None


class LibreNMSClient:
    """List, GET, POST, and DELETE on ``/api/v0/devices``; one attempt per call."""

    def __init__(
        self,
        url: str,
        token: SecretStr,
        *,
        allow_http: bool = False,
        ca_file: Path | None = None,
        timeout: float = TIMEOUT_S,
        secrets: Iterable[SecretStr] = (),
    ) -> None:
        self.base_url, self.origin = parse_base_url(url, allow_http=allow_http)
        self._token = token
        self._secrets = (token, *secrets)
        self._timeout = timeout
        self._pin: RouterPin | None = None
        handlers: list[urllib.request.BaseHandler] = [
            urllib.request.ProxyHandler({}),  # the token never goes to a proxy
            _SameOriginRedirects(self.origin),
        ]
        if self.origin.startswith("https:"):
            if ca_file is not None:
                self._pin = load_router_pin(ca_file, "onboard.ca_file")
            handlers.append(urllib.request.HTTPSHandler(context=tls_context(self._pin)))
        self._opener = urllib.request.build_opener(*handlers)

    def __repr__(self) -> str:
        return f"LibreNMSClient({self.base_url!r})"

    # --- device calls ----------------------------------------------------------

    def list_devices(self) -> list[Device]:
        """Every device the token may see, in one request."""
        status, data = self._request("GET", "/devices", limit=MAX_LIST_BYTES)
        if status != 200:
            raise self._error(status, data)
        rows = data.get("devices") if isinstance(data, dict) else None
        if not isinstance(rows, list):
            raise ApiError("unexpected answer: no list of devices")
        return [self._device_row(row) for row in rows]

    def get_device(self, hostname: str) -> Device | None:
        """The device named ``hostname``, or None when LibreNMS has none."""
        status, data = self._request("GET", self._device_path(hostname))
        if status == 404:
            return None
        if status != 200:
            raise self._error(status, data)
        return self._device(data)

    def get_device_by_id(self, device_id: int) -> Device | None:
        """The device with this id (an all-digit path segment), or None."""
        return self.get_device(str(device_id))

    def add_device(self, body: dict[str, Any]) -> Device:
        """POST one device; the answer must name the device that was created."""
        status, data = self._request("POST", "/devices", body)
        if status not in (200, 201):
            raise self._error(status, data)
        return self._device(data)

    def delete_device(self, hostname: str) -> bool:
        """DELETE one device: True when removed, False when it was already gone."""
        status, data = self._request("DELETE", self._device_path(hostname))
        if status == 404:
            return False
        if status != 200:
            raise self._error(status, data)
        return True

    def delete_device_by_id(self, device_id: int) -> bool:
        """DELETE the device with this id; False when it was already gone."""
        return self.delete_device(str(device_id))

    # --- internals ---------------------------------------------------------------

    @staticmethod
    def _device_path(hostname: str) -> str:
        return "/devices/" + urllib.parse.quote(hostname, safe="")

    def scrub(self, text: str) -> str:
        """Mask the token and every known secret; drop control characters."""
        for secret in self._secrets:
            value = secret.get_secret_value()
            if value:
                text = text.replace(value, MASK)
        return _CONTROL.sub("", redact(text))[:MAX_MESSAGE_CHARS]

    def _request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        limit: int | None = None,
    ) -> tuple[int, Any]:
        limit = MAX_BODY_BYTES if limit is None else limit
        headers = {
            "Accept": "application/json",
            "User-Agent": f"aimesh-snmp-proxy/{__version__}",
            "X-Auth-Token": self._token.get_secret_value(),
        }
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        call = f"{method} {API_ROOT}{path}"
        # S310: parse_base_url admits only http and https base URLs.
        req = urllib.request.Request(  # noqa: S310
            self.base_url + API_ROOT + path, data=data, method=method, headers=headers
        )
        try:
            with self._opener.open(req, timeout=self._timeout) as resp:
                status, raw = resp.status, resp.read(limit + 1)
        except urllib.error.HTTPError as exc:
            status = exc.code
            try:
                raw = exc.read(MAX_ERROR_BYTES)
            except OSError:
                raw = b""
            finally:
                exc.close()
        except _RedirectRefusedError as exc:
            raise TransportError(
                f"{call}: {exc}; only same-origin GET redirects are followed"
            ) from None
        except (OSError, http.client.HTTPException, ValueError) as exc:
            raise TransportError(f"{call}: {self._reason(exc)}") from None
        if 300 <= status < 400:
            raise TransportError(f"{call}: too many redirects (HTTP {status})", status)
        if len(raw) > limit:
            raise TransportError(f"{call}: answer is larger than {limit} bytes")
        try:
            parsed = json.loads(raw) if raw else None
        except (ValueError, RecursionError):  # deep nesting overflows the parser
            parsed = None
        if status in (401, 403):
            raise AuthError(self._message(f"{call}: HTTP {status}", parsed), status)
        if parsed is None or (status == 404 and not isinstance(parsed, dict)):
            what = "not JSON" if status < 400 else "not a LibreNMS API answer"
            raise TransportError(
                f"{call}: HTTP {status}, {what}; is [onboard] url the LibreNMS root?",
                status,
            )
        return status, parsed

    def _reason(self, exc: BaseException) -> str:
        reason = getattr(exc, "reason", None) or exc
        pin_failure = ssl.SSLCertVerificationError | PinMismatchError
        if self._pin is not None and isinstance(reason, pin_failure):
            return self._pin_failure(self._pin, reason)
        if isinstance(reason, ssl.SSLCertVerificationError):
            return self.scrub(
                f"TLS verification failed ({reason.verify_message}); "
                "set [onboard] ca_file to pin the LibreNMS certificate"
            )
        if isinstance(reason, ssl.SSLError):
            return self.scrub(f"TLS error: {reason.reason or reason}")
        if isinstance(reason, TimeoutError):
            return f"timed out after {self._timeout:g} s (no retry)"
        return self.scrub(f"{type(reason).__name__}: {reason}")

    def _pin_failure(self, pin: RouterPin, reason: OSError) -> str:
        """Both fingerprints, unscrubbed and whole: neither is a secret."""
        if isinstance(reason, PinMismatchError):
            why, presented = "not the pinned certificate", reason.presented
        else:  # the chain failed, so the handshake never showed the leaf
            why = self.scrub(str(getattr(reason, "verify_message", reason)))
            parts = urllib.parse.urlsplit(self.base_url)
            port = parts.port or _DEFAULT_PORTS["https"]
            presented = presented_fingerprint(parts.hostname, port, self._timeout)
        return (
            f"TLS pin check failed ({why}): pinned {', '.join(pin.fingerprints)}, "
            f"presented {presented or 'certificate unavailable'}; the server must "
            "present the [onboard] ca_file certificate (compare fingerprints out "
            "of band before re-pinning)"
        )

    def _message(self, prefix: str, data: Any) -> str:
        message = data.get("message") if isinstance(data, dict) else None
        if isinstance(message, dict | list):
            message = json.dumps(message, ensure_ascii=False)
        if not isinstance(message, str) or not message.strip():
            return prefix
        return f"{prefix}: {self.scrub(message.strip())}"

    def _error(self, status: int, data: Any) -> ApiError:
        return ApiError(self._message(f"HTTP {status}", data), status)

    def _device(self, data: Any) -> Device:
        rows = data.get("devices") if isinstance(data, dict) else None
        return self._device_row(rows[0] if isinstance(rows, list) and rows else None)

    @staticmethod
    def _device_row(row: Any) -> Device:
        if isinstance(row, dict):
            device_id, hostname = _int(row.get("device_id")), row.get("hostname")
            if device_id is not None and device_id > 0 and isinstance(hostname, str):
                overwrite_ip = row.get("overwrite_ip")
                return Device(
                    device_id,
                    hostname,
                    overwrite_ip if isinstance(overwrite_ip, str) else None,
                    _int(row.get("port")),
                )
        raise ApiError("unexpected answer: no device_id and hostname")


def _int(value: Any) -> int | None:
    """An integer, or the digits of a string (older LibreNMS); None otherwise."""
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return value if isinstance(value, int) and not isinstance(value, bool) else None
