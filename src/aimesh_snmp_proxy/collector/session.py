"""One pinned, fail-closed HTTPS session and AsusRouter per ASUS target (H1, H3).

The aiohttp session trusts only the pinned router certificate. A client
middleware refuses, before any connection opens, every request that is not
verified HTTPS to the target host and port, that hits an endpoint outside the
read allowlist, or that is a login the guard does not allow. The library is
configured so a session it creates on its own fails TLS instead of falling
back to HTTP, and so it never logs below INFO or calls back with replies.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import re
import ssl
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote, urlencode

import aiohttp
import yarl
from aiohttp.client_middlewares import ClientHandlerType, ClientMiddlewareType
from asusrouter import AsusRouter
from asusrouter.config import ARConfigKey
from asusrouter.config.connection import ARConnectionConfigKey as ARCCKey
from asusrouter.modules.endpoint import AREndpoint
from asusrouter.tools.security import ARSecurityLevel
from cryptography import x509
from cryptography.exceptions import InvalidSignature

from aimesh_snmp_proxy.collector.backoff import TargetGuard
from aimesh_snmp_proxy.config import RouterPin
from aimesh_snmp_proxy.logsafe import SecretStr

_LOG = logging.getLogger(__name__)

MAX_CONCURRENT_REQUESTS = 2
MAX_CA_FILE_BYTES = 16 * 1024  # the live root serves 1614 bytes
LIBRARY_LOGGER = "asusrouter"
LIBRARY_CONNECTION_CONFIG: dict[ARCCKey, Any] = {
    ARCCKey.VERIFY_SSL: True,
    ARCCKey.STRICT_SSL: True,
    ARCCKey.ALLOW_FALLBACK: False,
    ARCCKey.ALLOW_MULTIPLE_FALLBACKS: False,
    ARCCKey.ALLOW_UPGRADE_HTTP_TO_HTTPS: False,
    ARCCKey.MAX_CONCURRENT_REQUESTS: MAX_CONCURRENT_REQUESTS,
}
LIBRARY_CONFIG: dict[ARConfigKey, Any] = {
    ARConfigKey.SECURITY_LEVEL_LOG: ARSecurityLevel.STRICT,
}
# Read-only pages the collector's data sources use, plus login and logout
READ_ENDPOINTS = frozenset(
    e.value
    for e in (
        AREndpoint.LOGIN,
        AREndpoint.LOGOUT,
        AREndpoint.FETCH_DATA,
        AREndpoint.FETCH_ONBOARDING,
        AREndpoint.FETCH_DIAGNOSTICS_DATA,
        AREndpoint.FETCH_TRAFFIC_WIFI,
        AREndpoint.FETCH_TRAFFIC_BACKHAUL,
        AREndpoint.FETCH_TRAFFIC_ETHERNET,
        AREndpoint.FETCH_TEMPERATURE,
        AREndpoint.FETCH_PORT_STATUS,  # GET ?node_mac=all: every node's ports
        AREndpoint.FETCH_UPDATE,  # only in its _EXACT_FORMS form
        AREndpoint.FETCH_PORTS_ETHERNET,  # likewise
    )
)
# Endpoints that pass in one form only: (method, query), with an empty body.
# update.cgi runs whichever page handler `output` names (nvram_get among them);
# the ports page is the library's fallback without get_port_status.cgi.
_EXACT_FORMS: dict[str, tuple[str, tuple[tuple[str, str], ...]]] = {
    AREndpoint.FETCH_UPDATE.value: ("GET", (("output", "netdev"),)),
    AREndpoint.FETCH_PORTS_ETHERNET.value: ("POST", ()),
}
_PEM_BLOCK = re.compile(
    r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.DOTALL
)
FORBIDDEN_HOOKS = ("nvram_dump",)  # dumps every nvram value, passwords included


class RequestBlockedError(RuntimeError):
    """The guard middleware refused a request; no connection was opened."""


class SessionClosedError(RuntimeError):
    """The pinned session is closed; the library must not replace it."""


@dataclass(frozen=True)
class Target:
    """One ASUS web UI: the root router, or a node in per_node mode."""

    name: str
    host: str
    port: int
    username: str
    password: SecretStr = field(repr=False)
    pin: RouterPin = field(repr=False)


class _WithholdContent(logging.Filter):
    """The library logs an unparsable reply verbatim at ERROR; keep the event only."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = "router reply is not valid JSON (content withheld)"
        record.args = ()
        return True


_CONTENT_ECHO_LOGGERS = ("asusrouter.tools.readers.raw",)


def quiet_library_logging() -> None:
    """Keep asusrouter at INFO or above (DEBUG carries reply payloads), and
    strip the reply its JSON reader logs on a parse error (security logging).
    """
    root = logging.getLogger().getEffectiveLevel()
    library = logging.getLogger(LIBRARY_LOGGER)
    library.setLevel(max(logging.INFO, root, library.level))
    for name in _CONTENT_ECHO_LOGGERS:
        logger = logging.getLogger(name)
        if not any(isinstance(f, _WithholdContent) for f in logger.filters):
            logger.addFilter(_WithholdContent())


def _body_text(req: Any) -> str:
    body = getattr(req, "body", b"")
    if isinstance(body, aiohttp.payload.Payload):
        return unquote(body.decode(errors="replace"))
    if isinstance(body, bytes | bytearray):
        return unquote(bytes(body).decode(errors="replace"))
    return ""


def guard_middleware(target: Target, guard: TargetGuard) -> ClientMiddlewareType:
    """The client middleware every request of ``target`` passes first."""
    host = target.host.lower()

    async def middleware(req: Any, handler: ClientHandlerType) -> Any:
        url = req.url
        if (
            url.scheme != "https"
            or (url.host or "").lower() != host
            or url.port != (target.port)
        ):
            raise RequestBlockedError(f"{target.name}: not HTTPS to the pinned router")
        if req.ssl is not True:  # True means: verify with the session's pin context
            raise RequestBlockedError(f"{target.name}: unverified TLS refused")
        endpoint = url.path.lstrip("/")
        if endpoint not in READ_ENDPOINTS:
            raise RequestBlockedError(
                f"{target.name}: endpoint {endpoint!r} is not allowlisted"
            )
        exact = _EXACT_FORMS.get(endpoint)
        if exact is not None and (
            (req.method, tuple(url.query.items())) != exact or _body_text(req)
        ):
            method, query = exact
            form = f"{method} ?{urlencode(query)}" if query else f"an empty {method}"
            raise RequestBlockedError(
                f"{target.name}: {endpoint} passes only as {form}"
            )
        body = _body_text(req) + unquote(url.query_string)
        for hook in FORBIDDEN_HOOKS:
            if hook in body:
                raise RequestBlockedError(f"{target.name}: hook {hook} refused")
        if endpoint == AREndpoint.LOGIN.value:
            guard.before_login()
        return await handler(req)

    return middleware


def build_http_session(
    pin: RouterPin,
    *,
    timeout_s: float,
    middlewares: Sequence[ClientMiddlewareType] = (),
) -> aiohttp.ClientSession:
    """An aiohttp session that verifies the router against the pin only."""
    connector = aiohttp.TCPConnector(
        ssl=pin.ssl_context(),
        limit=MAX_CONCURRENT_REQUESTS,
        limit_per_host=MAX_CONCURRENT_REQUESTS,
    )
    return aiohttp.ClientSession(
        connector=connector,
        timeout=aiohttp.ClientTimeout(total=timeout_s),
        cookie_jar=aiohttp.DummyCookieJar(),  # the library sends its token itself
        middlewares=tuple(middlewares),
        trust_env=False,  # never route the login through an env-configured proxy
    )


class RouterSession:
    """The pinned session and AsusRouter for one target, reused across polls.

    Extra ``middlewares`` run after the guard, so they only see allowed requests.
    """

    def __init__(
        self,
        target: Target,
        guard: TargetGuard,
        *,
        timeout_s: float = 10.0,
        middlewares: Sequence[ClientMiddlewareType] = (),
    ) -> None:
        self.target = target
        self.guard = guard
        self._timeout_s = timeout_s
        self._middlewares = (guard_middleware(target, guard), *middlewares)
        self._http: aiohttp.ClientSession | None = None
        self._router: AsusRouter | None = None
        self._closed = False
        self._users = 0
        self._idle = asyncio.Event()
        self._idle.set()
        quiet_library_logging()

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def http(self) -> aiohttp.ClientSession | None:
        return self._http

    @property
    def router(self) -> AsusRouter:
        """The library client; created on first use, after the pinned session."""
        if self._closed:
            raise SessionClosedError(f"{self.target.name}: session closed")
        if self._http is None:
            self._http = build_http_session(
                self.target.pin,
                timeout_s=self._timeout_s,
                middlewares=self._middlewares,
            )
        elif self._http.closed:
            raise SessionClosedError(
                f"{self.target.name}: pinned session closed unexpectedly; "
                "refusing to let the library open an unpinned one"
            )
        if self._router is None:
            self._router = AsusRouter(
                hostname=self.target.host,
                username=self.target.username,
                password=self.target.password.get_secret_value(),
                port=self.target.port,
                use_ssl=True,
                session=self._http,
                config=dict(LIBRARY_CONFIG),
                connection_config=dict(LIBRARY_CONNECTION_CONFIG),
            )
        return self._router

    async def fetch(self, request: Any) -> dict[Any, Any]:
        """Fresh data for the request's sources; logs in when needed."""
        result = await self.router.async_fetch_data(request, force=True)
        return result if isinstance(result, dict) else {}

    async def read(self, endpoint: AREndpoint, request: str | None = None) -> Any:
        """One parsed reply, for data the library pipeline does not expose."""
        return await self.router.async_read(endpoint, request)

    @contextlib.asynccontextmanager
    async def use(self) -> AsyncIterator[RouterSession]:
        """Hold the session for one job; :meth:`retire` waits until none hold it."""
        self._users += 1
        self._idle.clear()
        try:
            yield self
        finally:
            self._users -= 1
            if not self._users:
                self._idle.set()

    async def retire(self, timeout_s: float) -> None:
        """Let running jobs finish (bounded wait), then log out and close.

        Closing under a running job would orphan its login or make the library
        open a session of its own; waiting first avoids both.
        """
        with contextlib.suppress(TimeoutError):
            async with asyncio.timeout(timeout_s):
                await self._idle.wait()
        await self.close()

    def drop_auth(self) -> None:
        """Forget a token the router rejected; no I/O, the same library client.

        The next request logs in once, and concurrent jobs share that login:
        the library dedupes it. A new client per loss would orphan logins.
        """
        if self._router is not None:
            self._router._async_drop_connection()  # the library's own auth reset

    async def close(self) -> None:
        """Log out if logged in, then close the pinned session (SIGTERM path)."""
        self._closed = True
        router, self._router = self._router, None
        http = self._http
        if http is None or http.closed:
            return
        if router is not None and router.connected:
            try:
                async with asyncio.timeout(self._timeout_s):
                    await router.async_disconnect()
            except Exception as exc:  # shutdown goes on regardless
                _LOG.warning(
                    "%s: logout failed: %s", self.target.name, type(exc).__name__
                )
        await http.close()


# --- certificates ---------------------------------------------------------------


def fingerprint_der(der: bytes) -> str:
    """``SHA256:AA:BB:...``, the format ``check-config`` prints for the pin."""
    return "SHA256:" + ":".join(f"{b:02X}" for b in hashlib.sha256(der).digest())


class CertFileError(ValueError):
    """The router's /cert.crt answer is not a usable download."""


async def fetch_router_ca_file(
    host: str, port: int, pin: RouterPin, *, timeout_s: float
) -> bytes:
    """GET /cert.crt, the CA an ASUS router publishes, over the pinned link.

    No login and no redirect; the caller must still verify what comes back.
    """
    connector = aiohttp.TCPConnector(ssl=pin.ssl_context())
    async with aiohttp.ClientSession(
        connector=connector,
        timeout=aiohttp.ClientTimeout(total=timeout_s),
        cookie_jar=aiohttp.DummyCookieJar(),
        trust_env=False,
    ) as http:
        url = yarl.URL.build(scheme="https", host=host, port=port, path="/cert.crt")
        async with http.get(url, allow_redirects=False) as resp:
            if resp.status != 200:
                raise CertFileError(f"HTTP {resp.status}")
            body = await resp.content.read(MAX_CA_FILE_BYTES + 1)
    if len(body) > MAX_CA_FILE_BYTES:
        raise CertFileError(f"larger than {MAX_CA_FILE_BYTES} bytes")
    return body


async def fetch_certificate(host: str, port: int, *, timeout_s: float) -> bytes:
    """The DER certificate a server presents. TLS handshake only: no HTTP, no login.

    Verification is off on purpose: the result is only shown to an operator,
    who compares its fingerprint out of band before trusting it.
    """
    chain = await fetch_chain(host, port, timeout_s=timeout_s, leaf_only=True)
    return chain[0]


async def fetch_chain(
    host: str, port: int, *, timeout_s: float, leaf_only: bool = False
) -> list[bytes]:
    """The DER chain a server presents, leaf first; a handshake only, unverified."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2  # explicit on every platform
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    async with asyncio.timeout(timeout_s):
        _, writer = await asyncio.open_connection(host, port, ssl=ctx)
    try:
        tls = writer.get_extra_info("ssl_object")
        chain = [] if leaf_only else _unverified_chain(tls)
        if not chain:
            leaf = tls.getpeercert(binary_form=True)
            chain = [leaf] if leaf else []
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    if not chain:
        raise ssl.SSLError("server presented no certificate")
    return chain


def _unverified_chain(tls: Any) -> list[bytes]:
    getter = getattr(tls, "get_unverified_chain", None)  # Python 3.13 and later
    if getter is not None:
        return [bytes(der) for der in getter() or ()]
    # 3.11 and 3.12 have only the private form, which yields Certificate objects.
    inner = getattr(getattr(tls, "_sslobj", None), "get_unverified_chain", None)
    if inner is None:
        return []
    return [cert.public_bytes(ssl._ssl.ENCODING_DER) for cert in inner() or ()]


def pin_verdict(pin: RouterPin, der: bytes) -> str:
    """How a presented certificate relates to ``pin``, for operator logs.

    A router pin compares fingerprints; a node CA pin checks the issuer only,
    since the node IP is checked by the TLS handshake itself.
    """
    if not pin.check_hostname:
        return "matches" if fingerprint_der(der) in pin.fingerprints else "MISMATCH"
    try:
        leaf = x509.load_der_x509_certificate(der)
    except ValueError:
        return "not a certificate"
    for block in _PEM_BLOCK.findall(pin.pem):
        try:
            leaf.verify_directly_issued_by(
                x509.load_pem_x509_certificate(block.encode())
            )
        except (ValueError, TypeError, InvalidSignature):
            continue
        return "issued by the node CA"
    return "not issued by the node CA"


async def log_pin_mismatch(target: Target, *, timeout_s: float) -> None:
    """Log both fingerprints after a TLS verification failure (security logging)."""
    pinned = ", ".join(target.pin.fingerprints)
    try:
        der = await fetch_certificate(target.host, target.port, timeout_s=timeout_s)
    except (OSError, TimeoutError, ssl.SSLError) as exc:
        _LOG.error(
            "%s: TLS verification failed; pinned %s, presented certificate "
            "unavailable (%s)",
            target.name,
            pinned,
            type(exc).__name__,
        )
        return
    presented = fingerprint_der(der)
    if target.pin.check_hostname:
        _LOG.error(
            "%s: TLS verification failed: node CA %s, presented %s (%s); a node "
            "certificate must come from that CA and must name %s",
            target.name,
            pinned,
            presented,
            pin_verdict(target.pin, der),
            target.host,
        )
        return
    _LOG.error(
        "%s: TLS pin mismatch: pinned %s, presented %s; re-pin only after "
        "checking the router out of band",
        target.name,
        pinned,
        presented,
    )
