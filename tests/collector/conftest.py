"""Fixtures for the collector tests: a fake clock and a fixed random source."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import logging
import random
import socket
import ssl
from collections.abc import AsyncIterator, Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import pytest
from aiohttp import web

from aimesh_snmp_proxy.config import RouterPin

CANARIES = {"asus_password": "canary-router-Pa55-1"}

WALL_START = 1_800_000_000.0  # an arbitrary epoch second, far from 0


class FakeClock:
    """Monotonic and wall time that move only when told to.

    ``sleep`` advances both clocks at once and yields to the event loop, so
    a scheduler loop runs at full speed while still letting tasks interleave.
    """

    def __init__(self, monotonic: float = 1000.0, wall: float = WALL_START) -> None:
        self._mono = monotonic
        self._wall = wall
        self.slept: list[float] = []

    def monotonic(self) -> float:
        return self._mono

    def time(self) -> float:
        return self._wall

    def advance(self, seconds: float) -> None:
        self._mono += seconds
        self._wall += seconds

    def set_wall(self, wall: float) -> None:
        """Step the wall clock only, as NTP or an operator would."""
        self._wall = wall

    async def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.advance(max(0.0, seconds))
        await asyncio.sleep(0)


class EdgeRandom(random.Random):
    """``uniform`` returns its upper (``high=True``) or lower bound."""

    def __init__(self, high: bool = True) -> None:
        super().__init__(0)
        self.high = high

    def uniform(self, a: float, b: float) -> float:
        return b if self.high else a


_CLAMPED_LOGGERS = ("asusrouter", "asusrouter.tools.readers.raw", "pysnmp")


@pytest.fixture(autouse=True)
def _restore_logging() -> Iterator[None]:
    """The collector clamps library loggers on purpose; undo it after each test.

    ``main()`` also installs the logsafe handler; drop it so later test files
    see the logging state they expect.
    """
    root = logging.getLogger()
    saved = {
        name: (logging.getLogger(name).level, list(logging.getLogger(name).filters))
        for name in _CLAMPED_LOGGERS
    }
    level, handlers = root.level, list(root.handlers)
    yield
    for name, (old_level, filters) in saved.items():
        logger = logging.getLogger(name)
        logger.setLevel(old_level)
        logger.filters[:] = filters
    root.setLevel(level)
    for handler in list(root.handlers):
        if handler not in handlers and getattr(handler, "_logsafe_handler", False):
            root.removeHandler(handler)


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def rng_high() -> EdgeRandom:
    return EdgeRandom(high=True)


@pytest.fixture
def rng_low() -> EdgeRandom:
    return EdgeRandom(high=False)


# --- mock ASUS router ------------------------------------------------------------

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def load_fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / f"{name}.json").read_text())


@dataclass
class Seen:
    method: str
    path: str
    query: dict[str, str]
    body: str
    cookie: str | None


def render_js(variables: dict[str, Any]) -> str:
    """ASUS ``.asp`` pages are ``name = value;`` lines."""
    return "\n".join(
        f"{name} = {json.dumps(value)};" for name, value in variables.items()
    )


class MockRouter:
    """An HTTPS ASUS web UI stand-in that serves one fixture and records requests."""

    def __init__(
        self, fixture: dict[str, Any], *, username: str, password: str
    ) -> None:
        self.fixture = fixture
        self.username = username
        self.password = password
        self.seen: list[Seen] = []
        self.login_error: int | None = None
        self.data_error: int | None = None
        self.tokens: set[str] = set()
        self.raw_replies: dict[str, str] = {}
        self.public: dict[str, str | None] = {}  # no login needed; None is a 404
        self.delays: dict[str, float] = {}
        self.host = "127.0.0.1"
        self.port = 0

    def paths(self) -> list[str]:
        return [s.path for s in self.seen]

    def logins(self) -> list[Seen]:
        return [s for s in self.seen if s.path == "/login.cgi"]

    def expire_tokens(self) -> None:
        self.tokens.clear()

    async def handle(self, request: web.Request) -> web.Response:
        body = unquote(await request.text())
        cookie = request.headers.get("cookie")
        self.seen.append(
            Seen(request.method, request.path, dict(request.query), body, cookie)
        )
        path = request.path.lstrip("/")
        if path in self.delays:
            await asyncio.sleep(self.delays[path])
        if path in self.public:
            text = self.public[path]
            return web.Response(status=404) if text is None else web.Response(text=text)
        token = (cookie or "").partition("asus_token=")[2].split(";")[0]
        if path == "login.cgi":
            return self._login(body)
        if path == "Logout.asp":
            self.tokens.discard(token)  # what is left at the end was never logged out
            return web.json_response({"error_status": "8"})
        if token not in self.tokens:
            return web.json_response({"error_status": "2"})
        if self.data_error is not None:
            return web.json_response({"error_status": str(self.data_error)})
        if path in self.raw_replies:
            return web.Response(text=self.raw_replies[path])
        if path == "appGet.cgi":
            return web.json_response(self._appget(body))
        pages = self.fixture.get("pages", {})
        if path in pages:
            return web.Response(text=render_js(pages[path]))
        query = {k: v.upper() for k, v in request.query.items()}
        for entry in self.fixture.get("queries", []):
            wanted = {k: str(v).upper() for k, v in entry["query"].items()}
            if entry["endpoint"] == path and wanted.items() <= query.items():
                return web.json_response(entry["reply"])
        return web.Response(status=404)

    def _login(self, body: str) -> web.Response:
        if self.login_error is not None:
            return web.json_response({"error_status": str(self.login_error)})
        _, _, encoded = body.partition("login_authorization=")
        try:
            user, _, password = base64.b64decode(encoded).decode().partition(":")
        except ValueError:
            return web.json_response({"error_status": "3"})
        if (user, password) != (self.username, self.password):
            return web.json_response({"error_status": "3"})
        token = f"tok{len(self.logins())}"
        self.tokens.add(token)
        return web.json_response({"asus_token": token})

    def _appget(self, body: str) -> dict[str, Any]:
        reply = {}
        values = self.fixture.get("appget", {})
        for call in body.removeprefix("hook=").split(";"):
            name, _, args = call.partition("(")
            key = args.rstrip(")") if name == "nvram_get" else name
            if key in values:
                reply[key] = values[key]
        return reply


@pytest.fixture
def mock_router(tmp_path: Path, router_cert: Any) -> Callable[..., Any]:
    """``async with mock_router() as router:`` serves a fixture over TLS."""

    @contextlib.asynccontextmanager
    async def _serve(
        fixture: str | dict[str, Any] = "mesh3", cert: Any = None
    ) -> AsyncIterator[MockRouter]:
        pair = cert or router_cert
        cert_file = tmp_path / f"srv-{id(pair)}.pem"
        key_file = tmp_path / f"srv-{id(pair)}.key"
        cert_file.write_text(pair.cert_pem)
        key_file.write_text(pair.key_pem)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cert_file, key_file)
        data = load_fixture(fixture) if isinstance(fixture, str) else fixture
        router = MockRouter(data, username="admin", password=CANARIES["asus_password"])
        app = web.Application()
        app.router.add_route("*", "/{tail:.*}", router.handle)
        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        site = web.SockSite(runner, sock, ssl_context=ctx)
        await site.start()
        router.port = sock.getsockname()[1]
        try:
            yield router
        finally:
            await runner.cleanup()

    return _serve


@pytest.fixture
def pin(router_cert: Any) -> RouterPin:
    return RouterPin(router_cert.cert_pem, (router_cert.fingerprint,))


@pytest.fixture
def mesh3() -> dict[str, Any]:
    """The three-node fixture: root, a 5G-2 wireless node, a wired node."""
    return load_fixture("mesh3")


@pytest.fixture
def capture() -> Callable[[str], dict[str, Any]]:
    """A synthetic capture in the ``discover --fixtures`` format.

    The scrubber keeps only ``[A-Za-z0-9_]`` support keys, so it dropped the
    ``2.4G`` and ``5G-2`` unit flags; restore those that ``wl<unit>_nband`` proves.
    """

    def _load(name: str) -> dict[str, Any]:
        data = load_fixture(name)
        appget = data["appget"]
        for unit, flag in ((0, "2.4G"), (2, "5G-2")):
            if appget.get(f"wl{unit}_nband"):
                appget["get_ui_support"].setdefault(flag, 1)
        return data

    return _load
