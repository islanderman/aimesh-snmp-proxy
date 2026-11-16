"""One pysnmp SnmpEngine per AiMesh node on 127.0.0.1, behind a SILENT gate.

All engines share one AsyncioDispatcher. Its routing callback runs before any
parsing: a packet for a node without a servable snapshot goes to a no-op
receiver, so a SILENT node never answers, not even with a v3 Report.
Only GET, GETNEXT, and GETBULK responders exist; there is no SET.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import socket
import tempfile
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from pysnmp import debug
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.carrier.asyncio.dispatch import AsyncioDispatcher
from pysnmp.entity import config, engine
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.proto import rfc1902

from aimesh_snmp_proxy.logsafe import SecretStr
from aimesh_snmp_proxy.model import NodeSnapshot, normalize_mac
from aimesh_snmp_proxy.profiles import DEFAULT_PROFILE, Profile, get_profile
from aimesh_snmp_proxy.profiles.base import LLDP_MIB
from aimesh_snmp_proxy.snmp.instrum import TableController
from aimesh_snmp_proxy.snmp.oidtable import MAX_BULK_VARBINDS, OidTable

log = logging.getLogger(__name__)

BIND_ADDRESS = "127.0.0.1"
BLACKHOLE = "blackhole"
ENGINE_ID_PREFIX = bytes.fromhex("80001f8803")  # net-snmp enterprise 8072, MAC format
MIN_PORT = 1024
MAX_PORT = 65535
MIN_USM_KEY_CHARS = 8  # RFC 3414 passphrase minimum
AUTH_PROTOCOLS = {
    "SHA-1": config.USM_AUTH_HMAC96_SHA,
    "SHA-224": config.USM_AUTH_HMAC128_SHA224,
    "SHA-256": config.USM_AUTH_HMAC192_SHA256,
    "SHA-384": config.USM_AUTH_HMAC256_SHA384,
    "SHA-512": config.USM_AUTH_HMAC384_SHA512,
}
PRIV_PROTOCOLS = {"AES-128": config.USM_PRIV_CFB128_AES}

_READ_VIEWS = ((1, 3, 6), LLDP_MIB)  # every subtree a profile renders
_V2C_SECURITY_NAME = "v2c-reader"
_USM_USER = re.compile(r"[A-Za-z0-9._-]{1,32}")
_EMPTY = OidTable()


class SnapshotSource(Protocol):
    """Where nodes' snapshots come from: the collector's store, or a fake."""

    def current(self, node_id: str) -> NodeSnapshot | None:
        """The servable snapshot, or None while the node must stay SILENT."""


@dataclass(frozen=True, slots=True)
class V3User:
    """An SNMPv3 authPriv user; the keys are RFC 3414 passphrases."""

    user: str
    auth_key: SecretStr
    priv_key: SecretStr
    auth: str = "SHA-256"
    priv: str = "AES-128"

    def __post_init__(self) -> None:
        if not _USM_USER.fullmatch(self.user):
            raise ValueError("v3 user: expected 1-32 letters, digits, '.', '_' or '-'")
        if self.auth not in AUTH_PROTOCOLS:
            raise ValueError(f"v3 auth must be one of {', '.join(AUTH_PROTOCOLS)}")
        if self.priv not in PRIV_PROTOCOLS:
            raise ValueError(f"v3 priv must be one of {', '.join(PRIV_PROTOCOLS)}")
        for label, key in (("auth_key", self.auth_key), ("priv_key", self.priv_key)):
            if not isinstance(key, SecretStr):
                raise TypeError(f"v3 {label} must be a SecretStr")
            if len(key.get_secret_value()) < MIN_USM_KEY_CHARS:
                raise ValueError(f"v3 {label}: at least {MIN_USM_KEY_CHARS} characters")


@dataclass(frozen=True, slots=True)
class EngineSpec:
    """Everything needed to serve one node; built by the daemon from config."""

    node_id: str
    sys_name: str
    mac: str
    port: int
    community: SecretStr | None = None
    v3: V3User | None = None
    profile: str = DEFAULT_PROFILE

    def __post_init__(self) -> None:
        if not self.node_id:
            raise ValueError("node_id must not be empty")
        label = f"node {self.node_id!r}"
        if not (0 < len(self.sys_name) <= 255 and self.sys_name.isprintable()):
            raise ValueError(f"{label}: sys_name must be 1-255 printable characters")
        mac = normalize_mac(self.mac)
        if mac is None:
            raise ValueError(f"{label}: mac must look like aa:bb:cc:dd:ee:ff")
        object.__setattr__(self, "mac", mac)
        if type(self.port) is not int or not MIN_PORT <= self.port <= MAX_PORT:
            raise ValueError(f"{label}: port must be {MIN_PORT}-{MAX_PORT}")
        if self.community is None and self.v3 is None:
            raise ValueError(f"{label}: needs a v2c community or a v3 user")
        if self.community is not None and not isinstance(self.community, SecretStr):
            raise TypeError(f"{label}: community must be a SecretStr")

    @property
    def engine_id(self) -> bytes:
        """snmpEngineID: the net-snmp enterprise prefix plus the node MAC."""
        return ENGINE_ID_PREFIX + bytes.fromhex(self.mac.replace(":", ""))


def cap_pysnmp_logging() -> None:
    """Keep pysnmp debug off (H3): it dumps decrypted PDUs and community strings."""
    debug.set_logger(0)
    logger = logging.getLogger("pysnmp")
    if logger.getEffectiveLevel() < logging.INFO:
        logger.setLevel(logging.INFO)
    if _info_or_above not in logger.filters:
        logger.addFilter(_info_or_above)  # survives a later setLevel(DEBUG)


def _info_or_above(record: logging.LogRecord) -> bool:
    return record.levelno >= logging.INFO


def _drop(*_args: Any) -> None:
    """The blackhole receiver: SILENT packets end here, unparsed."""


class _BulkResponder(cmdrsp.BulkCommandResponder):
    max_varbinds = MAX_BULK_VARBINDS


class _Node:
    """One node's spec, controller, and the table rendered from its snapshot.

    ``peers`` returns every served node's sysName by MAC, for LLDP remotes.
    """

    def __init__(
        self,
        spec: EngineSpec,
        profile: Profile,
        controller: TableController,
        peers: Callable[[], dict[str, str]] = dict,
    ):
        self.spec = spec
        self.profile = profile
        self.controller = controller
        self._peers = peers
        self._snapshot: NodeSnapshot | None = None
        self._serving_since: float | None = None
        self._ok = False
        self._answering = False

    def serve(self, snapshot: NodeSnapshot | None, now: float) -> bool:
        """Adopt ``snapshot`` (None means SILENT); True when the node answers."""
        if snapshot is None:
            self._snapshot = self._serving_since = None
            self._ok = False
        elif snapshot is not self._snapshot:
            if self._serving_since is None:
                self._serving_since = now
            self._snapshot = snapshot
            self._ok = self._render(snapshot, now)
        if not self._ok:
            # A silent node keeps no rows it could later serve by mistake.
            self.controller.table = _EMPTY
        if self._ok != self._answering:
            self._answering = self._ok
            state = "answering" if self._ok else "silent"
            log.info("node %s: SNMP %s", self.spec.node_id, state)
        return self._ok

    def _render(self, snapshot: NodeSnapshot, now: float) -> bool:
        try:
            rows = self.profile.render(
                snapshot,
                now=now,
                serving_since=self._serving_since,
                sys_name=self.spec.sys_name,
                peer_names=self._peers(),
            )
            self.controller.table = OidTable(rows)
        except Exception:
            log.exception("node %s: cannot render the snapshot", self.spec.node_id)
            return False
        return True


@contextlib.contextmanager
def _boots_under(state_dir: Path | None) -> Iterator[None]:
    """pysnmp keeps snmpEngineBoots under tempfile.gettempdir()."""
    saved = tempfile.tempdir
    if state_dir is not None:
        tempfile.tempdir = str(state_dir)
    try:
        yield
    finally:
        tempfile.tempdir = saved


class SnmpServer:
    """Answers SNMP for each added node on ``127.0.0.1:<port>``.

    ``source.current(node_id)`` decides SERVING or SILENT for every packet.
    With ``stale_after_s`` set, an old snapshot is SILENT too; ``clock`` must
    be the clock the snapshots' ``collected_at`` uses.
    """

    def __init__(
        self,
        source: SnapshotSource,
        *,
        bind: str = BIND_ADDRESS,
        state_dir: Path | None = None,
        stale_after_s: float | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if bind != BIND_ADDRESS:
            raise ValueError(f"SNMP must bind {BIND_ADDRESS} only, not {bind!r}")
        cap_pysnmp_logging()
        self._source = source
        self._state_dir = state_dir
        self._stale_after_s = stale_after_s
        self._clock = clock
        self._dispatcher: AsyncioDispatcher | None = None
        self._nodes: dict[str, _Node] = {}
        self._by_domain: dict[tuple[int, ...], _Node] = {}

    async def __aenter__(self) -> SnmpServer:
        return self

    async def __aexit__(self, *exc: object) -> None:
        self.close()

    async def add(self, spec: EngineSpec) -> None:
        """Bind ``spec.port`` and serve the node; OSError when the port is taken."""
        for node in self._nodes.values():
            if spec.node_id == node.spec.node_id:
                raise ValueError(f"node {spec.node_id!r} is already served")
            if spec.port == node.spec.port:
                raise ValueError(
                    f"port {spec.port} already serves {node.spec.node_id!r}"
                )
            if spec.mac == node.spec.mac:
                raise ValueError(
                    f"mac of {spec.node_id!r} already serves {node.spec.node_id!r}"
                )
        profile = get_profile(spec.profile)
        loop = asyncio.get_running_loop()
        snmp_engine, controller = self._engine(spec)
        sock = _bind(spec)
        domain = (*udp.DOMAIN_NAME, spec.port)
        transport = udp.UdpAsyncioTransport(loop=loop)
        dispatcher = self._dispatcher_for(loop)
        # Register before the endpoint exists, so no datagram finds it half wired.
        snmp_engine.register_transport_dispatcher(dispatcher, domain)
        config.add_transport(snmp_engine, domain, transport)
        try:
            await loop.create_datagram_endpoint(lambda: transport, sock=sock)
        except BaseException:
            sock.close()
            dispatcher.unregister_transport(domain)
            dispatcher.unregister_recv_callback(domain)
            raise
        node = _Node(spec, profile, controller, self._peer_names)
        self._nodes[spec.node_id] = node
        self._by_domain[domain] = node

    def _peer_names(self) -> dict[str, str]:
        """The sysName each served node answers with, by MAC."""
        return {node.spec.mac: node.spec.sys_name for node in self._nodes.values()}

    def close(self) -> None:
        """Close every socket and stop the dispatcher; ``add`` may start over."""
        if self._dispatcher is not None:
            self._dispatcher.close_dispatcher()
            self._dispatcher = None
        self._nodes.clear()
        self._by_domain.clear()

    def _engine(self, spec: EngineSpec) -> tuple[engine.SnmpEngine, TableController]:
        """A configured engine whose only MIB view is a fresh table controller."""
        with _boots_under(self._state_dir):
            snmp_engine = engine.SnmpEngine(rfc1902.OctetString(spec.engine_id))
        if spec.community is not None:
            config.add_v1_system(
                snmp_engine,
                "community",
                spec.community.get_secret_value(),
                securityName=_V2C_SECURITY_NAME,
            )
            for subtree in _READ_VIEWS:  # each call adds one subtree to one view
                config.add_vacm_user(
                    snmp_engine, 2, _V2C_SECURITY_NAME, "noAuthNoPriv", subtree
                )
        if spec.v3 is not None:
            user = spec.v3
            config.add_v3_user(
                snmp_engine,
                user.user,
                AUTH_PROTOCOLS[user.auth],
                user.auth_key.get_secret_value(),
                PRIV_PROTOCOLS[user.priv],
                user.priv_key.get_secret_value(),
            )
            for subtree in _READ_VIEWS:
                config.add_vacm_user(snmp_engine, 3, user.user, "authPriv", subtree)
        controller = TableController()
        snmp_context = context.SnmpContext(snmp_engine)
        # Replacing the default context leaves pysnmp's own tables unreachable.
        snmp_context.unregister_context_name(b"")
        snmp_context.register_context_name(b"", controller)
        cmdrsp.GetCommandResponder(snmp_engine, snmp_context)
        cmdrsp.NextCommandResponder(snmp_engine, snmp_context)
        _BulkResponder(snmp_engine, snmp_context)
        return snmp_engine, controller

    def _dispatcher_for(self, loop: asyncio.AbstractEventLoop) -> AsyncioDispatcher:
        if self._dispatcher is None:
            dispatcher = AsyncioDispatcher(loop=loop)
            dispatcher.register_routing_callback(self._route)
            dispatcher.register_recv_callback(_drop, BLACKHOLE)
            self._dispatcher = dispatcher
        return self._dispatcher

    def _route(
        self, domain: tuple[int, ...], _address: Any, _message: Any
    ) -> tuple[int, ...] | str:
        """The SERVING gate: runs for every datagram before pysnmp parses it."""
        node = self._by_domain.get(domain)
        if node is None:
            return BLACKHOLE
        now = self._clock()
        try:
            snapshot = self._source.current(node.spec.node_id)
        except Exception:
            log.exception("node %s: snapshot source failed", node.spec.node_id)
            snapshot = None
        stale = self._stale_after_s
        if (
            snapshot is not None
            and stale is not None
            and not snapshot.is_fresh(now, stale)
        ):
            snapshot = None
        return domain if node.serve(snapshot, now) else BLACKHOLE


def _bind(spec: EngineSpec) -> socket.socket:
    """Bind synchronously, so a taken port fails before anything registers."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((BIND_ADDRESS, spec.port))
    except OSError as exc:
        sock.close()
        where = f"{BIND_ADDRESS}:{spec.port}"
        message = f"node {spec.node_id!r}: cannot bind {where}: {exc.strerror}"
        raise OSError(exc.errno, message) from exc
    sock.setblocking(False)
    return sock
