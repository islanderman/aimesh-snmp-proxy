"""The collector service: jobs, guards, overrides, and shutdown (design section 3).

Jobs against the root router: topology (AiMesh list), clients, per-node
metrics (diagnostics and traffic, offset ``i * interval / N``), and the root's
own detail. ``per_node`` mode adds one guarded session per node for that
node's detail. Every job passes its target's guard first; failures are
classified into backoff, a latch, or one re-login.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import random
import ssl
from collections import Counter
from collections.abc import Awaitable, Callable, Iterable, Sequence
from dataclasses import dataclass, replace
from functools import partial
from pathlib import Path
from typing import Any

from asusrouter.const import DEFAULT_PORT_HTTPS
from asusrouter.error import AsusRouterAccessError
from asusrouter.modules.aimesh import ARAiMeshSourceUniversal, ARAiMeshTopology
from asusrouter.modules.clients import ARClientsSourceUniversal
from asusrouter.modules.clients.model import ARClient
from asusrouter.modules.clock import ARClockSourceUniversal
from asusrouter.modules.endpoint import AREndpoint
from asusrouter.modules.endpoint.error import ARAccessError
from asusrouter.modules.ports import ARPortsSourceUniversal
from asusrouter.modules.system_status import ARSystemStatusSource, legacy
from asusrouter.modules.temperature import ARTemperatureSourceUniversal
from asusrouter.modules.traffic.aimesh import ARTrafficAiMeshSource
from asusrouter.modules.traffic.interface import ARTrafficInterfaceSource
from asusrouter.modules.wifi import ARWiFiSourceUniversal

from aimesh_snmp_proxy.collector.backoff import (
    KDF_N,
    Clock,
    Gate,
    Latch,
    LockoutStore,
    Outcome,
    SystemClock,
    TargetGuard,
    classify,
)
from aimesh_snmp_proxy.collector.mapping import (
    ByteDelta,
    CounterBank,
    DeviceDetail,
    InterfaceCounters,
    MeshNode,
    build_snapshot,
    eth_ports,
    mac_text,
    mesh_nodes,
    parse_detail,
    standalone_node,
    unmetered_ports,
    usage_for,
)
from aimesh_snmp_proxy.collector.scheduler import Scheduler
from aimesh_snmp_proxy.collector.session import (
    RequestBlockedError,
    RouterSession,
    Target,
    fetch_certificate,
    log_pin_mismatch,
    pin_verdict,
)
from aimesh_snmp_proxy.collector.statefile import StateFileError
from aimesh_snmp_proxy.collector.store import SnapshotStore
from aimesh_snmp_proxy.config import (
    COUNTERS_FILE,
    LOCKOUT_FILE,
    ROOT_SYS_NAME,
    ConfigError,
    RouterPin,
    default_sys_name,
    load_node_ca,
    load_node_pin,
    read_secret,
)
from aimesh_snmp_proxy.logsafe import SecretStr
from aimesh_snmp_proxy.model import EthPort, NodeSnapshot, normalize_mac

_LOG = logging.getLogger(__name__)

MODES = ("root_only", "per_node")
_TOPOLOGY = "topology"
_METRICS = "metrics:"
_DETAIL = "detail:"
_NETDEV = "netdev:"  # a node's own byte counters, over its per_node session


@dataclass(frozen=True)
class CollectorSettings:
    """Cadence and limits; the defaults are design section 3."""

    mode: str = "root_only"
    stale_after_s: float = 180.0
    metrics_interval_s: float = 60.0
    topology_interval_s: float = 300.0
    request_timeout_s: float = 10.0
    housekeeping_s: float = 60.0

    def __post_init__(self) -> None:
        if self.mode not in MODES:
            raise ValueError(f"collector mode must be one of {', '.join(MODES)}")

    @property
    def per_node(self) -> bool:
        return self.mode == "per_node"


# --- overrides ----------------------------------------------------------------------


@dataclass(frozen=True)
class OverrideRule:
    """``[[override]]``: rename, locate, exclude, skip or pin the per-node login."""

    match: str
    sys_name: str | None = None
    location: str | None = None
    login: bool = True
    exclude: bool = False
    pin: RouterPin | None = None  # ca_file: the node's own leaf, an exact match


def _ipv4(text: Any) -> str | None:
    try:
        return (
            str(ipaddress.IPv4Address(text.strip())) if isinstance(text, str) else None
        )
    except ValueError:
        return None


def _match_key(text: Any) -> str | None:
    if not isinstance(text, str):
        return None
    return normalize_mac(text) or _ipv4(text)


class Overrides:
    """Per-node rules matched by MAC, else by IPv4 address."""

    def __init__(
        self, rules: Iterable[OverrideRule] = (), *, root_ip: str | None = None
    ) -> None:
        self._rules: dict[str, OverrideRule] = {}
        for rule in rules:
            self._rules.setdefault(rule.match, rule)
        self._root_ip = _ipv4(root_ip)

    @classmethod
    def from_config(cls, cfg: Any) -> Overrides:
        """Read the ``[[override]]`` entries of a v0.2 config and their leaf pins."""
        rules = []
        for index, item in enumerate(getattr(cfg, "overrides", None) or ()):
            key = _match_key(getattr(item, "match", None))
            if key is None:
                _LOG.warning("override with an unusable match ignored")
                continue
            ca_file = getattr(item, "ca_file", None)
            rules.append(
                OverrideRule(
                    key,
                    sys_name=getattr(item, "sys_name", None),
                    location=getattr(item, "location", None),
                    login=bool(getattr(item, "login", True)),
                    exclude=bool(getattr(item, "exclude", False)),
                    pin=None
                    if ca_file is None
                    else load_node_pin(ca_file, f"override[{index}].ca_file"),
                )
            )
        return cls(rules, root_ip=getattr(cfg, "root_ip", None))

    def find(self, mac: str, ip: str | None) -> OverrideRule | None:
        address = _ipv4(ip)
        return self._rules.get(mac) or (self._rules.get(address) if address else None)

    def sys_names(
        self, nodes: Iterable[tuple[str, str | None]], *, root_mac: str | None = None
    ) -> dict[str, str]:
        """``Config.sys_names`` without a config; a parity test keeps them equal.

        Override names win. The root (MAC ``root_mac``, or IP ``root_ip``) is
        ``aimesh-root``, others ``aimesh-<6 hex>``; a clash takes the full MAC.
        """
        root_key = normalize_mac(root_mac) if root_mac else None
        names: dict[str, str] = {}
        generated: list[str] = []
        root_default: str | None = None
        for mac, ip in nodes:
            rule = self.find(mac, ip)
            if rule is not None and rule.exclude:
                continue
            if rule is not None and rule.sys_name:
                names[mac] = rule.sys_name
            elif mac == root_key or (self._root_ip and _ipv4(ip) == self._root_ip):
                root_default = mac
            else:
                generated.append(mac)
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


# --- detail -------------------------------------------------------------------------

_EXTRA_SOURCES = (
    ARClockSourceUniversal,
    ARTemperatureSourceUniversal,
    ARWiFiSourceUniversal,
)


async def read_detail(
    session: RouterSession, prev: DeviceDetail | None, now: float
) -> DeviceDetail:
    """Cores, RAM bytes, uptime, temperatures, and channels of the logged-in device."""
    fetched = await session.fetch(list(_EXTRA_SOURCES))
    raw = await session.read(AREndpoint.FETCH_DATA, legacy.LEGACY_REQUEST)
    extras = {
        "clock": fetched.get(ARClockSourceUniversal) or {},
        "temperature": fetched.get(ARTemperatureSourceUniversal) or {},
        "wifi": fetched.get(ARWiFiSourceUniversal) or {},
    }
    units = session.router.description.wifi
    return parse_detail(
        raw if isinstance(raw, dict) else {}, extras, units, prev, now=now
    )


def _stat_signature(path: Path | None) -> tuple[int, int, int] | None:
    if path is None:
        return None
    try:
        st = os.stat(path)
    except OSError:
        return None
    return st.st_ino, st.st_size, st.st_mtime_ns


def _own_units(session: RouterSession) -> dict[str, int]:
    """Band to wl unit as the logged-in device itself numbers its radios."""
    wifi = getattr(session.router.description, "wifi", None) or {}
    return {band.value: unit for band, unit in wifi.items()}


NodeTargetFactory = Callable[[MeshNode], Target | None]
Namer = Callable[..., dict[str, str]]  # (pairs, *, root_mac) -> {mac: sysName}


# --- the service --------------------------------------------------------------------


class Collector:
    """Polls the root router (and, in per_node mode, each node) into a store.

    ``node_pin`` (``asus.node_ca_file``) gives every AiMesh node with an IP a
    session on ``node_port`` that the node CA and the node IP must verify; an
    override's leaf pin (``ca_file``) takes its place for that node.
    """

    def __init__(
        self,
        root: Target,
        state_dir: Path,
        *,
        settings: CollectorSettings | None = None,
        overrides: Overrides | None = None,
        password_file: Path | None = None,
        node_target: NodeTargetFactory | None = None,
        node_pin: RouterPin | None = None,
        node_port: int | None = None,
        namer: Namer | None = None,
        middlewares: Sequence[Any] = (),
        clock: Clock | None = None,
        rng: random.Random | None = None,
        kdf_n: int = KDF_N,
    ) -> None:
        self.settings = settings or CollectorSettings()
        self._clock = clock or SystemClock()
        self._rng = rng
        self._overrides = overrides or Overrides()
        self._password_file = password_file
        self._password_sig = _stat_signature(password_file)
        self._node_pin = node_pin
        self._node_port = node_port
        self._node_target = node_target or self._pinned_node
        self._namer = namer or self._overrides.sys_names
        self._lockouts = LockoutStore(state_dir / LOCKOUT_FILE, kdf_n=kdf_n)
        self._counters = CounterBank(
            state_dir / COUNTERS_FILE, max_gap_s=self.settings.stale_after_s
        )
        self._netdev = InterfaceCounters(max_gap_s=self.settings.stale_after_s)
        self.store = SnapshotStore(
            stale_after_s=self.settings.stale_after_s, clock=self._clock.monotonic
        )
        self.scheduler = Scheduler(clock=self._clock, rng=rng)
        fingerprint = self._lockouts.fingerprint(root.password.get_secret_value())
        guard = TargetGuard(
            root.name,
            self._lockouts,
            clock=self._clock,
            rng=rng,
            password_fp=fingerprint,
        )
        self._root_middlewares = tuple(middlewares)
        self.root = self._session(root, guard, self._root_middlewares)
        self._nodes: dict[str, MeshNode] = {}
        self._names: dict[str, str] = {}
        self._clients: tuple[float, list[ARClient]] | None = None
        self._ports: tuple[float, dict[str, tuple[EthPort, ...]]] | None = None
        self._ports_off = False  # the router lacks get_port_status.cgi
        self._ports_warned = False
        self._unmetered: dict[str, tuple[str, ...]] = {}  # last logged, per node
        self._node_bytes: dict[str, tuple[float, dict[str, ByteDelta]]] = {}
        self._standalone = False  # the nodes are the logged-in device alone
        self._details: dict[str, DeviceDetail] = {}
        self._node_sessions: dict[str, RouterSession] = {}
        self._warned_unpinned: set[str] = set()
        self._renewing = False
        self._retire_timeout_s = 2 * self.settings.request_timeout_s

    @classmethod
    def from_config(
        cls, cfg: Any, secrets: Any, pin: RouterPin, **kwargs: Any
    ) -> Collector:
        """Build from ``load_config``, ``load_secrets``, and ``load_router_pin``."""
        asus, col = cfg.asus, cfg.collector
        if not getattr(asus, "use_ssl", True):
            raise ConfigError(
                "asus.use_ssl: the collector logs in over pinned HTTPS only "
                "(security H1); allow_cleartext is not supported"
            )
        root = Target(
            "root",
            asus.host,
            asus.port or DEFAULT_PORT_HTTPS,
            asus.username,
            secrets.asus_password,
            pin,
        )
        settings = CollectorSettings(
            mode=col.mode,
            stale_after_s=col.stale_after_s,
            metrics_interval_s=col.metrics_interval_s,
            topology_interval_s=col.topology_interval_s,
            request_timeout_s=col.request_timeout_s,
        )
        if "overrides" not in kwargs:  # a caller's own skips reading the leaf pins
            kwargs["overrides"] = Overrides.from_config(cfg)
        kwargs.setdefault("password_file", asus.password_file)
        kwargs.setdefault("namer", getattr(cfg, "sys_names", None))
        node_ca = getattr(asus, "node_ca_file", None)
        if node_ca is not None:
            if "node_pin" not in kwargs:
                kwargs["node_pin"] = load_node_ca(node_ca)
            kwargs.setdefault("node_port", asus.port or DEFAULT_PORT_HTTPS)
            if settings.mode != "per_node":
                _LOG.warning(
                    "asus.node_ca_file is set, but collector.mode is %s: "
                    "no node sessions",
                    settings.mode,
                )
        return cls(root, cfg.state_dir, settings=settings, **kwargs)

    def _session(
        self, target: Target, guard: TargetGuard, middlewares: Sequence[Any] = ()
    ) -> RouterSession:
        return RouterSession(
            target,
            guard,
            timeout_s=self.settings.request_timeout_s,
            middlewares=middlewares,
        )

    @property
    def nodes(self) -> dict[str, MeshNode]:
        """The latest AiMesh list after overrides, keyed by MAC."""
        return dict(self._nodes)

    @property
    def names(self) -> dict[str, str]:
        return dict(self._names)

    def node_guard(self, mac: str) -> TargetGuard | None:
        session = self._node_sessions.get(mac)
        return session.guard if session is not None else None

    # --- lifecycle -------------------------------------------------------------

    async def run(self, stop: asyncio.Event) -> None:
        """Poll until ``stop`` is set (SIGTERM), then log out and persist."""
        s = self.settings
        # One login and one identity fetch first; parallel jobs would each connect
        await self.topology()
        self.scheduler.add(
            _TOPOLOGY,
            s.topology_interval_s,
            self.topology,
            offset_s=s.topology_interval_s,
        )
        self.scheduler.add("clients", s.metrics_interval_s, self.clients)
        self.scheduler.add("ports", s.metrics_interval_s, self.ports)
        self.scheduler.add(f"{_DETAIL}root", s.topology_interval_s, self.detail_root)
        self.scheduler.add("housekeeping", s.housekeeping_s, self.housekeeping)
        try:
            await self.scheduler.run(stop)
        finally:
            await self.shutdown()

    async def poll_once(self) -> dict[str, NodeSnapshot | None]:
        """One full cycle, in dependency order (``discover``, ``selftest``)."""
        await self.topology()
        await self.clients()
        await self.ports()
        await self.detail_root()
        for mac in list(self._nodes):
            await self.detail_node(mac)
            await self.netdev_node(mac)
        for mac in list(self._nodes):
            await self.metrics(mac)
        self.store.refresh_states()
        return {mac: self.store.current(mac) for mac in self._nodes}

    async def shutdown(self, *, persist: bool = True) -> None:
        """Persist counters and log out of every session (the SIGTERM path)."""
        if persist:
            self._save_counters()
        sessions = [self.root, *self._node_sessions.values()]
        await asyncio.gather(*(s.close() for s in sessions), return_exceptions=True)

    async def reload(self, reason: str) -> None:
        """SIGHUP: re-read the password file, renew sessions if needed, clear latches.

        Sessions are renewed only when the password changed or a guard is
        latched (the library keeps a refusal latch of its own); a healthy
        session is kept, so a SIGHUP costs no extra login.
        """
        secret = self._read_password(reason, force=True)
        current = self.root.target.password.get_secret_value()
        changed = secret is not None and secret.get_secret_value() != current
        latched = any(s.guard.latch is not None for s in self._sessions())
        if changed or latched:
            await self._renew_sessions(secret or self.root.target.password)
        for session in self._sessions():
            session.guard.clear_latch(reason)
        if secret is not None:
            self.root.guard.set_password_fp(
                self._lockouts.fingerprint(secret.get_secret_value())
            )

    # --- jobs ------------------------------------------------------------------

    async def topology(self) -> None:
        await self._guarded(self.root, self._topology_work)

    async def clients(self) -> None:
        await self._guarded(self.root, self._clients_work)

    async def ports(self) -> None:
        await self._guarded(self.root, self._ports_work)

    async def metrics(self, mac: str) -> None:
        await self._guarded(self.root, partial(self._metrics_work, mac=mac))

    async def detail_root(self) -> None:
        await self._guarded(self.root, self._detail_work)

    async def detail_node(self, mac: str) -> None:
        session = self._node_session(mac)
        if session is not None:
            await self._guarded(session, partial(self._detail_work, mac=mac))

    async def netdev_node(self, mac: str) -> None:
        session = self._node_session(mac)
        if session is not None:
            await self._guarded(session, partial(self._netdev_work, mac=mac))

    async def housekeeping(self) -> None:
        self._save_counters()
        self.store.refresh_states()
        if self.root.guard.latch is Latch.CREDENTIALS:
            secret = self._read_password("password file changed")
            if secret is not None:
                await self._renew_sessions(secret)
                self.root.guard.set_password_fp(
                    self._lockouts.fingerprint(secret.get_secret_value())
                )

    # --- job bodies --------------------------------------------------------------

    async def _topology_work(self, session: RouterSession) -> None:
        data = await session.fetch(ARAiMeshSourceUniversal)
        topology = data.get(ARAiMeshSourceUniversal)
        nodes = mesh_nodes(topology) if isinstance(topology, ARAiMeshTopology) else {}
        standalone = not nodes
        if standalone:
            if self._nodes and not self._standalone:  # a mesh root's empty reply
                _LOG.warning(
                    "root: the AiMesh list came back empty; keeping the last one"
                )
                return
            nodes = await self._standalone_nodes(session)
            if not nodes:
                _LOG.warning("root: no AiMesh list and no device MAC; nothing to serve")
                return
            if not self._standalone:
                _LOG.info("root: no AiMesh list; serving the logged-in device alone")
        elif self._standalone:
            _LOG.info("root: an AiMesh list arrived; serving its nodes")
        self._standalone = standalone
        root_mac = next((m for m, node in nodes.items() if node.role == "router"), None)
        names = self._namer(
            [(m, node.ip) for m, node in nodes.items()], root_mac=root_mac
        )
        kept = {}
        for mac, node in nodes.items():
            rule = self._overrides.find(mac, node.ip)
            if rule is None or not rule.exclude:
                kept[mac] = node
        self._nodes = kept
        self._names = {mac: names.get(mac) or default_sys_name(mac) for mac in kept}
        self.store.update_topology(kept, self._names)
        self._plan_jobs()

    async def _clients_work(self, session: RouterSession) -> None:
        data = await session.fetch(ARClientsSourceUniversal)
        clients = data.get(ARClientsSourceUniversal)
        values = list(clients.values()) if isinstance(clients, dict) else []
        self._clients = (self._clock.monotonic(), values)

    async def _standalone_nodes(self, session: RouterSession) -> dict[str, MeshNode]:
        """An AP or media bridge lists no AiMesh nodes: serve the device itself.

        Its client list is network-wide; clients without an AiMesh parent count
        on this device only when wireless, which its own radios report.
        """
        data = await session.fetch(ARWiFiSourceUniversal)
        wifi = data.get(ARWiFiSourceUniversal)
        node = standalone_node(
            session.router.description,
            wifi if isinstance(wifi, dict) else {},
            ip=_ipv4(session.target.host),
        )
        return {node.mac: node} if node is not None else {}

    async def _ports_work(self, session: RouterSession) -> None:
        """Every node's Ethernet ports, in one root request (get_port_status.cgi,
        else the library's fallback, ajax_ethernet_ports.asp, for the device).

        Failures that are the endpoint's own omit the rows without a backoff;
        an outage or a login refusal still reaches the guard like any job's.
        """
        if self._ports_off:
            return
        try:
            data = await session.fetch(ARPortsSourceUniversal)
        except RequestBlockedError:
            self._ports_unusable("the guard refused the port status request")
            return
        except AsusRouterAccessError as exc:
            if any(isinstance(arg, ARAccessError) for arg in exc.args):
                raise  # a session or login refusal: the guard's business
            self._ports_failed("get_port_status.cgi answered with an HTTP error")
            return
        except (AttributeError, KeyError, TypeError, ValueError):
            # The library's parser met a page format it does not know.
            self._ports_unusable("the port status page has an unknown format")
            return
        ports = eth_ports(data.get(ARPortsSourceUniversal))
        if not ports:
            self._ports_unusable("the router's port status listed no ports")
            return
        self._ports = (self._clock.monotonic(), ports)

    def _ports_unusable(self, reason: str) -> None:
        """Stop asking and drop the rows now: no stale rows, one warning."""
        self._ports_off = True
        self._ports = None
        self._ports_failed(reason)

    def _ports_failed(self, reason: str) -> None:
        if not self._ports_warned:
            self._ports_warned = True
            _LOG.warning(
                "root: no Ethernet port status (%s); port rows omitted", reason
            )

    def _fresh_ports(self, mac: str, now: float) -> tuple[EthPort, ...]:
        if self._ports and now - self._ports[0] <= self.settings.stale_after_s:
            return self._ports[1].get(mac, ())
        return ()

    async def _metrics_work(self, session: RouterSession, *, mac: str) -> None:
        node = self._nodes.get(mac)
        if node is None:
            return
        status = ARSystemStatusSource(target=mac)
        sources: list[Any] = [status]
        # AiMesh traffic covers only nodes in an AiMesh list. The logged-in
        # device (the root, or a standalone one) also has its own byte counters.
        aimesh = None if self._standalone else ARTrafficAiMeshSource(target=mac)
        own = ARTrafficInterfaceSource() if node.role == "router" else None
        sources += [s for s in (aimesh, own) if s is not None]
        data = await session.fetch(sources)
        now = self._clock.monotonic()
        if own is not None:
            link_bytes: dict[str, ByteDelta] | None = self._netdev.update(
                node, data.get(own) or {}, now, units=_own_units(session)
            )
        else:  # a node: its own counters arrive over its per_node session
            link_bytes = self._take_node_bytes(mac, now)
        clients: list[ARClient] = []
        if self._clients and now - self._clients[0] <= self.settings.stale_after_s:
            clients = self._clients[1]
        rule = self._overrides.find(mac, node.ip)
        snapshot = build_snapshot(
            node,
            sys_name=self._names.get(mac) or default_sys_name(mac),
            collected_at=now,
            usage=usage_for(data.get(status) or {}, mac),
            clients=clients,
            traffic=(data.get(aimesh) or {}) if aimesh is not None else None,
            detail=self._details.get(mac),
            counters=self._counters,
            location=rule.location if rule else None,
            ports=self._fresh_ports(mac, now),
            link_bytes=link_bytes,
        )
        self.store.put(snapshot)
        self._note_unmetered(snapshot)

    def _note_unmetered(self, snapshot: NodeSnapshot) -> None:
        """Log, once per change, the up ports that carry no counter of their own."""
        unmetered = unmetered_ports(snapshot)
        if unmetered == self._unmetered.get(snapshot.mac, ()):
            return
        self._unmetered[snapshot.mac] = unmetered
        if unmetered:
            names = ", ".join(p.name for p in snapshot.ports if p.native in unmetered)
            _LOG.info(
                "%s: no counter of its own for %s (one total covers several ports, "
                "or none measures it)",
                snapshot.sys_name,
                names,
            )

    async def _detail_work(
        self, session: RouterSession, *, mac: str | None = None
    ) -> None:
        if mac is None:  # the root: whatever device this session logged in to
            await session.fetch(ARClockSourceUniversal)
            mac = mac_text(session.router.description.mac)
            if mac is None:
                return
        self._details[mac] = await read_detail(
            session, self._details.get(mac), self._clock.monotonic()
        )

    async def _netdev_work(self, session: RouterSession, *, mac: str) -> None:
        """The node's own byte counters, pending until a snapshot takes them."""
        node = self._nodes.get(mac)
        if node is None:
            return
        source = ARTrafficInterfaceSource()
        data = await session.fetch(source)
        now = self._clock.monotonic()
        deltas = self._netdev.update(
            node, data.get(source) or {}, now, units=_own_units(session)
        )
        pending = self._node_bytes.get(mac, (now, {}))[1]
        self._node_bytes[mac] = (
            now,
            {n: pending[n].plus(d) if n in pending else d for n, d in deltas.items()},
        )

    def _take_node_bytes(self, mac: str, now: float) -> dict[str, ByteDelta] | None:
        """The node's deltas since the last snapshot, each taken once (later ones
        hold); None without a fresh sample, so the root's AiMesh rates fill in.
        """
        entry = self._node_bytes.get(mac)
        if entry is None or not 0 <= now - entry[0] <= self.settings.stale_after_s:
            return None
        sampled_at, pending = entry
        self._node_bytes[mac] = (
            sampled_at,
            {n: ByteDelta(None, None) for n in pending},
        )
        return pending

    # --- guard plumbing ------------------------------------------------------------

    async def _guarded(
        self,
        session: RouterSession,
        work: Callable[[RouterSession], Awaitable[None]],
    ) -> None:
        """Run one job on ``session`` behind its guard; classify any failure."""
        if self._renewing or session.closed:
            return  # sessions are being swapped; this tick is skipped
        guard = session.guard
        gate = guard.gate()
        if gate is Gate.PROBE:
            await self._probe(session)
            return
        if gate is not Gate.OPEN:
            return
        async with session.use():
            try:
                await work(session)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                if session.closed:  # retired under the job: not the router's fault
                    _LOG.debug(
                        "%s: job ended by session retirement", session.target.name
                    )
                    return
                failure = classify(exc)
                guard.on_failure(failure)
                if failure.outcome is Outcome.TOKEN_LOSS:
                    session.drop_auth()
                elif failure.outcome is Outcome.PIN_MISMATCH:
                    await log_pin_mismatch(
                        session.target, timeout_s=self.settings.request_timeout_s
                    )
            else:
                guard.on_success()

    async def _probe(self, session: RouterSession) -> None:
        """Hourly check while latched: a TLS handshake only, never credentials."""
        target, guard = session.target, session.guard
        try:
            der = await fetch_certificate(
                target.host, target.port, timeout_s=self.settings.request_timeout_s
            )
            pin = pin_verdict(target.pin, der)  # a node CA pin checks the issuer
            _LOG.warning(
                "%s: still latched (%s); router reachable, certificate pin %s",
                target.name,
                guard.latch,
                pin,
            )
        except (OSError, TimeoutError, ssl.SSLError) as exc:
            _LOG.warning(
                "%s: still latched (%s); router unreachable (%s)",
                target.name,
                guard.latch,
                type(exc).__name__,
            )
        finally:
            guard.probed()

    def _plan_jobs(self) -> None:
        """Add or drop per-node jobs; new ones start at offset ``i * interval / N``."""
        s = self.settings
        macs = sorted(self._nodes)
        plans = [(_METRICS, macs, s.metrics_interval_s, self.metrics)]
        if s.per_node:
            nodes = [m for m in macs if self._nodes[m].role != "router"]
            plans.append((_DETAIL, nodes, s.topology_interval_s, self.detail_node))
            plans.append((_NETDEV, nodes, s.metrics_interval_s, self.netdev_node))
        for prefix, wanted, interval, job in plans:
            for name in self.scheduler.names():
                gone = name.startswith(prefix) and name[len(prefix) :] not in wanted
                if gone and name != f"{_DETAIL}root":
                    self.scheduler.remove(name)
            offsets = Scheduler.offsets(interval, len(wanted))
            for mac, offset in zip(wanted, offsets, strict=True):
                self.scheduler.add(
                    f"{prefix}{mac}", interval, partial(job, mac), offset_s=offset
                )

    def _node_session(self, mac: str) -> RouterSession | None:
        node = self._nodes.get(mac)
        if node is None or node.role == "router" or not self.settings.per_node:
            return None
        rule = self._overrides.find(mac, node.ip)
        if rule is not None and not rule.login:
            return None
        session = self._node_sessions.get(mac)
        if session is None:
            target = self._node_target(node)
            if target is None:
                return None
            guard = TargetGuard(
                f"node:{mac}",
                self._lockouts,
                clock=self._clock,
                rng=self._rng,
                node=True,
            )
            session = self._node_sessions[mac] = self._session(target, guard)
        return session

    def _unpinned_node(self, node: MeshNode) -> Target | None:
        """No pin for this node: no session (H1), and one warning per node."""
        if node.mac not in self._warned_unpinned:
            self._warned_unpinned.add(node.mac)
            _LOG.warning(
                "per_node: no pinned certificate for node %s; its session is skipped",
                node.mac,
            )
        return None

    def _pinned_node(self, node: MeshNode) -> Target | None:
        """A node session verified by its own leaf pin, else the node CA and its IP.

        It reads the root's live credentials, so a SIGHUP password reload also
        reaches node sessions that start later.
        """
        rule = self._overrides.find(node.mac, node.ip)
        pin = rule.pin if rule is not None and rule.pin is not None else self._node_pin
        if pin is None:
            return self._unpinned_node(node)
        if node.ip is None:
            return None
        root = self.root.target
        return Target(
            f"node:{node.mac}",
            node.ip,
            self._node_port or root.port,
            root.username,
            root.password,
            pin,
        )

    def _sessions(self) -> list[RouterSession]:
        return [self.root, *self._node_sessions.values()]

    def _read_password(self, reason: str, *, force: bool = False) -> SecretStr | None:
        """The password file's value if it changed (or ``force``); None otherwise."""
        signature = _stat_signature(self._password_file)
        if self._password_file is None or (
            not force and signature == self._password_sig
        ):
            return None
        self._password_sig = signature
        try:
            return read_secret(self._password_file, "asus.password_file")
        except ConfigError as exc:
            _LOG.error("password reload (%s) failed: %s", reason, exc)
            return None

    async def _renew_sessions(self, password: SecretStr) -> None:
        """Swap in fresh sessions without two admin logins at once.

        Jobs pause; the old sessions finish their jobs and log out; only then
        do the new sessions take over, and the next tick logs in once.
        """
        self._renewing = True
        try:
            old = self._sessions()
            await asyncio.gather(
                *(s.retire(self._retire_timeout_s) for s in old), return_exceptions=True
            )
            self.root = self._session(
                replace(self.root.target, password=password),
                self.root.guard,
                self._root_middlewares,
            )
            for mac, session in list(self._node_sessions.items()):
                self._node_sessions[mac] = self._session(
                    replace(session.target, password=password), session.guard
                )
        finally:
            self._renewing = False
        _LOG.info("router sessions renewed")

    def _save_counters(self) -> None:
        try:
            self._counters.save()
        except StateFileError as exc:
            _LOG.error("derived counters not saved: %s", exc)
