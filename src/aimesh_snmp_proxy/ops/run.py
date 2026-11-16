"""``run``: the daemon. Poll the router and serve each AiMesh node on loopback.

The collector fills its store. Every ``interval`` the engine sync gives each
node the store lists an engine on its pinned port (``ports.json``); a busy port
is retried later, never swapped for another node's port. SIGTERM and SIGINT
stop cleanly: the collector logs out and saves counters, then every socket
closes. SIGHUP re-reads the password file and clears latches.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import signal
import time
from collections.abc import Callable, Iterable
from functools import partial
from ipaddress import IPv4Address
from typing import Any

from aimesh_snmp_proxy.collector import Collector, NodeIdentity
from aimesh_snmp_proxy.config import (
    Config,
    ConfigError,
    Secrets,
    assert_unprivileged_user,
    load_router_pin,
    load_secrets,
)
from aimesh_snmp_proxy.ports import PortMap, PortMapError
from aimesh_snmp_proxy.snmp.engines import EngineSpec, SnmpServer, V3User

log = logging.getLogger(__name__)


EXIT_OK = 0
EXIT_FAILED = 1
EXIT_CONFIG = 78  # sysexits EX_CONFIG; the unit's RestartPreventExitStatus=78
SYNC_INTERVAL_S = 1.0
RETRY_FIRST_S = 5.0
RETRY_MAX_S = 60.0
STOP_GRACE_S = 20.0  # the unit's TimeoutStopSec=30 must cover logout too
CLOSE_TIMEOUT_S = 5.0
ROUTER_ROLE = "router"


def v3_user(cfg: Config, secrets: Secrets) -> V3User | None:
    """The configured SNMPv3 user with its keys, or None for v2c only."""
    v3 = cfg.snmp.v3
    if v3 is None or secrets.snmp_auth_key is None or secrets.snmp_priv_key is None:
        return None
    return V3User(
        v3.user,
        secrets.snmp_auth_key,
        secrets.snmp_priv_key,
        auth=v3.auth,
        priv=v3.priv,
    )


class Engines:
    """Gives every node the store lists one engine, on a port it keeps."""

    def __init__(
        self,
        cfg: Config,
        secrets: Secrets,
        ports: PortMap,
        server: Any,
        *,
        clock: Callable[[], float] = time.monotonic,
        retry_first_s: float | None = None,
        retry_max_s: float = RETRY_MAX_S,
    ) -> None:
        self._cfg = cfg
        self._ports = ports
        self._server = server
        self._clock = clock
        self._retry_first_s = RETRY_FIRST_S if retry_first_s is None else retry_first_s
        self._retry_max_s = retry_max_s
        self._community = secrets.snmp_community
        self._v3 = v3_user(cfg, secrets)
        self._served: dict[str, EngineSpec] = {}
        self._holders: dict[int, str] = {}  # port -> node_id
        self._waiting: dict[str, tuple[float, float]] = {}  # node_id -> (due, delay)
        self._refused: set[str] = set()
        self._noted: set[tuple[str, str]] = set()
        self._root: str | None = None

    async def sync(self, identities: Iterable[NodeIdentity]) -> None:
        """Start an engine for each new node; retry nodes whose port was busy."""
        for identity in sorted(identities, key=self._order):
            spec = self._served.get(identity.node_id)
            if spec is not None:
                self._check_name(identity, spec)
            elif identity.node_id not in self._refused and self._due(identity):
                await self._start(identity)

    def _is_root(self, identity: NodeIdentity) -> bool:
        """The AiMesh router role, or the asus.host IP, as config and ports agree."""
        root_ip = self._cfg.root_ip
        if identity.role == ROUTER_ROLE:
            return True
        try:
            return root_ip is not None and str(IPv4Address(identity.ip)) == root_ip
        except ValueError:  # router data is untrusted; a bad IP is no root
            return False

    def _order(self, identity: NodeIdentity) -> tuple[bool, bool, str]:
        # The root first, then override-pinned nodes, which may move a pin holder.
        override = self._cfg.override_for(identity.mac, identity.ip)
        pinned = override is not None and override.port is not None
        return not self._is_root(identity), not pinned, identity.node_id

    def _due(self, identity: NodeIdentity) -> bool:
        return self._waiting.get(identity.node_id, (0.0, 0.0))[0] <= self._clock()

    async def _start(self, identity: NodeIdentity) -> None:
        spec = self._spec(identity)
        if spec is None:
            return
        try:
            await self._server.add(spec)
        except OSError as exc:
            self._wait(identity, str(exc))
            return
        except ValueError as exc:
            self._refuse(identity, str(exc))
            return
        self._served[identity.node_id] = spec
        self._holders[spec.port] = identity.node_id
        self._waiting.pop(identity.node_id, None)
        self._noted.discard((identity.node_id, "wait"))
        log.info(
            "node %s (%s): engine on %s:%d",
            spec.sys_name,
            identity.node_id,
            self._cfg.snmp.bind,
            spec.port,
        )

    def _spec(self, identity: NodeIdentity) -> EngineSpec | None:
        if self._is_root(identity):
            if self._root not in (None, identity.node_id):
                self._refuse(identity, "a second root router; restart to serve it")
                return None
            self._root = identity.node_id
            port = self._ports.root_port
        else:
            override = self._cfg.override_for(identity.mac, identity.ip)
            pin = override.port if override is not None else None
            holder = self._holders.get(pin) if pin is not None else None
            if holder not in (None, identity.node_id):
                self._refuse(
                    identity, f"override port {pin} serves another node until restart"
                )
                return None
            try:
                port = self._ports.assign(identity.mac, ip=identity.ip, pin=pin)
            except PortMapError as exc:
                self._wait(identity, str(exc))
                return None
        if self._holders.get(port) not in (None, identity.node_id):
            self._refuse(identity, f"port {port} serves another node")
            return None
        try:
            return EngineSpec(
                node_id=identity.node_id,
                sys_name=identity.sys_name,
                mac=identity.mac,
                port=port,
                community=self._community,
                v3=self._v3,
                profile=self._cfg.snmp.profile,
            )
        except (TypeError, ValueError) as exc:
            self._refuse(identity, str(exc))
            return None

    def _wait(self, identity: NodeIdentity, why: str) -> None:
        delay = self._waiting.get(identity.node_id, (0.0, 0.0))[1]
        delay = min(max(delay * 2, self._retry_first_s), self._retry_max_s)
        self._waiting[identity.node_id] = (self._clock() + delay, delay)
        if (identity.node_id, "wait") not in self._noted:
            self._noted.add((identity.node_id, "wait"))
            log.warning(
                "node %s (%s): %s; retrying, at most every %g s",
                identity.sys_name,
                identity.node_id,
                why,
                self._retry_max_s,
            )

    def _refuse(self, identity: NodeIdentity, why: str) -> None:
        self._refused.add(identity.node_id)
        log.error(
            "node %s (%s): no engine: %s", identity.sys_name, identity.node_id, why
        )

    def _check_name(self, identity: NodeIdentity, spec: EngineSpec) -> None:
        note = (identity.node_id, f"name:{identity.sys_name}")
        if identity.sys_name != spec.sys_name and note not in self._noted:
            self._noted.add(note)
            log.warning(
                "node %s (%s): sysName is now %s; the engine keeps %s until restart",
                spec.sys_name,
                identity.node_id,
                identity.sys_name,
                spec.sys_name,
            )


async def _sync_loop(
    engines: Engines, store: Any, stop: asyncio.Event, interval: float
) -> None:
    while not stop.is_set():
        await engines.sync(store.identities())
        store.refresh_states()  # logs each SERVING or SILENT transition once
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), interval)


async def serve(
    cfg: Config,
    secrets: Secrets,
    collector: Any,
    ports: PortMap,
    *,
    server: Any = None,
    interval: float = SYNC_INTERVAL_S,
    grace_s: float = STOP_GRACE_S,
) -> int:
    """Run the collector and the engines until SIGTERM or SIGINT; the exit code."""
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    if server is None:
        server = SnmpServer(
            collector.store, bind=cfg.snmp.bind, state_dir=cfg.state_dir
        )
    engines = Engines(cfg, secrets, ports, server)
    reloads: set[asyncio.Task[None]] = set()

    def on_stop(name: str) -> None:
        if not stop.is_set():
            log.info("%s: stopping", name)
            stop.set()

    def on_hup() -> None:
        if stop.is_set():
            return
        log.info("SIGHUP: re-reading the password file and clearing latches")
        task = loop.create_task(collector.reload("SIGHUP"))
        reloads.add(task)
        task.add_done_callback(reloads.discard)

    handlers = {
        signal.SIGTERM: partial(on_stop, "SIGTERM"),
        signal.SIGINT: partial(on_stop, "SIGINT"),
        signal.SIGHUP: on_hup,
    }
    for sig, handler in handlers.items():
        loop.add_signal_handler(sig, handler)
    log.info("running: SNMP on %s, ports in %s", cfg.snmp.bind, cfg.ports_file)
    poller = asyncio.create_task(collector.run(stop), name="collector")
    syncer = asyncio.create_task(
        _sync_loop(engines, collector.store, stop, interval), name="engine sync"
    )
    try:
        await asyncio.wait({poller, syncer}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        stop.set()
        try:
            failed = await _finish(collector, poller, syncer, reloads, grace_s)
            server.close()
        finally:
            # Only now: a signal during logout would otherwise kill the process.
            for sig in handlers:
                loop.remove_signal_handler(sig)
    log.info("stopped")
    return EXIT_FAILED if failed else EXIT_OK


async def _finish(
    collector: Any,
    poller: asyncio.Task[None],
    syncer: asyncio.Task[None],
    reloads: set[asyncio.Task[None]],
    grace_s: float,
) -> bool:
    """Wait for both tasks, then close stray sessions; True when a task failed."""
    try:
        await asyncio.wait_for(asyncio.shield(poller), grace_s)
    except TimeoutError:
        log.warning("collector did not stop within %g s; cancelling it", grace_s)
        poller.cancel()
    except Exception:  # noqa: S110  gathered and logged below
        pass
    tasks = [poller, syncer, *reloads]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    failed = False
    for task, result in zip(tasks, results, strict=True):
        if isinstance(result, Exception):
            failed = True
            log.error("%s task failed", task.get_name(), exc_info=result)
    try:
        # A reload or a cancelled poll can leave a session open; close them all.
        await asyncio.wait_for(collector.shutdown(persist=False), CLOSE_TIMEOUT_S)
    except Exception as exc:
        log.warning("closing router sessions failed: %s", type(exc).__name__)
    return failed


def cli_run(config: Config, argv: list[str]) -> int:
    argparse.ArgumentParser(
        prog="aimesh-snmp-proxy run",
        description="Poll the router and serve each AiMesh node over SNMP on "
        "loopback until SIGTERM or SIGINT; SIGHUP re-reads the password file.",
    ).parse_args(argv)
    try:
        assert_unprivileged_user()
        secrets = load_secrets(config)
        pin = load_router_pin(config.asus.ca_file)
        ports = PortMap.load(
            config.ports_file,
            config.snmp.port_base,
            config.nodes.expected,
            root_ip=config.root_ip,
        )
        collector = Collector.from_config(config, secrets, pin)
    except (ConfigError, PortMapError) as exc:
        log.error("config error: %s", exc)
        return EXIT_CONFIG
    return asyncio.run(serve(config, secrets, collector, ports))
