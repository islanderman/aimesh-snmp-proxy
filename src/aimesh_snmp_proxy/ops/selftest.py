"""``selftest``: one read-only router poll, then each node over SNMP on loopback.

The router latch file is copied to a scratch directory first, so a latch still
blocks the login while nothing in ``state_dir`` changes, ``ports.json``
included. Engines bind free ports outside the service's range, so a running
service is never disturbed; the router sees one more read-only login.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import re
import shutil
import socket
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, TextIO

from pysnmp.proto import rfc1902

from aimesh_snmp_proxy.collector import Collector, NodeIdentity
from aimesh_snmp_proxy.config import (
    Config,
    ConfigError,
    RouterPin,
    Secrets,
    load_router_pin,
    load_secrets,
)
from aimesh_snmp_proxy.ops.run import v3_user
from aimesh_snmp_proxy.ops.snmpget import (
    SYS_DESCR,
    SYS_NAME,
    SYS_OBJECT_ID,
    SnmpCheckError,
    get,
    text,
    walk,
)
from aimesh_snmp_proxy.ports import MAX_INDEX
from aimesh_snmp_proxy.profiles.asuswrt_merlin import (
    EXTEND_OUTPUT_1LINE,
    EXTEND_OUTPUT_FULL,
    encode_string,
)
from aimesh_snmp_proxy.snmp.engines import MIN_PORT, EngineSpec, SnmpServer

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_CONFIG = 78
QUERY_TIMEOUT_S = 1.0
QUERY_RETRIES = 1
BIND_ATTEMPTS = 5
_RATE_NAMES = tuple(
    f"{d}-{{}}-{p}" for d in ("tx", "rx") for p in ("min", "max", "avg")
)
_NUMERIC = re.compile(
    r"\s*[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?\s*"
)  # PHP is_numeric
_INTERFACES = ".".join(map(str, (*EXTEND_OUTPUT_FULL, *encode_string("interfaces"))))
_ONE_LINE = ".".join(map(str, EXTEND_OUTPUT_1LINE)) + "."


@dataclasses.dataclass(frozen=True)
class NodeReport:
    """What one node's test engine answered; ``reason`` explains a failure."""

    identity: NodeIdentity
    port: int | None
    online: bool | None
    serving: bool
    reason: str | None = None
    sys_object_id: str | None = None
    sys_name: str | None = None
    sys_descr: str | None = None
    oid_count: int | None = None
    created: tuple[str, ...] = ()
    omitted: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.serving and self.reason is None


# --- LibreNMS wireless discovery, replayed --------------------------------------


def wireless_sensors(
    interfaces: str | None, extends: Mapping[str, str]
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """The wireless sensors LibreNMS ``AsuswrtMerlin`` discovery would create.

    It reads ``key,label`` lines from the ``interfaces`` extend, then one
    1-line extend per sensor, and drops a value that is not numeric.
    """
    keys = [
        line.split(",", 1)[0] for line in (interfaces or "").split("\n") if line.strip()
    ]
    if not keys:
        return (), ("all (no interfaces extend)",)

    def numeric(name: str) -> bool:
        return _NUMERIC.fullmatch(extends.get(name, "x")) is not None

    created: list[str] = []
    omitted: list[str] = []

    def group(
        target: list[str], sensor: str, names: Sequence[str], why: str = ""
    ) -> None:
        if names:
            target.append(f"{sensor} {' '.join(names)}" + (f" ({why})" if why else ""))

    clients = [k for k in keys if numeric(f"clients-{k}")]
    missing = [k for k in keys if k not in clients]
    if len(keys) > 1:  # LibreNMS adds the wlan total only for 2+ interfaces
        (clients if numeric("clients-wlan") else missing).append("wlan")
    group(created, "clients", clients)
    group(omitted, "clients", missing, "missing")
    freq = [k for k in keys if numeric(f"frequency-{k}")]
    group(created, "frequency", freq)
    group(omitted, "frequency", [k for k in keys if k not in freq], "channel unknown")
    full, idle, partial, unknown = [], [], [], []
    for key in keys:
        found = sum(numeric("rate-" + name.format(key)) for name in _RATE_NAMES)
        if found == len(_RATE_NAMES):
            full.append(key)
        elif found:
            partial.append(f"rate {key} ({found} of {len(_RATE_NAMES)} values)")
        elif extends.get(f"clients-{key}", "").strip() == "0":
            idle.append(key)
        else:
            unknown.append(key)
    group(created, "rate", full)
    group(omitted, "rate", idle, "no clients")
    omitted.extend(partial)
    group(omitted, "rate", unknown, "rate unknown")
    omitted.append("snr, noise-floor (never served)")
    return tuple(created), tuple(omitted)


def _extends(rows: Sequence[tuple[str, Any]]) -> tuple[str | None, dict[str, str]]:
    """The ``interfaces`` text and every 1-line extend, by name, from a walk."""
    interfaces, extends = None, {}
    for oid, value in rows:
        if oid == _INTERFACES:
            interfaces = text(value)
        elif oid.startswith(_ONE_LINE):
            index = [int(part) for part in oid[len(_ONE_LINE) :].split(".")]
            if index and index[0] == len(index) - 1 and all(b < 256 for b in index):
                extends[bytes(index[1:]).decode("utf-8", "replace")] = text(value) or ""
    return interfaces, extends


# --- test engines ----------------------------------------------------------------


def _free_port(cfg: Config) -> int:
    """A port the OS has free now, outside the range the service may bind."""
    service = range(cfg.snmp.port_base, cfg.snmp.port_base + MAX_INDEX + 1)
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind((cfg.snmp.bind, 0))
            port = sock.getsockname()[1]
        if port >= MIN_PORT and port not in service:
            return port


async def _start(
    server: SnmpServer, cfg: Config, secrets: Secrets, identity: NodeIdentity
) -> int:
    error: OSError | None = None
    for _ in range(BIND_ATTEMPTS):  # another program may take the port first
        spec = EngineSpec(
            node_id=identity.node_id,
            sys_name=identity.sys_name,
            mac=identity.mac,
            port=_free_port(cfg),
            community=secrets.snmp_community,
            v3=v3_user(cfg, secrets),
            profile=cfg.snmp.profile,
        )
        try:
            await server.add(spec)
        except OSError as exc:
            error = exc
        else:
            return spec.port
    raise error or OSError("no free port")


async def _query(
    host: str, port: int, credentials: Any, identity: NodeIdentity, online: bool | None
) -> NodeReport:
    known = {"identity": identity, "port": port, "online": online}
    options = {"timeout": QUERY_TIMEOUT_S, "retries": QUERY_RETRIES}
    oids = [SYS_OBJECT_ID, SYS_NAME, SYS_DESCR]
    try:
        values = await get(host, port, credentials, oids, **options)
    except SnmpCheckError as exc:
        return NodeReport(**known, serving=False, reason=str(exc))
    oid = values.get(SYS_OBJECT_ID)
    found = {
        "sys_object_id": (
            str(oid)
            if oid is not None and oid.tagSet == rfc1902.ObjectIdentifier.tagSet
            else None
        ),
        "sys_name": text(values.get(SYS_NAME)),
        "sys_descr": text(values.get(SYS_DESCR)),
    }
    try:
        rows = await walk(host, port, credentials, "1.3.6", **options)
    except SnmpCheckError as exc:
        return NodeReport(**known, serving=True, reason=f"walk: {exc}", **found)
    reason = None
    if found["sys_object_id"] is None:
        reason = "no sysObjectID.0"
    elif found["sys_name"] != identity.sys_name:
        reason = f"serves sysName {found['sys_name']!r}, not {identity.sys_name}"
    created, omitted = wireless_sensors(*_extends(rows))
    return NodeReport(
        **known,
        serving=True,
        reason=reason,
        **found,
        oid_count=len(rows),
        created=created,
        omitted=omitted,
    )


async def check_nodes(
    cfg: Config,
    secrets: Secrets,
    source: Any,
    identities: Sequence[NodeIdentity],
    online: Mapping[str, bool],
    *,
    state_dir: Path | None = None,
) -> list[NodeReport]:
    """Serve each node from ``source`` on a free port and query it in-process."""
    server = SnmpServer(source, bind=cfg.snmp.bind, state_dir=state_dir)
    credentials = secrets.snmp_community or v3_user(cfg, secrets)
    reports = []
    try:
        for identity in identities:
            state = online.get(identity.node_id)
            try:
                port = await _start(server, cfg, secrets, identity)
            except (OSError, ValueError) as exc:
                reason = f"no engine: {exc}"
                reports.append(NodeReport(identity, None, state, False, reason))
                continue
            reports.append(
                await _query(cfg.snmp.bind, port, credentials, identity, state)
            )
    finally:
        server.close()
    return reports


# --- the report ------------------------------------------------------------------


def _absent(cfg: Config, identities: Sequence[NodeIdentity]) -> list[str]:
    present = {identity.ip for identity in identities}
    absent = []
    for ip in cfg.nodes.expected:
        override = cfg.override_for("", ip)
        if ip not in present and not (override is not None and override.exclude):
            absent.append(ip)
    return absent


def print_report(
    cfg: Config, reports: Sequence[NodeReport], latch: Any, out: TextIO
) -> int:
    """Print the table and details; the exit code."""
    print(
        f"selftest: one read-only poll of {cfg.asus.host}; test engines on "
        f"{cfg.snmp.bind} outside the service ports; nothing is written",
        file=out,
    )
    if not reports:
        why = f"the router is latched ({latch})" if latch else "see the log above"
        print(f"router: no AiMesh list; {why}\nFAIL: no node to check", file=out)
        return EXIT_FAILED
    width = max(len("NODE"), *(len(r.identity.sys_name) for r in reports))
    models = [r.identity.model or "-" for r in reports]
    mwidth = max(len("MODEL"), *(len(m) for m in models))
    print(f"\n{'NODE':<{width}}  {'MODEL':<{mwidth}}  ONLINE  STATE    OIDS", file=out)
    for report, model in zip(reports, models, strict=True):
        online = {True: "yes", False: "no", None: "-"}[report.online]
        state = "serving" if report.serving else "silent"
        oids = "-" if report.oid_count is None else str(report.oid_count)
        print(
            f"{report.identity.sys_name:<{width}}  {model:<{mwidth}}  "
            f"{online:<6}  {state:<7}  {oids:>4}",
            file=out,
        )
    print(file=out)
    for report in reports:
        name = report.identity.sys_name
        if not report.serving:
            print(f"{name}: silent: {report.reason}", file=out)
            continue
        print(
            f"{name}: sysObjectID .{report.sys_object_id}; sysDescr {report.sys_descr}",
            file=out,
        )
        if report.reason:
            print(f"  FAIL: {report.reason}", file=out)
        print(f"  wireless created: {'; '.join(report.created) or 'none'}", file=out)
        print(f"  wireless omitted: {'; '.join(report.omitted) or 'none'}", file=out)
    absent = _absent(cfg, [r.identity for r in reports])
    for ip in absent:
        print(f"expected {ip}: absent from the AiMesh list", file=out)
    good = sum(r.ok for r in reports)
    if good == len(reports) and not absent:
        print(f"OK: all {good} nodes serve", file=out)
        return EXIT_OK
    missing = f"; {len(absent)} expected node(s) absent" if absent else ""
    print(f"FAIL: {good} of {len(reports)} nodes serve{missing}", file=out)
    return EXIT_FAILED


# --- entry points ----------------------------------------------------------------


async def selftest(
    cfg: Config,
    secrets: Secrets,
    pin: RouterPin,
    *,
    out: TextIO | None = None,
    **collector_options: Any,
) -> int:
    """Poll once, check every node, print the report; the exit code."""
    out = out or sys.stdout
    with tempfile.TemporaryDirectory(prefix="aimesh-selftest-") as scratch:
        scratch_dir = Path(scratch)
        if cfg.lockout_file.exists():
            try:  # the latches still apply; their updates stay in scratch
                shutil.copyfile(cfg.lockout_file, scratch_dir / cfg.lockout_file.name)
            except OSError as exc:
                print(
                    f"selftest: cannot read {cfg.lockout_file}: {exc.strerror}",
                    file=out,
                )
                return EXIT_FAILED
        try:
            collector = Collector.from_config(
                dataclasses.replace(cfg, state_dir=scratch_dir),
                secrets,
                pin,
                **collector_options,
            )
        except ConfigError as exc:
            print(f"config error: {exc}", file=sys.stderr)
            return EXIT_CONFIG
        try:
            await collector.poll_once()
        finally:
            await collector.shutdown(persist=False)
        identities = collector.store.identities()
        online = {mac: node.online for mac, node in collector.nodes.items()}
        reports = await check_nodes(
            cfg, secrets, collector.store, identities, online, state_dir=scratch_dir
        )
    return print_report(cfg, reports, collector.root.guard.latch, out)


def cli_selftest(config: Config, argv: list[str]) -> int:
    argparse.ArgumentParser(
        prog="aimesh-snmp-proxy selftest",
        description="Read-only check: one router poll, then each node over SNMP "
        "on loopback test ports. Writes nothing; exit 0 only when every expected "
        "node serves.",
    ).parse_args(argv)
    try:
        secrets = load_secrets(config)
        pin = load_router_pin(config.asus.ca_file)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    return asyncio.run(selftest(config, secrets, pin))
