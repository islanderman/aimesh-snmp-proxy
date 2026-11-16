"""``onboard``: add each node the proxy serves to LibreNMS through its API.

Nodes are planned from ``ports.json`` plus the config, with no router login:
the hostname is the sysName the proxy serves (override, else ``aimesh-`` plus
the last 6 hex digits of the MAC) or, with ``[onboard] hostname = "ip"``, the
node's LAN IP; ``overwrite_ip`` is the SNMP bind address, the port the node's pin.

A dry run is the default. ``--apply`` adds a node only when no device holds its
hostname or its SNMP endpoint (``overwrite_ip`` and port), so a renamed device is
not added twice, and never changes an existing device; ``--force`` sets
``force_add`` only after this tool's own SNMP GET of the node. ``onboarded.json``
records each create, so ``--remove`` deletes those devices, found by id and so
even when renamed, and nothing else.
"""

from __future__ import annotations

import argparse
import datetime
import ipaddress
import json
import sys
from dataclasses import dataclass, replace

from aimesh_snmp_proxy.config import (
    Config,
    ConfigError,
    Override,
    load_onboard_token,
    read_secret,
)
from aimesh_snmp_proxy.logsafe import MASK, SecretStr
from aimesh_snmp_proxy.ops.ledger import LEDGER_FILE, Entry, Ledger, LedgerError
from aimesh_snmp_proxy.ops.librenms import (
    API_ROOT,
    ApiError,
    AuthError,
    Device,
    LibreNMSClient,
    TransportError,
)
from aimesh_snmp_proxy.ops.snmpget import SnmpCheckError, get_identity
from aimesh_snmp_proxy.ports import PortMap, PortMapError

ROOT = "root"
NODE = "node"
EXIT_OK = 0
EXIT_FAILED = 1
EXIT_CONFIG = 78  # sysexits EX_CONFIG, as in __main__
DISPLAY = {ROOT: "AiMesh root {}", NODE: "AiMesh {}"}

# Evidence: no API field toggles ICMP; LibreNMS reads icmp_check once, at create
# (LegacyDeviceCreator.php:84, BuildDefaultPollingMethods.php:67-70).
ICMP_GUIDANCE = (
    "ICMP: the LibreNMS API cannot turn ICMP off for one device. Every node",
    "shares overwrite_ip 127.0.0.1, so LibreNMS would file all their ping results",
    "under one device. LibreNMS reads icmp_check only when it creates a device;",
    "on the LibreNMS host, as the librenms user, run:",
    "  before --apply:  lnms config:set icmp_check false",
    "  after --apply:   lnms config:set icmp_check true",
    "Devices created in between keep ICMP off. Web UI: Settings > Poller > Ping",
    "(/settings/icmp_check); per device afterwards: Edit device > Polling > ICMP.",
)


@dataclass(frozen=True)
class Node:
    """One SNMP endpoint as onboard plans it; ``skip`` says why it is not added.

    ``hostname`` names the LibreNMS device. ``sys_name`` is the sysName the proxy
    serves when that differs from it (``[onboard] hostname = "ip"``).
    """

    port: int
    role: str
    hostname: str | None
    skip: str | None = None
    sys_name: str | None = None

    @property
    def served(self) -> str | None:
        """The sysName the proxy serves on this port."""
        return self.sys_name or self.hostname


def _ipv4(text: str) -> str | None:
    try:
        return str(ipaddress.IPv4Address(text))
    except ValueError:
        return None


def plan_nodes(cfg: Config, ports: PortMap) -> tuple[list[Node], list[str]]:
    """The root and every pinned node, in port order, plus warnings.

    ``ports.json`` stores MACs, not IPs, so an IP override is placed the way
    PortMap assigns ports: the node pinned at the override's ``port``, else the
    node at the index reserved for that IP in ``nodes.expected``. The root is
    not pinned; ``Config.root_sys_name`` names it. With ``hostname = "ip"`` the
    LibreNMS hostname is that same IP, and the sysName moves to ``sys_name``.
    """
    expected = cfg.nodes.expected
    base = cfg.snmp.port_base
    router_ip = cfg.root_ip
    ip_overrides = [
        o for o in cfg.overrides if _ipv4(o.match) is not None and o.match != router_ip
    ]
    loose = [o for o in ip_overrides if o.port is None and o.match not in expected]
    warnings = [
        f"override match {o.match}: outside nodes.expected and without a port, "
        "so onboard cannot tell its node without a router login; match it by MAC"
        for o in loose
    ]

    matched: dict[str, Override | None] = {}
    lan_ips: dict[int, str | None] = {base: router_ip}
    for mac, port in ports.pinned().items():
        index = port - base
        reserved_ip = expected[index - 1] if 1 <= index <= len(expected) else None
        matched[mac] = _override_for(cfg, mac, port, reserved_ip, ip_overrides)
        by_ip = matched[mac] if matched[mac] in ip_overrides else None
        lan_ips[port] = by_ip.match if by_ip is not None else reserved_ip
    names = cfg.sys_names(
        (mac, o.match if o is not None and o in ip_overrides else None)
        for mac, o in matched.items()
    )

    nodes = [_root(cfg)]
    for mac, port in ports.pinned().items():
        override = matched[mac]
        if override is not None and override.exclude:
            nodes.append(Node(port, NODE, None, "excluded by override"))
        elif override is None and loose and port - base > len(expected):
            reason = "an IP override may name this node; match it by MAC"
            nodes.append(Node(port, NODE, names[mac], reason))
        else:
            nodes.append(Node(port, NODE, names[mac]))
    nodes.sort(key=lambda n: n.port)
    if cfg.onboard is not None and cfg.onboard.hostname == "ip":
        nodes = [_named_by_ip(node, lan_ips.get(node.port)) for node in nodes]
    return _refuse_unsafe(nodes), warnings


def _override_for(
    cfg: Config,
    mac: str,
    port: int,
    reserved_ip: str | None,
    ip_overrides: list[Override],
) -> Override | None:
    by_mac = cfg.override_for(mac)
    if by_mac is not None:
        return by_mac
    for override in ip_overrides:
        if override.port == port:
            return override
    for override in ip_overrides:
        if override.port is None and override.match == reserved_ip:
            return override
    return None


def _root(cfg: Config) -> Node:
    """The root serves ``port_base``; config names it without a router login."""
    name = cfg.root_sys_name()
    if name is None:
        return Node(cfg.snmp.port_base, ROOT, None, "excluded by override")
    return Node(cfg.snmp.port_base, ROOT, name)


def _named_by_ip(node: Node, ip: str | None) -> Node:
    """Move the sysName to ``sys_name`` and name the node by its LAN IP."""
    if node.hostname is None:  # excluded
        return node
    if ip is not None:
        return replace(node, hostname=ip, sys_name=node.hostname)
    what = "asus.host" if node.role == ROOT else "nodes.expected"
    reason = f"no LAN IP to name it by without a router login: set {what} to an IPv4"
    return replace(
        node, hostname=None, skip=node.skip or reason, sys_name=node.hostname
    )


def _refuse_unsafe(nodes: list[Node]) -> list[Node]:
    """Skip names the device API would misread or that two endpoints share."""
    owners: dict[str, list[int]] = {}
    for node in nodes:
        if node.hostname is not None and node.skip is None:
            owners.setdefault(node.hostname.lower(), []).append(node.port)
    safe = []
    for node in nodes:
        if node.hostname is None or node.skip is not None:
            safe.append(node)
            continue
        others = [p for p in owners[node.hostname.lower()] if p != node.port]
        if node.hostname.isdigit():
            # The API reads an all-digit path segment as a device id.
            reason = "an all-digit hostname reads as a device id in the LibreNMS API"
        elif others:
            ports = ", ".join(map(str, others))
            reason = f"hostname also planned for port {ports}; rename one by override"
        else:
            reason = None
        safe.append(replace(node, skip=reason))
    return safe


# --- command line ------------------------------------------------------------


class _StopError(Exception):
    """Ends the run: later calls would fail alike or act on an unknown state."""


@dataclass(frozen=True)
class _Setup:
    client: LibreNMSClient
    community: SecretStr
    ledger: Ledger


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aimesh-snmp-proxy onboard",
        description="Add each node the proxy serves to LibreNMS through its API, "
        "or remove the devices onboard added. Prints the planned calls only, "
        "unless --apply.",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--dry-run",
        dest="apply",
        action="store_false",
        help="print the planned API calls and send nothing (default)",
    )
    mode.add_argument(
        "--apply", dest="apply", action="store_true", help="send the API calls"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="add with force_add=true, which skips the LibreNMS checks, but only "
        "after this tool's own SNMP GET of the node succeeds",
    )
    parser.add_argument(
        "--remove",
        action="store_true",
        help=f"delete the devices that state_dir/{LEDGER_FILE} lists as created by "
        "onboard, and nothing else",
    )
    parser.add_argument(
        "--allow-http",
        action="store_true",
        help="accept an http:// url; the API token then travels in cleartext",
    )
    parser.set_defaults(apply=False)
    return parser


def cli_onboard(config: Config, argv: list[str]) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.force and args.remove:
        parser.error("--force adds devices; it does not combine with --remove")
    try:
        setup = _setup(config, args)
        ports = None
        if not args.remove:
            ports = PortMap.load(
                config.ports_file,
                config.snmp.port_base,
                config.nodes.expected,
                root_ip=config.root_ip,
                read_only=True,
            )
        if args.apply:
            setup.ledger.save()  # fail before the first change, not after it
    except (ConfigError, PortMapError, LedgerError) as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    if ports is None:
        return _remove(config, args, setup)
    return _onboard(config, args, setup, ports)


def _setup(cfg: Config, args: argparse.Namespace) -> _Setup:
    if cfg.onboard is None:
        raise ConfigError("[onboard] is missing: set url and token_file")
    if cfg.snmp.community_file is None:
        raise ConfigError("onboard registers v2c devices: set snmp.community_file")
    token = load_onboard_token(cfg)
    community = read_secret(cfg.snmp.community_file, "snmp.community_file")
    client = LibreNMSClient(
        cfg.onboard.url,
        token,
        allow_http=args.allow_http,
        ca_file=cfg.onboard.ca_file,
        secrets=(community,),
    )
    return _Setup(client, community, Ledger.load(cfg.state_dir / LEDGER_FILE))


def device_body(cfg: Config, node: Node, community: str, *, force: bool) -> dict:
    """The add_device JSON for one node (``api_functions.inc.php:420-444``)."""
    body: dict[str, object] = {
        "hostname": node.hostname,
        "display_template": DISPLAY[node.role].format(node.served),
        "overwrite_ip": cfg.snmp.bind,
        "port": node.port,
        "transport": "udp",
        "snmpver": "v2c",
        "community": community,
        "os": cfg.snmp.profile,
    }
    if force:
        body["force_add"] = True
    return body


def _row(port: object, role: str, hostname: str, text: str, width: int) -> str:
    return f"{port!s:<6} {role:<5} {hostname:<{width}}  {text}"


def _width(nodes: list[Node]) -> int:
    return max([len("HOSTNAME"), *(len(n.hostname or "-") for n in nodes)])


def _onboard(
    cfg: Config, args: argparse.Namespace, setup: _Setup, ports: PortMap
) -> int:
    nodes, warnings = plan_nodes(cfg, ports)
    if not cfg.ports_file.exists():
        warnings.insert(
            0,
            f"no ports.json at {cfg.ports_file} yet: start the service so it pins "
            "a port for each node",
        )
    verb = "adding nodes to" if args.apply else "dry run; nothing is sent to"
    print(f"onboard: {verb} {setup.client.base_url}")
    for warning in warnings:
        print(f"warning: {warning}")
    print("", *ICMP_GUIDANCE, "", sep="\n")
    if args.apply:
        return _apply(cfg, args, setup, nodes)
    _print_calls(cfg, args, nodes)
    width = _width(nodes)
    print(_row("PORT", "ROLE", "HOSTNAME", "PLAN", width))
    for node in nodes:
        if node.skip is not None:
            plan = f"skipped: {node.skip}"
        else:
            plan = "add after SNMP GET (force_add)" if args.force else "add (checked)"
            if node.sys_name:
                plan += f"; serves sysName {node.sys_name}"
        print(_row(node.port, node.role, node.hostname or "-", plan, width))
    print("\nRun again with --apply to send these calls.")
    return EXIT_OK


def _print_calls(cfg: Config, args: argparse.Namespace, nodes: list[Node]) -> None:
    todo = [n for n in nodes if n.skip is None]
    if not todo:
        print("No node to add.\n")
        return
    print("Planned API calls, in port order; a node that exists stops at its GET:")
    where = f"{cfg.snmp.bind}:PORT"
    print(f"  GET  {API_ROOT}/devices  (once: a node already at {where} is left alone)")
    for node in todo:
        body = device_body(cfg, node, MASK, force=args.force)
        print(f"  GET  {API_ROOT}/devices/{node.hostname}")
        if args.force:
            at = f"{cfg.snmp.bind}:{node.port}"
            print(f"  SNMP GET sysObjectID.0, sysName.0 from {at}; on success:")
        print(f"  POST {API_ROOT}/devices {json.dumps(body, sort_keys=True)}")
    print()


def _apply(
    cfg: Config, args: argparse.Namespace, setup: _Setup, nodes: list[Node]
) -> int:
    width = _width(nodes)
    print(_row("PORT", "ROLE", "HOSTNAME", "RESULT", width))
    known: list[Device] = []
    if any(node.skip is None for node in nodes):
        try:
            known = setup.client.list_devices()
        except ApiError as exc:  # no list, so no way to tell a renamed device
            print(f"stopped: {exc}")
            print(f"onboard stopped: {exc}", file=sys.stderr)
            return EXIT_FAILED
    outcomes: list[str] = []
    for node in nodes:
        hostname = node.hostname or "-"
        if node.skip is not None:
            print(_row(node.port, node.role, hostname, f"skipped: {node.skip}", width))
            continue
        try:
            outcome, text = _add(cfg, args, setup, node, known)
        except _StopError as exc:
            print(_row(node.port, node.role, hostname, f"stopped: {exc}", width))
            print(f"onboard stopped at {hostname}: {exc}", file=sys.stderr)
            return EXIT_FAILED
        outcomes.append(outcome)
        print(_row(node.port, node.role, hostname, text, width))
    if "refused" in outcomes and not args.force:
        print(
            "\nLibreNMS refused a checked add. Every node shares overwrite_ip "
            "127.0.0.1, so its duplicate check can refuse them: run again with "
            "--force, which first checks each node over SNMP itself."
        )
    added = outcomes.count("added")
    print(
        f"\nCreated {added} device(s). {setup.ledger.path} lists "
        f"{len(setup.ledger.entries())}; onboard --remove deletes only those."
    )
    print("Next: lnms config:set icmp_check true")
    failed = any(o in ("failed", "refused") for o in outcomes)
    return EXIT_FAILED if failed else EXIT_OK


def _add(
    cfg: Config,
    args: argparse.Namespace,
    setup: _Setup,
    node: Node,
    known: list[Device],
) -> tuple[str, str]:
    """One node: GET, optional SNMP GET, POST, record. Returns (outcome, text)."""
    try:
        existing = setup.client.get_device(node.hostname)
    except ApiError as exc:  # unexpected answers too: never guess and create
        raise _StopError(str(exc)) from None
    if existing is None:  # a renamed device keeps its endpoint
        existing = next(
            (
                d
                for d in known
                if (d.overwrite_ip, d.port) == (cfg.snmp.bind, node.port)
            ),
            None,
        )
    if existing is not None:
        return "exists", _exists_text(existing, node)
    force = False
    if args.force:
        try:
            identity = get_identity(cfg.snmp.bind, node.port, setup.community)
        except SnmpCheckError as exc:
            return "failed", f"failed: SNMP GET: {exc}; not added"
        if identity.sys_name != node.served:
            served = (
                "no sysName"
                if identity.sys_name is None
                else f"sysName {identity.sys_name!r}"
            )
            where = f"{cfg.snmp.bind}:{node.port}"
            return (
                "failed",
                f"failed: {where} serves {served}, not {node.served}; not added",
            )
        force = True
    body = device_body(cfg, node, setup.community.get_secret_value(), force=force)
    try:
        device = setup.client.add_device(body)
    except AuthError as exc:
        raise _StopError(str(exc)) from None
    except TransportError as exc:
        raise _StopError(
            f"{exc}; the device may exist: check LibreNMS before running again"
        ) from None
    except ApiError as exc:  # 400: a LibreNMS check refused the add
        return ("refused" if exc.status == 400 else "failed"), f"failed: {exc}"
    entry = Entry(
        node.hostname, device.device_id, node.port, setup.client.origin, _now()
    )
    try:
        setup.ledger.record(entry)
    except LedgerError as exc:
        raise _StopError(
            f"added device {device.device_id} but could not record it ({exc}); "
            "onboard --remove will not delete it"
        ) from None
    return "added", f"added (device {device.device_id})"


def _exists_text(existing: Device, node: Node) -> str:
    if existing.hostname.lower() == (node.hostname or "").lower():
        return f"exists (device {existing.device_id}); left unchanged"
    return (
        f"exists as {existing.hostname} (device {existing.device_id}), "
        "same SNMP endpoint; left unchanged"
    )


def _now() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# --- removal -------------------------------------------------------------------


def _remove(cfg: Config, args: argparse.Namespace, setup: _Setup) -> int:
    origin, ledger = setup.client.origin, setup.ledger
    verb = "deleting from" if args.apply else "dry run; nothing is sent to"
    print(f"onboard --remove: {verb} {setup.client.base_url}")
    print(f"Only devices that {ledger.path} lists are touched.")
    mine = []
    for entry in ledger.entries():
        if entry.origin == origin:
            mine.append(entry)
        else:
            print(
                f"warning: {entry.hostname} was created on {entry.origin}, "
                f"not {origin}; left alone"
            )
    if not mine:
        print("Nothing to remove.")
        return EXIT_OK
    width = max(len("HOSTNAME"), *(len(e.hostname) for e in mine))
    if not args.apply:
        print("\nPlanned API calls, in port order:")
        for entry in mine:
            path = f"{API_ROOT}/devices/{entry.device_id}"
            where = f"{cfg.snmp.bind}:{entry.port}"
            note = f"created as {entry.hostname}; must still be at {where}"
            print(f"  GET    {path}  ({note})")
            print(f"  DELETE {path}")
        print("\n" + _row("PORT", "ROLE", "HOSTNAME", "PLAN", width))
        for entry in mine:
            plan = f"delete device {entry.device_id}"
            print(_row(entry.port, "-", entry.hostname, plan, width))
        print("\nRun again with --apply to send these calls.")
        return EXIT_OK
    print("\n" + _row("PORT", "ROLE", "HOSTNAME", "RESULT", width))
    failed = False
    for entry in mine:
        try:
            text, ok = _remove_one(cfg, setup, entry)
        except _StopError as exc:
            print(_row(entry.port, "-", entry.hostname, f"stopped: {exc}", width))
            print(f"onboard stopped at {entry.hostname}: {exc}", file=sys.stderr)
            return EXIT_FAILED
        failed = failed or not ok
        print(_row(entry.port, "-", entry.hostname, text, width))
    return EXIT_FAILED if failed else EXIT_OK


def _remove_one(cfg: Config, setup: _Setup, entry: Entry) -> tuple[str, bool]:
    """GET by id, DELETE by id only if it still sits at the endpoint onboard gave it.

    The hostname is no key: the operator may have renamed the device since.
    """
    try:
        device = setup.client.get_device_by_id(entry.device_id)
    except ApiError as exc:
        raise _StopError(str(exc)) from None
    if device is None:
        _forget(setup, entry)
        return "already gone; forgotten", True
    here = (device.device_id, device.overwrite_ip, device.port)
    if here != (entry.device_id, cfg.snmp.bind, entry.port):
        seen = f"{device.overwrite_ip or '-'}:{device.port or '-'}"
        return (
            f"kept: device {device.device_id} ({device.hostname}) is at {seen}, not "
            f"at {cfg.snmp.bind}:{entry.port} where onboard created it",
            False,
        )
    try:
        removed = setup.client.delete_device_by_id(entry.device_id)
    except AuthError as exc:
        raise _StopError(str(exc)) from None
    except TransportError as exc:
        raise _StopError(
            f"{exc}; the device may be gone: check LibreNMS before running again"
        ) from None
    except ApiError as exc:
        return f"failed: {exc}", False
    _forget(setup, entry)
    return (f"removed (device {entry.device_id})" if removed else "already gone"), True


def _forget(setup: _Setup, entry: Entry) -> None:
    try:
        setup.ledger.forget(entry.hostname)
    except LedgerError as exc:
        raise _StopError(f"device {entry.device_id} is gone, but {exc}") from None
