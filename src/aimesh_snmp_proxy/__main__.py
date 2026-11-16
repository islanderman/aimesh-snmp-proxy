"""Command-line entry point: ``aimesh-snmp-proxy`` or ``python -m aimesh_snmp_proxy``.

``check-config`` runs here. Every other command lives in a sibling package that
is imported on demand, so the CLI works before those packages exist.
"""

from __future__ import annotations

import argparse
import importlib
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from aimesh_snmp_proxy import __version__
from aimesh_snmp_proxy.config import (
    Config,
    ConfigError,
    RouterPin,
    load_config,
    load_node_ca,
    load_node_pin,
    load_router_pin,
    load_secrets,
)
from aimesh_snmp_proxy.logsafe import setup_logging
from aimesh_snmp_proxy.ports import PortMap, PortMapError

DEFAULT_CONFIG = Path("/etc/aimesh-snmp-proxy/config.toml")
CONFIG_ENV = "AIMESH_PROXY_CONFIG"
DEFAULT_ROUTER_HTTPS_PORT = 8443  # asusrouter DEFAULT_PORT_HTTPS
EXIT_NOT_IMPLEMENTED = 2
EXIT_CONFIG = 78  # sysexits EX_CONFIG; systemd RestartPreventExitStatus=78 skips loops

Handler = Callable[[Config | None, list[str]], int]
# These run without a config file unless one is named; their handler gets None.
CONFIG_OPTIONAL = frozenset({"dump-snmprec"})

# command -> (module, handler, help); the handler parses its own options.
COMMANDS: dict[str, tuple[str, str, str]] = {
    "run": ("aimesh_snmp_proxy.ops", "cli_run", "poll the router and serve SNMP"),
    "dump-snmprec": (
        "aimesh_snmp_proxy.profiles",
        "cli_dump_snmprec",
        "print the OIDs a snapshot renders, in snmprec format",
    ),
    "discover": (
        "aimesh_snmp_proxy.collector",
        "cli_discover",
        "list the router and its nodes read-only; --fixtures DIR, --pin-cert PATH",
    ),
    "onboard": (
        "aimesh_snmp_proxy.ops",
        "cli_onboard",
        "add every node to LibreNMS (dry run by default)",
    ),
    "selftest": (
        "aimesh_snmp_proxy.ops",
        "cli_selftest",
        "query every node endpoint over SNMP",
    ),
}


def _add_config_option(parser: argparse.ArgumentParser) -> None:
    # SUPPRESS keeps a value given before the command when none follows it.
    parser.add_argument(
        "-c",
        "--config",
        type=Path,
        default=argparse.SUPPRESS,
        help=f"config file (default: ${CONFIG_ENV}, else {DEFAULT_CONFIG})",
    )


def build_parser() -> argparse.ArgumentParser:
    """``--config`` works before or after the command; the later one wins."""
    parser = argparse.ArgumentParser(
        prog="aimesh-snmp-proxy",
        description="Serve ASUS router and AiMesh node metrics over SNMP for LibreNMS.",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    _add_config_option(parser)
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")
    check = commands.add_parser(
        "check-config", help="validate the config, secret files, and router pin"
    )
    _add_config_option(check)
    for name, (_, _, help_text) in COMMANDS.items():
        _add_config_option(commands.add_parser(name, help=help_text, add_help=False))
    return parser


def config_path(args: argparse.Namespace) -> Path | None:
    """The ``--config`` value, else ``$AIMESH_PROXY_CONFIG``; None if neither."""
    named = getattr(args, "config", None)
    if named is not None:
        return named
    env = os.environ.get(CONFIG_ENV)
    return Path(env) if env else None


def _load_handler(command: str) -> Handler | None:
    """The command's handler, or None while its package does not exist yet."""
    module_name, attribute, _ = COMMANDS[command]
    try:
        module = importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        if exc.name != module_name:  # a broken dependency, not a missing command
            raise
        return None
    return getattr(module, attribute, None)


def describe(
    cfg: Config,
    pin: RouterPin,
    ports: PortMap,
    node_pin: RouterPin | None = None,
    leaf_pins: Mapping[int, RouterPin] | None = None,
) -> list[str]:
    """Summary lines for ``check-config``: no secret values and no MACs.

    ``leaf_pins`` maps an ``[[override]]`` index to its node's own leaf pin.
    """
    asus, snmp = cfg.asus, cfg.snmp
    port = asus.port or DEFAULT_ROUTER_HTTPS_PORT
    router = f"{asus.host} port {port} over HTTPS, pin {', '.join(pin.fingerprints)}"
    v2c = "v2c community file" if snmp.community_file else "v2c off"
    v3 = (
        f"v3 user {snmp.v3.user} {snmp.v3.auth}/{snmp.v3.priv}" if snmp.v3 else "v3 off"
    )
    stale = f"{cfg.collector.stale_after_s:g}"
    expected = len(cfg.nodes.expected)
    reserved = (
        f"{expected} expected (ports {snmp.port_base + 1}-{snmp.port_base + expected})"
        if expected
        else "none expected"
    )
    pinned = sorted(ports.pinned().values())
    pins = (
        f"{len(pinned)} pinned (ports {pinned[0]}-{pinned[-1]})"
        if pinned
        else "none pinned yet"
    )
    node_ca = []
    per_node = cfg.collector.mode == "per_node"
    unused = f"unused: collector.mode is {cfg.collector.mode}"
    if node_pin is not None:
        use = "per_node sessions check each node's IP" if per_node else unused
        node_ca = [f"node CA: {', '.join(node_pin.fingerprints)} ({use})"]
    use = "per_node: that node's exact certificate, by any name" if per_node else unused
    node_ca += [
        f"node pin: override[{index}] {', '.join(leaf.fingerprints)} ({use})"
        for index, leaf in (leaf_pins or {}).items()
    ]
    return [
        f"config ok: {cfg.source}",
        f"router: {router}",
        *node_ca,
        f"snmp: {snmp.bind}, root port {snmp.port_base}, {v2c}, {v3}",
        f"nodes: {reserved}, {len(cfg.overrides)} override(s)",
        f"collector: {cfg.collector.mode}, stale after {stale} s",
        f"state: {cfg.state_dir}",
        f"ports.json: {pins}",
        *(
            [f"onboard: {cfg.onboard.url} (onboard checks its token and ca_file)"]
            if cfg.onboard
            else []
        ),
        f"secret files: {len(cfg.secret_files())} ok (owner-only)",
    ]


def check_config(path: Path) -> int:
    """Validate the config, secret files, pins, and ports.json; change nothing."""
    try:
        cfg = load_config(path)
        load_secrets(cfg)
        pin = load_router_pin(cfg.asus.ca_file)
        node_ca = cfg.asus.node_ca_file
        node_pin = load_node_ca(node_ca) if node_ca is not None else None
        leaf_pins = {
            index: load_node_pin(override.ca_file, f"override[{index}].ca_file")
            for index, override in enumerate(cfg.overrides)
            if override.ca_file is not None
        }
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    try:
        ports = PortMap.load(
            cfg.ports_file,
            cfg.snmp.port_base,
            cfg.nodes.expected,
            root_ip=cfg.root_ip,
            read_only=True,
        )
    except PortMapError as exc:
        print(f"state error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    print("\n".join(describe(cfg, pin, ports, node_pin, leaf_pins)))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args, rest = parser.parse_known_args(argv)
    path = config_path(args)
    if args.command == "check-config":
        if rest:
            parser.error(f"unrecognized arguments: {' '.join(rest)}")
        return check_config(path or DEFAULT_CONFIG)
    handler = _load_handler(args.command)
    if handler is None:
        print(f"{args.command}: not implemented yet", file=sys.stderr)
        return EXIT_NOT_IMPLEMENTED
    if path is None and args.command not in CONFIG_OPTIONAL:
        path = DEFAULT_CONFIG
    cfg = None
    if path is not None:
        try:
            cfg = load_config(path)
        except ConfigError as exc:
            print(f"config error: {exc}", file=sys.stderr)
            return EXIT_CONFIG
    setup_logging(cfg.logging.level if cfg is not None else "INFO")
    return handler(cfg, rest)


if __name__ == "__main__":
    sys.exit(main())
