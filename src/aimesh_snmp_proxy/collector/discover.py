"""``discover``: list the router and its nodes read-only; fixtures; pin the router cert.

The listing shows the SNMP port, model, firmware, IP, MAC tail, online,
level, and backhaul per node: no client MACs and no secrets.
``--fixtures DIR`` runs one full poll and saves the key-allowlist-scrubbed
replies (H4). ``--pin-cert PATH`` fetches the router's certificate by TLS
handshake only, prints its SHA-256 fingerprint, and writes the PEM only
after ``--yes`` or a typed "yes" (H1). ``--pin-node-ca PATH`` does the same
for the CA that issued a node's certificate, the per_node trust anchor;
``--pin-cert PATH --node MAC|IP`` for one node's own certificate instead.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import ipaddress
import os
import re
import ssl
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any, TextIO

import aiohttp
from asusrouter.const import DEFAULT_PORT_HTTPS
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from aimesh_snmp_proxy.collector import statefile
from aimesh_snmp_proxy.collector.fixtures import FIXTURE_FILE, FixtureRecorder, scrub
from aimesh_snmp_proxy.collector.mapping import MeshNode
from aimesh_snmp_proxy.collector.service import Collector, Overrides
from aimesh_snmp_proxy.collector.session import (
    fetch_certificate,
    fetch_chain,
    fetch_router_ca_file,
    fingerprint_der,
)
from aimesh_snmp_proxy.config import (
    ConfigError,
    load_node_ca,
    load_node_pin,
    load_router_pin,
    load_secrets,
)
from aimesh_snmp_proxy.model import normalize_mac
from aimesh_snmp_proxy.ports import PortMap, PortMapError

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_CONFIG = 78  # sysexits EX_CONFIG, as in __main__
_PEM_BLOCK = re.compile(
    r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.DOTALL
)
_COLUMNS = (
    "role",
    "sys_name",
    "port",
    "model",
    "firmware",
    "ip",
    "mac_tail",
    "online",
    "level",
    "backhaul",
)


def _node_key(text: str) -> str:
    """``--node``: a normalized MAC or a canonical IPv4 address."""
    try:
        return str(ipaddress.IPv4Address(text))
    except ValueError:
        mac = normalize_mac(text)
        if mac is None:
            raise argparse.ArgumentTypeError(
                "expected a MAC or an IPv4 address"
            ) from None
        return mac


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aimesh-snmp-proxy discover",
        description="List the router and the AiMesh nodes it reports (read-only).",
    )
    parser.add_argument(
        "--fixtures",
        type=Path,
        metavar="DIR",
        help="also poll once and save scrubbed replies to DIR/fixture.json",
    )
    parser.add_argument(
        "--pin-cert",
        type=Path,
        metavar="PATH",
        help="fetch the router certificate, show its fingerprint, save it as the pin",
    )
    parser.add_argument(
        "--node",
        type=_node_key,
        metavar="MAC|IP",
        help="with --pin-cert: pin this AiMesh node's own certificate instead "
        "(ca_file in its [[override]]); a MAC costs one root login",
    )
    parser.add_argument(
        "--pin-node-ca",
        type=Path,
        metavar="PATH",
        help="fetch a node's certificate chain, show its issuing CA, save that CA "
        "as the node pin (asus.node_ca_file)",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="with --pin-cert or --pin-node-ca: save without asking",
    )
    return parser


def cli_discover(
    cfg: Any,
    argv: list[str],
    *,
    out: TextIO | None = None,
    err: TextIO | None = None,
    ask: Callable[[str], str] = input,
) -> int:
    """Entry point for ``aimesh-snmp-proxy discover``."""
    out = out or sys.stdout
    err = err or sys.stderr
    parser = _parser()
    args = parser.parse_args(argv)
    if args.node is not None and args.pin_cert is None:
        parser.error("--node needs --pin-cert")
    if args.node is not None:
        return asyncio.run(
            pin_node_cert(cfg, args.pin_cert, args.node, args.yes, out, err, ask)
        )
    if args.pin_cert is not None:
        return asyncio.run(pin_certificate(cfg, args.pin_cert, args.yes, out, err, ask))
    if args.pin_node_ca is not None:
        return asyncio.run(pin_node_ca(cfg, args.pin_node_ca, args.yes, out, err, ask))
    return asyncio.run(discover(cfg, args.fixtures, out, err))


# --- listing ----------------------------------------------------------------------


def _tail(mac: str | None) -> str:
    return mac[-8:] if mac else "-"


def _backhaul(node: MeshNode) -> str:
    bh = node.backhaul
    if bh is None:
        return "-"
    parts = [bh.medium or "unknown"]
    if bh.band:
        parts.append(bh.band)
    if bh.rssi_dbm is not None:
        parts.append(f"{bh.rssi_dbm} dBm")
    if bh.link_bps:
        parts.append(f"{bh.link_bps // 1_000_000} Mbit/s")
    if bh.parent_mac:
        parts.append(f"via {_tail(bh.parent_mac)}")
    return " ".join(parts)


def preview_ports(cfg: Any, nodes: dict[str, MeshNode], err: TextIO) -> dict[str, str]:
    """Each node's SNMP port as ``run`` gives it: pinned, else a preview.

    The map is read-only, so ``ports.json`` is never created or changed. Nodes
    go in ``run``'s order (the root, then override-pinned nodes, then by MAC):
    a pin can move the node holding its index. A second root gets no port.
    """
    try:
        ports = PortMap.load(
            cfg.ports_file,
            cfg.snmp.port_base,
            cfg.nodes.expected,
            root_ip=cfg.root_ip,
            read_only=True,
        )
    except (PortMapError, ValueError) as exc:
        print(f"discover: ports unavailable: {exc}", file=err)
        return {}

    def is_root(node: MeshNode) -> bool:
        return node.role == "router" or (
            cfg.root_ip is not None and node.ip == cfg.root_ip
        )

    def pin(node: MeshNode) -> int | None:
        override = cfg.override_for(node.mac, node.ip)
        return override.port if override is not None else None

    def order(mac: str) -> tuple[bool, bool, str]:  # ops.run.Engines._order
        return not is_root(nodes[mac]), pin(nodes[mac]) is None, mac

    shown: dict[str, str] = {}
    root_taken = False
    for mac in sorted(nodes, key=order):
        node = nodes[mac]
        try:
            if is_root(node):
                if root_taken:
                    print(
                        f"discover: {_tail(mac)} is a second root; run refuses it",
                        file=err,
                    )
                    continue
                root_taken = True
                port = ports.root_port
            else:
                port = ports.assign(mac, ip=node.ip, pin=pin(node))
        except (PortMapError, ValueError) as exc:
            print(f"discover: no port for {_tail(mac)}: {exc}", file=err)
            continue
        shown[mac] = str(port)
    return shown


def _rows(
    nodes: dict[str, MeshNode], names: dict[str, str], ports: dict[str, str]
) -> list[list[str]]:
    ordered = sorted(nodes.values(), key=lambda n: (n.role != "router", n.level, n.mac))
    return [
        [
            node.role,
            names.get(node.mac, "-"),
            ports.get(node.mac, "-"),
            node.model or "-",
            node.firmware or "-",
            node.ip or "-",
            _tail(node.mac),
            "yes" if node.online else "no",
            str(node.level),
            _backhaul(node),
        ]
        for node in ordered
    ]


def _table(rows: list[list[str]]) -> str:
    table = [list(_COLUMNS), *rows]
    widths = [max(len(row[i]) for row in table) for i in range(len(_COLUMNS) - 1)]
    lines = []
    for row in table:
        cells = [cell.ljust(width) for cell, width in zip(row, widths, strict=False)]
        lines.append("  ".join([*cells, row[-1]]))
    return "\n".join(lines)


async def discover(cfg: Any, fixtures: Path | None, out: TextIO, err: TextIO) -> int:
    recorder = FixtureRecorder() if fixtures is not None else None
    try:
        if cfg.asus.ca_file is None:
            raise ConfigError(
                "asus.ca_file: required; run discover --pin-cert PATH to create it"
            )
        secrets = load_secrets(cfg)
        pin = load_router_pin(cfg.asus.ca_file)
        collector = Collector.from_config(
            cfg, secrets, pin, middlewares=(recorder,) if recorder else ()
        )
    except ConfigError as exc:
        print(f"config error: {exc}", file=err)
        return EXIT_CONFIG
    try:
        if recorder is not None:
            await collector.poll_once()
        else:
            await collector.topology()
    finally:
        await collector.shutdown(persist=False)
    nodes = collector.nodes
    if not nodes:
        print(f"discover: {_no_nodes(collector, cfg.asus.host)}", file=err)
        return EXIT_FAILED
    print(
        _table(_rows(nodes, collector.names, preview_ports(cfg, nodes, err))), file=out
    )
    if recorder is not None and fixtures is not None:
        path = fixtures / FIXTURE_FILE
        statefile.write_json(path, scrub(recorder.entries))
        print(
            f"fixtures: {path} ({len(recorder.entries)} replies, key-allowlist "
            "scrubbed; review before sharing)",
            file=out,
        )
    return EXIT_OK


def _no_nodes(collector: Collector, host: str) -> str:
    guard = collector.root.guard
    why = guard.last_failure
    reason = f"{why.outcome} ({why.detail})" if why else f"login {guard.gate()}"
    return f"no AiMesh nodes read from {host}: {reason}"


# --- pinning ----------------------------------------------------------------------


def _write_pem(path: Path, pem: str) -> None:
    """Atomic 0644 write: the certificate is public, but must not be swapped."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as fh:
            fh.write(pem)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


async def pin_certificate(
    cfg: Any,
    path: Path,
    yes: bool,
    out: TextIO,
    err: TextIO,
    ask: Callable[[str], str],
) -> int:
    host = cfg.asus.host
    port = cfg.asus.port or DEFAULT_PORT_HTTPS
    try:
        der = await fetch_certificate(
            host, port, timeout_s=cfg.collector.request_timeout_s
        )
    except (OSError, TimeoutError, ssl.SSLError) as exc:
        print(
            f"pin-cert: cannot fetch the certificate from {host}:{port}: "
            f"{type(exc).__name__}",
            file=err,
        )
        return EXIT_FAILED
    presented = fingerprint_der(der)
    print(f"{host}:{port} presents certificate {presented}", file=out)
    return _save_pin(
        path,
        der,
        load=load_router_pin,
        hint="set [asus] ca_file to this path",
        yes=yes,
        out=out,
        ask=ask,
    )


async def pin_node_cert(
    cfg: Any,
    path: Path,
    node: str,
    yes: bool,
    out: TextIO,
    err: TextIO,
    ask: Callable[[str], str],
) -> int:
    """Pin one AiMesh node's own certificate (``ca_file`` in its ``[[override]]``).

    An IP costs a handshake only; a MAC costs one root login to read its IP.
    """
    host: str | None = node
    if normalize_mac(node) is not None:
        try:
            if cfg.asus.ca_file is None:
                raise ConfigError(
                    "asus.ca_file: required; run discover --pin-cert PATH to create it"
                )
            # Its own Overrides and no node CA: no pin file is read, not even PATH.
            collector = Collector.from_config(
                cfg,
                load_secrets(cfg),
                load_router_pin(cfg.asus.ca_file),
                overrides=Overrides(),
                node_pin=None,
            )
        except ConfigError as exc:
            print(f"config error: {exc}", file=err)
            return EXIT_CONFIG
        try:
            await collector.topology()
        finally:
            await collector.shutdown(persist=False)
        found = collector.nodes.get(node)
        if not collector.nodes:
            print(f"pin-cert: {_no_nodes(collector, cfg.asus.host)}", file=err)
            return EXIT_FAILED
        if found is None or found.ip is None:
            print(f"pin-cert: the root reports no node {node} with an IP", file=err)
            return EXIT_FAILED
        host = None if found.role == "router" else found.ip
    if host is None or host == cfg.root_ip:
        print(f"pin-cert: {node} is the root router; pin it without --node", file=err)
        return EXIT_FAILED
    port = cfg.asus.port or DEFAULT_PORT_HTTPS
    try:
        der = await fetch_certificate(
            host, port, timeout_s=cfg.collector.request_timeout_s
        )
    except (OSError, TimeoutError, ssl.SSLError) as exc:
        print(
            f"pin-cert: cannot fetch the certificate from {host}:{port}: "
            f"{type(exc).__name__}",
            file=err,
        )
        return EXIT_FAILED
    print(
        f"node {node} at {host}:{port} presents certificate {fingerprint_der(der)}",
        file=out,
    )
    return _save_pin(
        path,
        der,
        load=load_node_pin,
        hint=f"set ca_file to this path in the [[override]] for {node}",
        yes=yes,
        out=out,
        ask=ask,
    )


def _save_pin(
    path: Path,
    der: bytes,
    *,
    load: Callable[[Path], Any],
    hint: str,
    yes: bool,
    out: TextIO,
    ask: Callable[[str], str],
) -> int:
    """Compare with the current pin, then write it after ``--yes`` or a "yes"."""
    presented = fingerprint_der(der)
    if path.exists():
        try:
            current = load(path)
        except ConfigError:
            print(f"{path} holds no usable certificate; it would be replaced", file=out)
        else:
            if presented in current.fingerprints:
                print(f"already pinned: {path}", file=out)
                return EXIT_OK
            pinned = ", ".join(current.fingerprints)
            print(f"{path} pins a different certificate: {pinned}", file=out)
    print("Check the fingerprint on the router itself before you trust it.", file=out)
    if not yes:
        try:
            answer = ask("Type yes to pin this certificate: ")
        except EOFError:
            answer = ""
        if answer.strip().lower() != "yes":
            print("not pinned", file=out)
            return EXIT_FAILED
    _write_pem(path, ssl.DER_cert_to_PEM_cert(der))
    print(f"pinned: {path} ({hint})", file=out)
    return EXIT_OK


async def pin_node_ca(
    cfg: Any,
    path: Path,
    yes: bool,
    out: TextIO,
    err: TextIO,
    ask: Callable[[str], str],
) -> int:
    """Pin the CA that issued the AiMesh node certificates (``asus.node_ca_file``).

    The first answering ``nodes.expected`` IP gives its chain by handshake only;
    the pin is the chain's certificate that signed the node's own.
    """
    port = cfg.asus.port or DEFAULT_PORT_HTTPS
    hosts = tuple(cfg.nodes.expected)
    if not hosts:
        print("pin-node-ca: list the node IPs in nodes.expected first", file=err)
        return EXIT_CONFIG
    for host in hosts:
        try:
            chain = await fetch_chain(
                host, port, timeout_s=cfg.collector.request_timeout_s
            )
        except (OSError, TimeoutError, ssl.SSLError) as exc:
            print(f"pin-node-ca: {host}:{port}: {type(exc).__name__}", file=err)
            continue
        break
    else:
        print("pin-node-ca: no node answered; is a node online?", file=err)
        return EXIT_FAILED
    issuer = _issuing_ca(chain)
    if issuer is None:
        print(
            f"{host}:{port} sent no issuing CA with its certificate; trying the "
            "root's /cert.crt",
            file=out,
        )
        issuer, why = await _root_ca_file(cfg, chain[0])
        if issuer is None:
            print(
                f"pin-node-ca: {host}:{port} sent no issuing CA, and the root's "
                f"/cert.crt was not usable: {why}",
                file=err,
            )
            return EXIT_FAILED
    subject = x509.load_der_x509_certificate(issuer).subject.rfc4514_string()
    print(
        f"{host}:{port} presents a certificate issued by {subject} "
        f"{fingerprint_der(issuer)}",
        file=out,
    )
    if not _names_ip(chain[0], host):
        print(f"warning: the node certificate does not name {host}", file=out)
    return _save_pin(
        path,
        issuer,
        load=load_node_ca,
        hint="set [asus] node_ca_file to this path",
        yes=yes,
        out=out,
        ask=ask,
    )


async def _root_ca_file(cfg: Any, node_leaf: bytes) -> tuple[bytes | None, str]:
    """The root's own CA from /cert.crt, fetched over the router pin, no login.

    Taken only as one PEM CA certificate that issued both the pinned router
    certificate and the node's: the download alone proves nothing.
    """
    try:
        router_pin = load_router_pin(cfg.asus.ca_file)
    except ConfigError as exc:
        return None, f"pin the router first (discover --pin-cert): {exc}"
    port = cfg.asus.port or DEFAULT_PORT_HTTPS
    try:
        body = await fetch_router_ca_file(
            cfg.asus.host, port, router_pin, timeout_s=cfg.collector.request_timeout_s
        )
    except (
        OSError,
        TimeoutError,
        ssl.SSLError,
        aiohttp.ClientError,
        ValueError,
    ) as exc:
        return None, f"cannot fetch it: {str(exc) or type(exc).__name__}"
    return _verified_root_ca(body, router_pin, node_leaf)


def _verified_root_ca(
    body: bytes, router_pin: Any, node_leaf: bytes
) -> tuple[bytes | None, str]:
    try:
        text = body.decode("ascii")
    except UnicodeDecodeError:
        return None, "expected exactly one PEM certificate"
    if "PRIVATE KEY" in text:
        return None, "it holds a private key"
    blocks = _PEM_BLOCK.findall(text)
    if len(blocks) != 1:
        return None, f"expected exactly one PEM certificate, found {len(blocks)}"
    try:
        ca = x509.load_pem_x509_certificate(blocks[0].encode())
        constraints = ca.extensions.get_extension_for_class(x509.BasicConstraints)
        is_ca = constraints.value.ca
    except (ValueError, x509.ExtensionNotFound):
        is_ca = False
    if not is_ca:
        return None, "it is not a CA certificate (CA:TRUE)"
    router = x509.load_pem_x509_certificate(
        _PEM_BLOCK.findall(router_pin.pem)[0].encode()
    )
    for cert, what in (
        (router, "the pinned router certificate"),
        (x509.load_der_x509_certificate(node_leaf), "the node certificate"),
    ):
        try:
            cert.verify_directly_issued_by(ca)
        except (ValueError, TypeError, InvalidSignature):
            return None, f"it did not issue {what}"
    return ca.public_bytes(serialization.Encoding.DER), ""


def _issuing_ca(chain: list[bytes]) -> bytes | None:
    """The certificate in ``chain`` that signed the leaf, ``chain[0]``."""
    leaf = x509.load_der_x509_certificate(chain[0])
    for der in chain[1:]:
        try:
            leaf.verify_directly_issued_by(x509.load_der_x509_certificate(der))
        except (ValueError, TypeError, InvalidSignature):
            continue
        return der
    return None


def _names_ip(der: bytes, host: str) -> bool:
    try:
        names = x509.load_der_x509_certificate(der).extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        return ipaddress.ip_address(host) in names.value.get_values_for_type(
            x509.IPAddress
        )
    except (x509.ExtensionNotFound, ValueError):
        return False
