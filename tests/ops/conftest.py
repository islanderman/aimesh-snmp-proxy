"""Fixtures for the ops tests: a fake LibreNMS API v0, the mock ASUS router,
and NET-SNMP's ``snmpget`` against loopback engines.
"""

from __future__ import annotations

import asyncio
import datetime
import hashlib
import importlib.util
import ipaddress
import json
import os
import random
import shutil
import socket
import ssl
import sys
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from aimesh_snmp_proxy import logsafe

API = "/api/v0/devices"
Reply = tuple[int, dict[str, str], bytes]
_KEY_USAGES = (
    "digital_signature",
    "content_commitment",
    "key_encipherment",
    "data_encipherment",
    "key_agreement",
    "key_cert_sign",
    "crl_sign",
    "encipher_only",
    "decipher_only",
)


@dataclass(frozen=True)
class Seen:
    """One request as the fake server received it."""

    method: str
    path: str
    headers: dict[str, str]
    body: bytes

    def json(self) -> dict:
        return json.loads(self.body)


def json_reply(status: int, doc: object, **headers: str) -> Reply:
    return (
        status,
        {"Content-Type": "application/json", **headers},
        json.dumps(doc).encode(),
    )


class FakeLibreNMS:
    """The device routes onboard uses, with LibreNMS status codes and bodies.

    Devices carry ``community`` the way the API shows it to a token whose user
    may unmask secrets, so tests prove onboard never prints or stores it.
    ``routes`` overrides one ``(method, path)`` with a custom reply function.
    """

    reply = staticmethod(json_reply)

    def __init__(self, token: str, tls: ssl.SSLContext | None = None) -> None:
        self.token = token
        self.devices: dict[int, dict] = {}
        self.next_id = 500
        self.requests: list[Seen] = []
        self.routes: dict[tuple[str, str], Callable[[Seen], Reply | None]] = {}
        self.reject_checked_add = False
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _handler_for(self))
        if tls is not None:
            self.server.socket = tls.wrap_socket(self.server.socket, server_side=True)
        self.scheme = "https" if tls is not None else "http"
        self._thread = threading.Thread(
            target=self.server.serve_forever, args=(0.02,), daemon=True
        )
        self._thread.start()

    @property
    def url(self) -> str:
        return f"{self.scheme}://127.0.0.1:{self.server.server_address[1]}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def add_existing(self, hostname: str, **fields: object) -> int:
        device_id = self.next_id
        self.next_id += 1
        self.devices[device_id] = {
            "device_id": device_id,
            "hostname": hostname,
            **fields,
        }
        return device_id

    def load_recorded(self, path: Path) -> None:
        """Replace the devices with a recorded ``GET /api/v0/devices`` answer."""
        rows = json.loads(path.read_text())["devices"]
        self.devices = {row["device_id"]: row for row in rows}
        self.next_id = max(self.devices, default=499) + 1

    def find(self, key: str) -> dict | None:
        if key.isdigit():
            return self.devices.get(int(key))
        return next(
            (d for d in self.devices.values() if d["hostname"].lower() == key.lower()),
            None,
        )

    def calls(self) -> list[tuple[str, str]]:
        return [(seen.method, seen.path) for seen in self.requests]

    def handle(self, seen: Seen) -> Reply | None:
        if seen.headers.get("X-Auth-Token") != self.token:
            return json_reply(401, {"message": "Unauthenticated."})
        route = self.routes.get((seen.method, seen.path))
        if route is not None:
            return route(seen)
        if seen.method == "POST" and seen.path == API:
            return self._add(seen.json())
        if seen.method == "GET" and seen.path == API:
            return self._list()
        if seen.path.startswith(API + "/"):
            key = unquote(seen.path[len(API) + 1 :])
            if seen.method == "GET":
                return self._get(key)
            if seen.method == "DELETE":
                return self._delete(key)
        return json_reply(404, {"status": "error", "message": "no such route"})

    def _list(self) -> Reply:
        rows = sorted(self.devices.values(), key=lambda d: d["hostname"])
        return json_reply(200, {"status": "ok", "devices": rows, "count": len(rows)})

    def _get(self, key: str) -> Reply:
        device = self.find(key)
        if device is None:
            return json_reply(
                404, {"status": "error", "message": f"Device {key} does not exist"}
            )
        return json_reply(200, {"status": "ok", "devices": [device], "count": 1})

    def _add(self, data: dict) -> Reply:
        hostname = data["hostname"]
        if self.find(hostname) is not None:
            return json_reply(
                400,
                {"status": "error", "message": f"Hostname {hostname} already exists"},
            )
        if self.reject_checked_add and not data.get("force_add"):
            message = f"Cannot add {hostname}, already exists as librenms (127.0.0.1)"
            return json_reply(400, {"status": "error", "message": message})
        fields = {k: v for k, v in data.items() if k not in ("hostname", "force_add")}
        device_id = self.add_existing(hostname, **fields)
        message = f"Device {hostname} ({device_id}) has been added successfully"
        return json_reply(
            200,
            {"status": "ok", "message": message, "devices": [self.devices[device_id]]},
        )

    def _delete(self, key: str) -> Reply:
        device = self.find(key)
        if device is None:
            return json_reply(
                404, {"status": "error", "message": f"Device {key} not found"}
            )
        del self.devices[device["device_id"]]
        message = f"Removed device {device['hostname']}\n"
        return json_reply(
            200, {"status": "ok", "message": message, "devices": [device]}
        )


def _handler_for(fake: FakeLibreNMS) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def _serve(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            seen = Seen(
                self.command, self.path, dict(self.headers), self.rfile.read(length)
            )
            fake.requests.append(seen)
            reply = fake.handle(seen)
            if reply is None:  # a route returning None drops the connection
                self.close_connection = True
                return
            status, headers, body = reply
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_POST = do_DELETE = do_PATCH = _serve  # noqa: N815

        def log_message(self, format: str, *args: object) -> None:
            pass  # keep pytest output clean

    return Handler


@dataclass(frozen=True)
class ServerCert:
    cert_path: Path
    key_path: Path
    pem: str

    @property
    def fingerprint(self) -> str:
        """``SHA256:AA:BB:...``, the format onboard and check-config print."""
        digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(self.pem)).digest()
        return "SHA256:" + ":".join(f"{b:02X}" for b in digest)


def make_cert(
    directory: Path,
    name: str,
    *,
    common_name: str = "librenms.test",
    san_ip: str | None = "127.0.0.1",
    ca: bool = True,
    issuer: ServerCert | None = None,
    bare: bool = False,
) -> ServerCert:
    """A certificate, self-signed unless ``issuer`` signs it; the key is 0600.

    ``bare`` leaves out every extension, the SAN included.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    signer, signer_name = key, subject
    if issuer is not None:
        signer = serialization.load_pem_private_key(issuer.key_path.read_bytes(), None)
        signer_name = x509.load_pem_x509_certificate(issuer.pem.encode()).subject
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(signer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
    )
    extensions: list[tuple[x509.ExtensionType, bool]] = []
    if not bare:
        if san_ip is not None:
            ip = x509.IPAddress(ipaddress.IPv4Address(san_ip))
            extensions.append((x509.SubjectAlternativeName([ip]), False))
        extensions += [
            (x509.BasicConstraints(ca=ca, path_length=None), True),
            (x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False),
        ]
        if ca:
            usage = dict.fromkeys(_KEY_USAGES, False)
            usage.update(digital_signature=True, key_cert_sign=True, crl_sign=True)
            extensions.append((x509.KeyUsage(**usage), True))
        if issuer is not None:
            akid = x509.AuthorityKeyIdentifier.from_issuer_public_key(
                signer.public_key()
            )
            extensions.append((akid, False))
    for extension, critical in extensions:
        builder = builder.add_extension(extension, critical=critical)
    cert = builder.sign(signer, hashes.SHA256())
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    cert_path = directory / f"{name}.pem"
    key_path = directory / f"{name}.key"
    cert_path.write_text(pem)
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    cert_path.chmod(0o644)
    key_path.chmod(0o600)
    return ServerCert(cert_path, key_path, pem)


@pytest.fixture(scope="session")
def librenms_cert(tmp_path_factory) -> ServerCert:
    return make_cert(tmp_path_factory.mktemp("tls"), "librenms")


@pytest.fixture(scope="session")
def other_cert(tmp_path_factory) -> ServerCert:
    return make_cert(tmp_path_factory.mktemp("tls-other"), "other")


@pytest.fixture(scope="session", params=["extensions", "bare"])
def ip_cn_cert(request, tmp_path_factory) -> ServerCert:
    """Like the live LibreNMS certificate: self-signed, CN=127.0.0.1, no SAN."""
    return make_cert(
        tmp_path_factory.mktemp("tls-ip-cn"),
        "ip-cn",
        common_name="127.0.0.1",
        san_ip=None,
        bare=request.param == "bare",
    )


@pytest.fixture(scope="session")
def librenms_ca(tmp_path_factory) -> ServerCert:
    """A CA that signs ``ca_issued_cert``; trusted by a pin or by SSL_CERT_FILE."""
    return make_cert(
        tmp_path_factory.mktemp("tls-ca"), "ca", common_name="Test CA", san_ip=None
    )


@pytest.fixture(scope="session")
def ca_issued_cert(tmp_path_factory, librenms_ca) -> ServerCert:
    """A leaf for 127.0.0.1 (IP SAN) signed by ``librenms_ca``."""
    return make_cert(
        tmp_path_factory.mktemp("tls-leaf"), "leaf", ca=False, issuer=librenms_ca
    )


@pytest.fixture(autouse=True)
def fresh_registry(monkeypatch):
    """Each test starts with no registered secrets, as a fresh process would."""
    monkeypatch.setattr(logsafe, "_literals", logsafe._Literals())


@pytest.fixture
def make_fake(canaries) -> Iterator[Callable[..., FakeLibreNMS]]:
    """Start fake LibreNMS servers that accept the canary onboard token."""
    started: list[FakeLibreNMS] = []

    def _make(tls_cert: ServerCert | None = None) -> FakeLibreNMS:
        ctx = None
        if tls_cert is not None:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(tls_cert.cert_path, tls_cert.key_path)
        fake = FakeLibreNMS(canaries["onboard_token"], ctx)
        started.append(fake)
        return fake

    yield _make
    for fake in started:
        fake.close()


@pytest.fixture
def fake(make_fake) -> FakeLibreNMS:
    return make_fake()


# --- the collector tests' mock HTTPS router -------------------------------------


def _collector_fixtures():
    """Load tests/collector/conftest.py once; pytest only loads it for that folder."""
    path = Path(__file__).resolve().parent.parent / "collector" / "conftest.py"
    spec = importlib.util.spec_from_file_location("_ops_collector_fixtures", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look their module up here
    spec.loader.exec_module(module)
    return module


_collector = _collector_fixtures()
# Re-exported fixtures: the TLS mock router, and the logger cleanup it needs.
mock_router = _collector.mock_router
_restore_logging = _collector._restore_logging


# --- loopback helpers -----------------------------------------------------------

SNMPGET = shutil.which("snmpget")


def free_port_block(count: int) -> int:
    """The first of ``count`` consecutive UDP ports free on 127.0.0.1 right now.

    Probes 20000-60000: a valid ``snmp.port_base`` (at most 65280) below the
    ephemeral range, where the kernel hands out ports to other programs.
    """
    rng = random.SystemRandom()
    for _ in range(200):
        first = rng.randrange(20000, 60000 - count)
        socks = []
        try:
            for port in range(first, first + count):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                socks.append(sock)
                sock.bind(("127.0.0.1", port))
        except OSError:
            continue
        finally:
            for sock in socks:
                sock.close()
        return first
    raise RuntimeError("no free block of UDP ports on 127.0.0.1")


async def net_snmp_get(port: int, community: str, oid: str, home: Path) -> str | None:
    """``snmpget`` v2c, value only; None on a timeout or any error."""
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(home),
        "SNMPCONFPATH": str(home),
        "SNMP_PERSISTENT_DIR": str(home),
        "MIBS": "",
    }
    proc = await asyncio.create_subprocess_exec(
        SNMPGET,
        "-v2c",
        "-c",
        community,
        "-t",
        "0.3",
        "-r",
        "0",
        "-On",
        "-Oqv",
        f"127.0.0.1:{port}",
        oid,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )
    out, _ = await proc.communicate()
    return out.decode().strip().strip('"') if proc.returncode == 0 else None


@pytest.fixture
def port_block() -> Callable[[int], int]:
    return free_port_block


@pytest.fixture
def snmp_get(tmp_path: Path) -> Callable[..., object]:
    """``await snmp_get(port, community, oid)``; skips when snmpget is missing."""
    if SNMPGET is None:
        pytest.skip("NET-SNMP snmpget not installed")

    async def _get(port: int, community: str, oid: str) -> str | None:
        return await net_snmp_get(port, community, oid, tmp_path)

    return _get
