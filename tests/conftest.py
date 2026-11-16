"""Shared fixtures for the aimesh_snmp_proxy test suite."""

from __future__ import annotations

import copy
import datetime
import ipaddress
import json
import os
import ssl
import types
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

CANARIES = {
    "asus_password": "canary-router-Pa55-1",
    "snmp_auth_key": "canary-auth-key-22",
    "snmp_priv_key": "canary-priv-key-33",
    "snmp_community": "canary-community-44",
    "onboard_token": "canary-onboard-token-55",
}

BASE_CONFIG = {
    "asus": {
        "host": "192.168.50.1",
        "username": "admin",
        "password_file": "asus_password",
        "ca_file": "router.pem",
    },
    "nodes": {"expected": "192.168.50.101-110"},
    "snmp": {"community_file": "snmp_community"},
}

V3_TABLE = {
    "user": "librenms",
    "auth_key_file": "snmp_auth_key",
    "priv_key_file": "snmp_priv_key",
}


@dataclass(frozen=True)
class CertPair:
    cert_pem: str
    key_pem: str
    fingerprint: str


def _self_signed(common_name: str) -> CertPair:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    digest = cert.fingerprint(hashes.SHA256())
    return CertPair(
        cert.public_bytes(serialization.Encoding.PEM).decode(),
        key_pem,
        "SHA256:" + ":".join(f"{b:02X}" for b in digest),
    )


@pytest.fixture(scope="session")
def router_cert() -> CertPair:
    """Self-signed stand-in for the router's exported HTTPS certificate."""
    return _self_signed("router.asus.com")


@pytest.fixture(scope="session")
def rogue_cert() -> CertPair:
    """A different self-signed certificate, as a spoofed router would present."""
    return _self_signed("router.asus.com")


def _certificate(
    common_name: str,
    *,
    ca: bool,
    issuer: CertPair | None = None,
    san_ip: str | None = None,
) -> CertPair:
    """A CA or a leaf; an issued leaf's ``cert_pem`` carries the chain, CA last."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    signer, issuer_name = key, subject
    if issuer is not None:
        signer = serialization.load_pem_private_key(issuer.key_pem.encode(), None)
        issuer_name = x509.load_pem_x509_certificate(issuer.cert_pem.encode()).subject
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if ca:
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
    if issuer is not None:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()),
            critical=False,
        )
    if san_ip is not None:
        ip = x509.IPAddress(ipaddress.IPv4Address(san_ip))
        builder = builder.add_extension(
            x509.SubjectAlternativeName([ip]), critical=False
        )
    cert = builder.sign(signer, hashes.SHA256())
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    digest = cert.fingerprint(hashes.SHA256())
    fingerprint = "SHA256:" + ":".join(f"{b:02X}" for b in digest)
    chain = pem + (issuer.cert_pem if issuer is not None else "")
    return CertPair(chain, key_pem, fingerprint)


@pytest.fixture(scope="session")
def node_ca() -> CertPair:
    """Like the root router's own CA, which issues the AiMesh node certs."""
    return _certificate("AiMesh Root CA", ca=True)


@pytest.fixture(scope="session")
def node_leaf(node_ca) -> CertPair:
    """A node certificate issued by ``node_ca`` whose SAN is the node IP."""
    return _certificate("GT-AXE11000", ca=False, issuer=node_ca, san_ip="127.0.0.1")


@pytest.fixture(scope="session")
def foreign_leaf() -> CertPair:
    """A certificate for the node IP, issued by some other CA."""
    other = _certificate("Other CA", ca=True)
    return _certificate("GT-AXE11000", ca=False, issuer=other, san_ip="127.0.0.1")


@pytest.fixture(scope="session")
def nameless_leaf(node_ca) -> CertPair:
    """Issued by ``node_ca`` but naming no IP: the hostname check must fail."""
    return _certificate("GT-AXE11000", ca=False, issuer=node_ca)


@pytest.fixture(scope="session")
def root_leaf(node_ca) -> CertPair:
    """The root router's own certificate, issued by the same CA as the nodes'."""
    return _certificate("RT-AX88U", ca=False, issuer=node_ca, san_ip="127.0.0.1")


@pytest.fixture(scope="session")
def old_node_cert() -> CertPair:
    """Like the certs of some older node models: self-signed, CA:TRUE, no IP SAN."""
    return _certificate("www.asusrouter.com", ca=True)


@pytest.fixture(scope="session")
def old_node_child(old_node_cert) -> CertPair:
    """A certificate the old node cert signed: it chains to that pin, yet is not it."""
    return _certificate("impostor", ca=False, issuer=old_node_cert, san_ip="127.0.0.1")


@pytest.fixture
def leaf_only() -> Callable[[CertPair], CertPair]:
    """The pair without its chain, as the live routers serve: the leaf alone."""
    end = "-----END CERTIFICATE-----\n"

    def _strip(pair: CertPair) -> CertPair:
        return CertPair(
            pair.cert_pem.split(end)[0] + end, pair.key_pem, pair.fingerprint
        )

    return _strip


@pytest.fixture
def canaries() -> dict[str, str]:
    return dict(CANARIES)


@pytest.fixture
def lax_tls(monkeypatch: pytest.MonkeyPatch) -> Callable[..., list[ssl.SSLContext]]:
    """Start new TLS contexts of the given modules at MINIMUM_SUPPORTED.

    Many Linux builds default to that; returns the contexts created meanwhile.
    """
    created: list[ssl.SSLContext] = []

    def lax(make: Callable[..., ssl.SSLContext]) -> Callable[..., ssl.SSLContext]:
        def factory(*args: object, **kwargs: object) -> ssl.SSLContext:
            ctx = make(*args, **kwargs)
            ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
            created.append(ctx)
            return ctx

        return factory

    def patch(*modules: object) -> list[ssl.SSLContext]:
        fake = types.SimpleNamespace(**vars(ssl))
        fake.SSLContext = lax(ssl.SSLContext)
        fake.create_default_context = lax(ssl.create_default_context)
        for module in modules:
            monkeypatch.setattr(module, "ssl", fake)
        return created

    return patch


@pytest.fixture
def write_file(tmp_path: Path) -> Callable[..., Path]:
    """Write ``content`` under tmp_path with an exact mode; return the path."""

    def _write(name: str, content: str | bytes, mode: int = 0o600) -> Path:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        data = content.encode() if isinstance(content, str) else content
        path.write_bytes(data)
        os.chmod(path, mode)
        return path

    return _write


def _toml_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return repr(value)
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, list):
        return "[" + ", ".join(_toml_value(v) for v in value) + "]"
    raise TypeError(f"cannot render {type(value).__name__}")


def _is_table_array(value: object) -> bool:
    return (
        isinstance(value, list)
        and bool(value)
        and all(isinstance(v, dict) for v in value)
    )


def render_toml(doc: dict, prefix: str = "") -> str:
    """Render nested dicts as TOML tables and lists of dicts as arrays of tables."""
    lines = [
        f"{key} = {_toml_value(value)}"
        for key, value in doc.items()
        if not isinstance(value, dict) and not _is_table_array(value)
    ]
    for key, value in doc.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict):
            lines += ["", f"[{name}]", render_toml(value, f"{name}.")]
        elif _is_table_array(value):
            for item in value:
                lines += ["", f"[[{name}]]", render_toml(item, f"{name}.")]
    return "\n".join(lines)


@pytest.fixture
def base_config(tmp_path: Path) -> dict:
    """A fresh, valid config document; tests mutate it before writing."""
    doc = {"state_dir": str(tmp_path / "state"), **copy.deepcopy(BASE_CONFIG)}
    return doc


@pytest.fixture
def v3_table() -> dict:
    """An [snmp.v3] table whose key files make_config writes."""
    return dict(V3_TABLE)


@pytest.fixture
def make_config(
    tmp_path: Path, write_file: Callable[..., Path], router_cert: CertPair
) -> Callable[..., Path]:
    """Write secret files, the router cert, and a config.toml; return its path."""

    def _make(doc: dict | None = None, *, text: str | None = None) -> Path:
        for name, value in CANARIES.items():
            if not (tmp_path / name).exists():
                write_file(name, value + "\n")
        if not (tmp_path / "router.pem").exists():
            write_file("router.pem", router_cert.cert_pem, 0o644)
        body = text if text is not None else render_toml(doc or {})
        return write_file("config.toml", body, 0o644)

    return _make
