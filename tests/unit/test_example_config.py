from pathlib import Path

import pytest

from aimesh_snmp_proxy import logsafe
from aimesh_snmp_proxy.config import load_config, load_router_pin, load_secrets

EXAMPLE = Path(__file__).resolve().parents[2] / "config.example.toml"
OPTIONAL_LINES = (
    "node_ca_file = ",
    "[snmp.v3]",
    "user = ",
    "auth = ",
    "auth_key_file = ",
    "priv = ",
    "priv_key_file = ",
    "[onboard]",
    "url = ",
    "token_file = ",
    "ca_file = ",
    "hostname = ",
    "[[override]]",
    "match = ",
    "sys_name = ",
    "login = ",
)


@pytest.fixture(autouse=True)
def fresh_registry(monkeypatch):
    monkeypatch.setattr(logsafe, "_literals", logsafe._Literals())


def test_example_config_validates_with_its_secret_files(
    tmp_path, write_file, router_cert, canaries
):
    for name in ("asus_password", "snmp_community"):
        write_file(f"creds/{name}", canaries[name])
    write_file("creds/asus_router.pem", router_cert.cert_pem, 0o644)
    cfg = load_config(EXAMPLE, env={"CREDENTIALS_DIRECTORY": str(tmp_path / "creds")})
    assert cfg.state_dir == Path("/var/lib/aimesh-snmp-proxy")
    assert cfg.asus.port == 8443
    assert cfg.snmp.port_base == 16101
    assert cfg.nodes.expected == tuple(f"192.168.50.{n}" for n in range(101, 111))
    assert cfg.overrides == ()  # a seeded instance config must not inherit one
    assert cfg.asus.node_ca_file is None
    secrets = load_secrets(cfg)
    assert secrets.snmp_community.get_secret_value() == canaries["snmp_community"]
    assert load_router_pin(cfg.asus.ca_file).fingerprints == (router_cert.fingerprint,)


def test_example_optional_sections_validate_once_uncommented(tmp_path):
    text = EXAMPLE.read_text()
    for line in OPTIONAL_LINES:
        assert f"# {line}" in text
        text = text.replace(f"# {line}", line)
    path = tmp_path / "config.toml"
    path.write_text(text)
    cfg = load_config(path, env={})
    assert (cfg.snmp.v3.user, cfg.snmp.v3.auth) == ("librenms", "SHA-256")
    assert cfg.onboard.url == "https://192.168.50.10"
    assert cfg.onboard.token_file == tmp_path / "librenms_token"
    assert cfg.onboard.ca_file == tmp_path / "librenms.pem"
    assert cfg.onboard.hostname == "sysname"
    assert cfg.asus.node_ca_file == tmp_path / "asus_node_ca.pem"
    assert [(o.match, o.sys_name, o.login) for o in cfg.overrides] == [
        ("192.168.50.101", "aimesh-hall", False)
    ]
