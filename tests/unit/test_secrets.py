import base64
import contextlib
import logging
import os
import socket
import ssl
import struct
import threading
import types

import pytest

from aimesh_snmp_proxy import __main__ as cli
from aimesh_snmp_proxy import config, logsafe
from aimesh_snmp_proxy.config import (
    MAX_SECRET_BYTES,
    ConfigError,
    load_config,
    load_node_ca,
    load_node_pin,
    load_onboard_token,
    load_router_pin,
    load_secrets,
    read_secret,
)
from aimesh_snmp_proxy.ops import onboard as onboard_mod
from aimesh_snmp_proxy.ops import run as run_mod
from aimesh_snmp_proxy.ops.onboard import cli_onboard

CANARY = "canary-secret-9b1d"
EUID = os.geteuid()
ANY = 0xFFFFFFFF
USER_OBJ, USER, GROUP_OBJ, GROUP, MASK, OTHER = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20


@pytest.fixture(autouse=True)
def fresh_registry(monkeypatch):
    monkeypatch.setattr(logsafe, "_literals", logsafe._Literals())


@pytest.fixture
def cfg(make_config, base_config):
    return load_config(make_config(base_config), env={})


def acl(*entries):
    body = b"".join(struct.pack("<HHI", tag, perm, qid) for tag, perm, qid in entries)
    return b"\x02\x00\x00\x00" + body


def systemd_acl(*extra):
    """What systemd LoadCredential= sets: root 0400 plus read for the service."""
    return acl(
        (USER_OBJ, 4, ANY),
        (USER, 4, EUID),
        (GROUP_OBJ, 0, ANY),
        *extra,
        (MASK, 4, ANY),
        (OTHER, 0, ANY),
    )


# --- secrets -----------------------------------------------------------------


def test_load_secrets_returns_masked_values(cfg, canaries):
    secrets = load_secrets(cfg)
    assert secrets.asus_password.get_secret_value() == canaries["asus_password"]
    assert secrets.snmp_community.get_secret_value() == canaries["snmp_community"]
    assert (secrets.snmp_auth_key, secrets.snmp_priv_key) == (None, None)
    rendered = repr(secrets) + str(secrets)
    for value in canaries.values():
        assert value not in rendered


def test_load_secrets_registers_values_and_login_blob(cfg, canaries):
    load_secrets(cfg)
    blob = base64.b64encode(f"admin:{canaries['asus_password']}".encode()).decode()
    text = f"{canaries['asus_password']} {canaries['snmp_community']} {blob}"
    assert logsafe.redact(text) == "*** *** ***"


def test_optional_secrets_are_read_when_configured(
    make_config, base_config, v3_table, canaries
):
    base_config["snmp"]["v3"] = v3_table
    secrets = load_secrets(load_config(make_config(base_config), env={}))
    assert secrets.snmp_auth_key.get_secret_value() == canaries["snmp_auth_key"]
    assert secrets.snmp_priv_key.get_secret_value() == canaries["snmp_priv_key"]


def test_daemon_secrets_never_touch_the_onboard_token(make_config, base_config):
    base_config["onboard"] = {"token_file": "missing_token"}
    secrets = load_secrets(load_config(make_config(base_config), env={}))
    assert not hasattr(secrets, "onboard_token")


def test_load_onboard_token(make_config, base_config, canaries):
    base_config["onboard"] = {"token_file": "onboard_token"}
    cfg = load_config(make_config(base_config), env={})
    token = load_onboard_token(cfg)
    assert token.get_secret_value() == canaries["onboard_token"]
    assert canaries["onboard_token"] not in logsafe.redact(canaries["onboard_token"])


@pytest.mark.parametrize(
    ("onboard", "message"),
    [
        (None, r"onboard: add an \[onboard\] section with token_file"),
        ({"url": "https://192.168.50.10"}, r"onboard.token_file: required"),
        ({"token_file": "missing_token"}, r"onboard.token_file: file not found"),
    ],
)
def test_load_onboard_token_errors(make_config, base_config, onboard, message):
    if onboard is not None:
        base_config["onboard"] = onboard
    cfg = load_config(make_config(base_config), env={})
    with pytest.raises(ConfigError, match=message):
        load_onboard_token(cfg)


def test_v3_only_config_has_no_community(make_config, base_config, v3_table):
    del base_config["snmp"]["community_file"]
    base_config["snmp"]["v3"] = v3_table
    secrets = load_secrets(load_config(make_config(base_config), env={}))
    assert secrets.snmp_community is None


def test_read_secret_strips_trailing_newlines(write_file):
    path = write_file("s", "value-1\r\n\n")
    assert read_secret(path, "x").get_secret_value() == "value-1"


def test_trailing_spaces_are_part_of_the_secret(write_file):
    path = write_file("s", "value-1  \n")
    assert read_secret(path, "x").get_secret_value() == "value-1  "


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o620, 0o602, 0o610, 0o601])
def test_loose_permissions_are_refused(write_file, mode):
    path = write_file("s", CANARY, mode)
    with pytest.raises(ConfigError, match=r"is accessible to group or others") as exc:
        read_secret(path, "asus.password_file")
    message = str(exc.value)
    assert CANARY not in message
    assert f"mode {mode:04o}" in message
    assert message.startswith(f"asus.password_file: the file in {path.parent} ")
    assert str(path) not in message


@pytest.mark.parametrize("mode", [0o600, 0o400])
def test_owner_only_permissions_pass(write_file, mode):
    path = write_file("s", CANARY, mode)
    assert read_secret(path, "x").get_secret_value() == CANARY


def test_startup_refuses_world_readable_password_file(cfg, tmp_path):
    os.chmod(tmp_path / "asus_password", 0o644)
    with pytest.raises(ConfigError, match=r"asus.password_file: .* run chmod 600"):
        load_secrets(cfg)


@pytest.mark.skipif(EUID == 0, reason="root may read any owner's file")
def test_file_owned_by_another_user_is_refused(write_file, monkeypatch):
    path = write_file("s", CANARY)
    owner = os.stat(path).st_uid
    monkeypatch.setattr(os, "geteuid", lambda: owner + 1)
    with pytest.raises(ConfigError, match=rf"is owned by uid {owner}; it must belong"):
        read_secret(path, "x")


def test_missing_secret_file(tmp_path):
    with pytest.raises(ConfigError, match=rf"x: file not found in {tmp_path}; "):
        read_secret(tmp_path / "nope", "x")


def test_directory_is_not_a_secret_file(tmp_path):
    with pytest.raises(ConfigError, match=r"x: not a regular file"):
        read_secret(tmp_path, "x")


def test_fifo_is_refused_without_blocking(tmp_path):
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(ConfigError, match=r"not a regular file"):
        read_secret(fifo, "x")


def test_symlink_to_owner_only_file_is_followed(write_file, tmp_path):
    target = write_file("real", "value-12345678")
    link = tmp_path / "link"
    link.symlink_to(target)
    assert read_secret(link, "x").get_secret_value() == "value-12345678"


@pytest.mark.skipif(EUID == 0, reason="root ignores mode 000")
def test_unreadable_file(write_file):
    path = write_file("s", CANARY, 0o000)
    with pytest.raises(ConfigError, match=r"x: cannot open .*: Permission denied"):
        read_secret(path, "x")


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("", "is empty"),
        ("\n\r\n", "is empty"),
        (f"{CANARY}\nsecond line", "must hold one line"),
        (f"{CANARY}\0tail", "must hold one line"),
        (b"\xff\xfe" + CANARY.encode(), "is not UTF-8 text"),
    ],
)
def test_malformed_secret_content_is_never_echoed(write_file, content, message):
    path = write_file("s", content)
    with pytest.raises(ConfigError, match=message) as exc:
        read_secret(path, "x")
    assert CANARY not in str(exc.value)


def test_oversized_secret_is_refused(write_file):
    path = write_file("s", "x" * (MAX_SECRET_BYTES + 1))
    with pytest.raises(ConfigError, match=rf"larger than {MAX_SECRET_BYTES} bytes"):
        read_secret(path, "x")


def test_secret_at_size_limit_is_accepted(write_file):
    path = write_file("s", "y" * MAX_SECRET_BYTES)
    assert len(read_secret(path, "x").get_secret_value()) == MAX_SECRET_BYTES


@pytest.mark.parametrize("key", ["snmp_auth_key", "snmp_priv_key"])
def test_short_usm_key_is_refused_without_echo(
    make_config, base_config, v3_table, write_file, key
):
    write_file(key, "short7!")
    base_config["snmp"]["v3"] = v3_table
    cfg = load_config(make_config(base_config), env={})
    with pytest.raises(ConfigError, match=r"at least 8 characters") as exc:
        load_secrets(cfg)
    assert "short7!" not in str(exc.value)


# --- a secret typed in as a file name never shows ---------------------------------

NAME_CANARY = "Canary-Pa55w0rd-typed-as-a-file-name"
# Each secret file key: (its config table, the example file name the hint gives).
SECRET_KEYS = {
    "asus.password_file": (("asus",), "asus_password"),
    "snmp.community_file": (("snmp",), "snmp_community"),
    "snmp.v3.auth_key_file": (("snmp", "v3"), "snmp_auth_key"),
    "snmp.v3.priv_key_file": (("snmp", "v3"), "snmp_priv_key"),
    "onboard.token_file": (("onboard",), "librenms_token"),
}
DAEMON_KEYS = [key for key in SECRET_KEYS if key != "onboard.token_file"]


@pytest.fixture(params=["config_dir", "credentials_dir"])
def secret_dir(request, tmp_path, canaries, monkeypatch):
    """Where relative ``*_file`` values resolve, as (directory, env); os.environ
    matches env, for commands that read it themselves."""
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    if request.param == "config_dir":
        return tmp_path, {}
    creds = tmp_path / "credentials"
    creds.mkdir()
    for name, value in canaries.items():
        (creds / name).write_text(value + "\n")
        (creds / name).chmod(0o600)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds))
    return creds, {"CREDENTIALS_DIRECTORY": str(creds)}


def misnamed(make_config, base_config, v3_table, key, value=NAME_CANARY):
    """A config file whose ``key`` holds ``value``, with every secret key in use."""
    base_config["snmp"]["v3"] = v3_table
    base_config["onboard"] = {"token_file": "onboard_token"}
    table = base_config
    for name in SECRET_KEYS[key][0]:
        table = table[name]
    table[key.rsplit(".", 1)[1]] = value
    return make_config(base_config)


def load_key(cfg, key):
    return load_onboard_token(cfg) if key == "onboard.token_file" else load_secrets(cfg)


@pytest.mark.parametrize("kind", ["missing", "unreadable", "loose_mode"])
@pytest.mark.parametrize("key", SECRET_KEYS)
def test_a_secret_file_error_names_the_key_and_directory_never_the_file(
    make_config, base_config, v3_table, secret_dir, key, kind
):
    if kind == "unreadable" and EUID == 0:
        pytest.skip("root reads mode 000 files")
    folder, env = secret_dir
    path = misnamed(make_config, base_config, v3_table, key)
    if kind != "missing":
        (folder / NAME_CANARY).write_text("a-value-12345678\n")
        (folder / NAME_CANARY).chmod(0o000 if kind == "unreadable" else 0o644)
    with pytest.raises(ConfigError) as caught:
        load_key(load_config(path, env=env), key)
    text = str(caught.value)
    assert NAME_CANARY not in text
    assert text.startswith(f"{key}: ")
    assert f" in {folder}" in text
    example = SECRET_KEYS[key][1]
    hint = f"the value must name a file such as {example}, not the secret itself"
    assert text.endswith(hint)


@pytest.mark.parametrize(
    ("value", "parts"),
    [
        ("Canary7k3J/Pq9+Wz==", ("Canary7k3J", "Pq9+Wz")),
        ("/CanaryAbs9q/Zx7Y", ("CanaryAbs9q", "Zx7Y")),
    ],
    ids=["slash", "absolute"],
)
def test_no_part_of_a_secret_typed_as_a_path_shows(
    make_config, base_config, v3_table, secret_dir, value, parts
):
    _, env = secret_dir
    path = misnamed(make_config, base_config, v3_table, "asus.password_file", value)
    with pytest.raises(
        ConfigError, match=r"password_file: file not found in "
    ) as caught:
        load_secrets(load_config(path, env=env))
    for part in parts:
        assert part not in str(caught.value)


@pytest.mark.parametrize("key", DAEMON_KEYS)
def test_check_config_never_prints_a_secret_typed_as_a_file_name(
    make_config, base_config, v3_table, secret_dir, key, capsys
):
    folder, _ = secret_dir
    path = misnamed(make_config, base_config, v3_table, key)
    assert cli.main(["--config", str(path), "check-config"]) == cli.EXIT_CONFIG
    out, err = capsys.readouterr()
    assert NAME_CANARY not in out + err
    assert err.startswith(f"config error: {key}: file not found in {folder}; ")


@pytest.mark.parametrize("key", ["onboard.token_file", "snmp.community_file"])
def test_onboard_never_prints_a_secret_typed_as_a_file_name(
    make_config, base_config, v3_table, secret_dir, key, capsys
):
    _, env = secret_dir
    cfg = load_config(misnamed(make_config, base_config, v3_table, key), env=env)
    assert cli_onboard(cfg, []) == onboard_mod.EXIT_CONFIG
    out, err = capsys.readouterr()
    assert NAME_CANARY not in out + err
    assert f"config error: {key}: file not found in " in err


@pytest.mark.parametrize("key", DAEMON_KEYS)
def test_run_never_logs_a_secret_typed_as_a_file_name(
    make_config, base_config, v3_table, secret_dir, key, caplog, monkeypatch
):
    _, env = secret_dir
    cfg = load_config(misnamed(make_config, base_config, v3_table, key), env=env)
    monkeypatch.setattr(run_mod, "assert_unprivileged_user", lambda: None)
    caplog.set_level(logging.DEBUG)
    assert run_mod.cli_run(cfg, []) == run_mod.EXIT_CONFIG
    assert f"config error: {key}: file not found in " in caplog.text
    assert NAME_CANARY not in caplog.text


# --- POSIX ACLs (systemd credentials) -----------------------------------------


def test_systemd_credential_acl_is_accepted(write_file, monkeypatch):
    path = write_file("s", "cred-value-1", 0o440)
    monkeypatch.setattr(config, "_posix_acl", lambda fd: systemd_acl())
    assert read_secret(path, "x").get_secret_value() == "cred-value-1"


@pytest.mark.parametrize(
    "raw",
    [
        systemd_acl((GROUP, 4, 1234)),
        acl((USER_OBJ, 6, ANY), (USER, 4, EUID + 1), (MASK, 4, ANY), (OTHER, 0, ANY)),
        acl((USER_OBJ, 6, ANY), (GROUP_OBJ, 4, ANY), (MASK, 4, ANY), (OTHER, 0, ANY)),
        acl((USER_OBJ, 6, ANY), (GROUP_OBJ, 0, ANY), (MASK, 0, ANY), (OTHER, 4, ANY)),
        b"\x01\x00\x00\x00",
        b"\x02\x00\x00\x00\x01",
        b"",
    ],
    ids=[
        "named-group",
        "other-user",
        "owning-group",
        "others",
        "version",
        "short",
        "empty",
    ],
)
def test_acl_granting_anyone_else_is_refused(write_file, monkeypatch, raw):
    path = write_file("s", CANARY, 0o440)
    monkeypatch.setattr(config, "_posix_acl", lambda fd: raw)
    with pytest.raises(ConfigError, match=r"accessible to group or others"):
        read_secret(path, "x")


def test_acl_mask_limits_named_entries(write_file, monkeypatch):
    path = write_file("s", "masked-1", 0o400)
    raw = acl((USER_OBJ, 4, ANY), (GROUP_OBJ, 0, ANY), (GROUP, 4, 99), (MASK, 0, ANY))
    monkeypatch.setattr(config, "_posix_acl", lambda fd: raw + acl((OTHER, 0, ANY))[4:])
    assert read_secret(path, "x").get_secret_value() == "masked-1"


def test_posix_acl_is_none_without_acl(write_file):
    fd = os.open(write_file("s", "v"), os.O_RDONLY)
    try:
        assert config._posix_acl(fd) is None
    finally:
        os.close(fd)


def test_posix_acl_reads_the_xattr_when_supported(monkeypatch):
    calls = []

    def fake_getxattr(fd, name):
        calls.append((fd, name))
        return b"raw-acl"

    monkeypatch.setattr(os, "getxattr", fake_getxattr, raising=False)
    assert config._posix_acl(7) == b"raw-acl"
    assert calls == [(7, "system.posix_acl_access")]

    def no_acl(fd, name):
        raise OSError(61, "No data available")

    monkeypatch.setattr(os, "getxattr", no_acl, raising=False)
    assert config._posix_acl(7) is None


# --- router certificate pin -----------------------------------------------------


def handshake(client_ctx, server_cert, tmp_path, hostname="192.168.50.1"):
    """Run a TLS handshake in memory against a server holding ``server_cert``."""
    cert, key = tmp_path / "srv.pem", tmp_path / "srv.key"
    cert.write_text(server_cert.cert_pem)
    key.write_text(server_cert.key_pem)
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(cert, key)
    c_in, c_out, s_in, s_out = (ssl.MemoryBIO() for _ in range(4))
    client = client_ctx.wrap_bio(c_in, c_out, server_hostname=hostname)
    server = server_ctx.wrap_bio(s_in, s_out, server_side=True)
    for _ in range(10):
        finished = 0
        for side in (client, server):
            try:
                side.do_handshake()
                finished += 1
            except ssl.SSLWantReadError:
                pass
        s_in.write(c_out.read())
        c_in.write(s_out.read())
        if finished == 2:
            return
    raise AssertionError("handshake did not finish")


def test_router_pin_fingerprint_and_context(cfg, router_cert):
    pin = load_router_pin(cfg.asus.ca_file)
    assert pin.fingerprints == (router_cert.fingerprint,)
    ctx = pin.ssl_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is False
    assert len(ctx.get_ca_certs()) == 1
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_router_context_sets_tls_1_2_whatever_the_platform_default(cfg, monkeypatch):
    # Many Linux builds leave minimum_version at MINIMUM_SUPPORTED by default.
    def lax_default(protocol):
        ctx = ssl.SSLContext(protocol)
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        return ctx

    linux_like = types.SimpleNamespace(**{**vars(ssl), "SSLContext": lax_default})
    monkeypatch.setattr(config, "ssl", linux_like)
    ctx = load_router_pin(cfg.asus.ca_file).ssl_context()
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2


def test_pinned_context_accepts_the_router(cfg, router_cert, tmp_path):
    handshake(load_router_pin(cfg.asus.ca_file).ssl_context(), router_cert, tmp_path)


def test_pinned_context_rejects_a_spoofed_router(cfg, rogue_cert, tmp_path):
    ctx = load_router_pin(cfg.asus.ca_file).ssl_context()
    with pytest.raises(ssl.SSLCertVerificationError):
        handshake(ctx, rogue_cert, tmp_path)


def test_pin_with_two_certificates(write_file, router_cert, rogue_cert):
    path = write_file("chain.pem", router_cert.cert_pem + rogue_cert.cert_pem, 0o644)
    pin = load_router_pin(path)
    assert pin.fingerprints == (router_cert.fingerprint, rogue_cert.fingerprint)
    assert len(pin.ssl_context().get_ca_certs()) == 2


def test_group_writable_cert_is_refused(write_file, router_cert):
    path = write_file("router.pem", router_cert.cert_pem, 0o664)
    with pytest.raises(ConfigError, match=r"is writable by group or others"):
        load_router_pin(path)


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("not a certificate", "holds no PEM certificate"),
        (b"\xff\xfe", "is not a PEM certificate"),
        (
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
            "is not a valid certificate",
        ),
    ],
)
def test_invalid_cert_files(write_file, content, message):
    path = write_file("router.pem", content, 0o644)
    with pytest.raises(ConfigError, match=rf"asus.ca_file: .* {message}"):
        load_router_pin(path)


def test_cert_file_with_private_key_is_refused(write_file, router_cert):
    path = write_file("router.pem", router_cert.cert_pem + router_cert.key_pem, 0o600)
    with pytest.raises(ConfigError, match=r"contains a private key"):
        load_router_pin(path)


def test_missing_cert_file(tmp_path):
    with pytest.raises(ConfigError, match=r"asus.ca_file: file not found"):
        load_router_pin(tmp_path / "router.pem")


# --- node CA pin (asus.node_ca_file) ------------------------------------------------


def test_the_node_ca_pin_checks_the_chain_and_the_node_ip(
    write_file, node_ca, tmp_path
):
    pin = load_node_ca(write_file("node_ca.pem", node_ca.cert_pem, 0o644))
    assert pin.check_hostname is True
    ctx = pin.ssl_context()
    assert (ctx.verify_mode, ctx.check_hostname) == (ssl.CERT_REQUIRED, True)
    assert len(ctx.get_ca_certs()) == 1  # the CA alone, no system store


def test_a_node_certificate_from_the_pinned_ca_naming_the_ip_passes(
    write_file, node_ca, node_leaf, tmp_path
):
    ctx = load_node_ca(write_file("node_ca.pem", node_ca.cert_pem, 0o644)).ssl_context()
    handshake(ctx, node_leaf, tmp_path, hostname="127.0.0.1")


@pytest.mark.parametrize(
    ("leaf", "hostname", "why"),
    [
        ("foreign_leaf", "127.0.0.1", "certificate verify failed"),
        ("nameless_leaf", "127.0.0.1", "mismatch"),
        ("node_leaf", "127.0.0.2", "mismatch"),
    ],
)
def test_a_node_certificate_is_refused_off_the_ca_or_the_ip(
    write_file, node_ca, tmp_path, request, leaf, hostname, why
):
    ctx = load_node_ca(write_file("node_ca.pem", node_ca.cert_pem, 0o644)).ssl_context()
    with pytest.raises(ssl.SSLCertVerificationError, match=why):
        handshake(ctx, request.getfixturevalue(leaf), tmp_path, hostname=hostname)


def test_a_leaf_in_node_ca_file_is_refused(write_file, node_leaf):
    leaf_only = node_leaf.cert_pem.split("-----END CERTIFICATE-----")[0]
    path = write_file("node_ca.pem", leaf_only + "-----END CERTIFICATE-----\n", 0o644)
    with pytest.raises(ConfigError, match=r"asus.node_ca_file: .* is not a CA"):
        load_node_ca(path)


def test_the_router_pin_keeps_skipping_the_hostname(cfg):
    pin = load_router_pin(cfg.asus.ca_file)
    assert pin.check_hostname is False
    assert pin.ssl_context().check_hostname is False


# --- a node's own leaf pin ([[override]] ca_file) ------------------------------------


def test_a_node_leaf_pin_accepts_that_exact_certificate_by_any_name(
    write_file, old_node_cert, tmp_path
):
    pin = load_node_pin(write_file("node-104.pem", old_node_cert.cert_pem, 0o644))
    assert (pin.check_hostname, pin.exact) == (False, True)
    handshake(pin.ssl_context(), old_node_cert, tmp_path, hostname="192.168.50.104")


@pytest.mark.parametrize("presented", ["old_node_child", "router_cert"])
def test_a_node_leaf_pin_refuses_any_other_certificate(
    write_file, old_node_cert, tmp_path, request, presented
):
    # old_node_child chains to the pinned CA:TRUE cert: only the exact match stops it.
    pin = load_node_pin(write_file("node-104.pem", old_node_cert.cert_pem, 0o644))
    with pytest.raises(ssl.SSLCertVerificationError):
        handshake(pin.ssl_context(), request.getfixturevalue(presented), tmp_path)


def test_a_node_leaf_pin_holds_on_blocking_sockets(
    write_file, old_node_cert, old_node_child
):
    pin = load_node_pin(write_file("node-104.pem", old_node_cert.cert_pem, 0o644))
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(
        write_file("srv.pem", old_node_child.cert_pem),
        write_file("srv.key", old_node_child.key_pem),
    )
    near, far = socket.socketpair()
    far.settimeout(5)

    def serve() -> None:
        with far, contextlib.suppress(OSError):
            server_ctx.wrap_socket(far, server_side=True).close()

    server = threading.Thread(target=serve)
    server.start()
    with near, pytest.raises(ssl.SSLCertVerificationError) as refused:
        pin.ssl_context().wrap_socket(near, server_hostname="192.168.50.104")
    server.join(5)
    assert refused.value.verify_message == "certificate is not the pinned leaf"
    assert str(refused.value).endswith(
        f"{old_node_child.fingerprint} is not the pinned leaf"
    )


def test_a_node_leaf_pin_names_its_key_in_errors(tmp_path):
    with pytest.raises(ConfigError, match=r"override\[2\].ca_file: file not found"):
        load_node_pin(tmp_path / "node-104.pem", "override[2].ca_file")


# --- service account ------------------------------------------------------------


def test_unprivileged_user_passes():
    config.assert_unprivileged_user(forbidden_names=("nobody-here",))


@pytest.mark.parametrize(("uid", "euid"), [(0, 0), (0, 1000), (1000, 0)])
def test_root_is_refused(monkeypatch, uid, euid):
    monkeypatch.setattr(config.os, "getuid", lambda: uid)
    monkeypatch.setattr(config.os, "geteuid", lambda: euid)
    with pytest.raises(ConfigError, match=r"refusing to run as root \(uid 0\)"):
        config.assert_unprivileged_user()


@pytest.mark.parametrize("names", [("librenms",), ["librenms", "www-data"]])
def test_forbidden_account_is_refused(monkeypatch, names):
    monkeypatch.setattr(config.os, "getuid", lambda: 4242)
    monkeypatch.setattr(config.os, "geteuid", lambda: 4242)
    monkeypatch.setattr(
        config.pwd, "getpwuid", lambda uid: types.SimpleNamespace(pw_name="librenms")
    )
    with pytest.raises(ConfigError, match=r"refusing to run as user 'librenms'"):
        config.assert_unprivileged_user(names)


def test_default_forbidden_names_include_librenms(monkeypatch):
    monkeypatch.setattr(config.os, "geteuid", lambda: 4242)
    monkeypatch.setattr(config.os, "getuid", lambda: 4242)
    monkeypatch.setattr(
        config.pwd, "getpwuid", lambda uid: types.SimpleNamespace(pw_name="librenms")
    )
    with pytest.raises(ConfigError, match="librenms"):
        config.assert_unprivileged_user()


def test_uid_without_a_passwd_entry_is_allowed(monkeypatch):
    monkeypatch.setattr(config.os, "geteuid", lambda: 61234)
    monkeypatch.setattr(config.os, "getuid", lambda: 61234)

    def missing(uid):
        raise KeyError(uid)

    monkeypatch.setattr(config.pwd, "getpwuid", missing)
    config.assert_unprivileged_user()
