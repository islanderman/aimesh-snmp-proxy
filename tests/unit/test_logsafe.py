import io
import json
import logging
import sys
import warnings

import pytest

from aimesh_snmp_proxy import logsafe
from aimesh_snmp_proxy.logsafe import (
    MASK,
    JsonFormatter,
    RedactionFilter,
    SecretStr,
    redact,
    register_secret,
    setup_logging,
)

CANARY = "canary-Pa55w0rd-7f3a"
FINGERPRINT = "SHA256:" + ":".join(f"{i:02X}" for i in range(0xA0, 0xC0))


@pytest.fixture(autouse=True)
def fresh_registry(monkeypatch):
    monkeypatch.setattr(logsafe, "_literals", logsafe._Literals())


@pytest.fixture
def root_logger():
    root = logging.getLogger()
    pysnmp = logging.getLogger("pysnmp")
    saved = (root.level, list(root.handlers), [list(h.filters) for h in root.handlers])
    pysnmp_level = pysnmp.level
    yield root
    pysnmp.setLevel(pysnmp_level)
    for handler in list(root.handlers):
        if handler not in saved[1]:
            root.removeHandler(handler)
    for handler, filters in zip(saved[1], saved[2], strict=True):
        handler.filters[:] = filters
    root.setLevel(saved[0])
    logging.captureWarnings(False)


def make_record(msg, *args, exc_info=None, **extra):
    record = logging.LogRecord("test", logging.INFO, __file__, 1, msg, args, exc_info)
    for key, value in extra.items():
        setattr(record, key, value)
    return record


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("password=hunter2x", "hunter2x"),
        ("passwd: hunter2x", "hunter2x"),
        ('{"password": "hunter 2x"}', "hunter 2x"),
        ("{'password': 'hunter 2x'}", "hunter 2x"),
        ("{'password': b'hunter2x'}", "hunter2x"),
        ("Login(password='hunter2x', user='admin')", "hunter2x"),
        ("login_authorization=YWRtaW46aHVudGVyMng=", "YWRtaW46aHVudGVyMng"),
        ("asus_token=Zx81kQ09; clickedItem_tab=0", "Zx81kQ09"),
        ("sent Cookie: asus_token=Zx81kQ09; theme=dark", "Zx81kQ09"),
        ("Set-Cookie: asus_token=Zx81kQ09; HttpOnly", "Zx81kQ09"),
        ("Authorization: Basic YWRtaW46aHVudGVyMng=", "YWRtaW46aHVudGVyMng"),
        ("headers={'Authorization': 'Bearer eyJ0eXAi.eyJzdWIi.c2ln'}", "eyJ0eXAi"),
        ("auth with bearer eyJ0eXAi.eyJzdWIi.c2ln now", "eyJ0eXAi"),
        ("X-Auth-Token: c0ffee00c0ffee00", "c0ffee00c0ffee00"),
        ("GET /api/v0/devices?token=c0ffee00c0ffee00&x=1", "c0ffee00c0ffee00"),
        ("url https://admin:hunter2x@192.168.50.1:8443/login.cgi", "hunter2x"),
        ("usmUserAuthKeyLocalized=0x1122334455667788", "0x1122334455667788"),
        ("authKey: s3cr3t-auth", "s3cr3t-auth"),
        ("priv_key=s3cr3t-priv", "s3cr3t-priv"),
        ("community=publ1c-ro", "publ1c-ro"),
        ("api_key=k-123456", "k-123456"),
        ("client_secret = abc123xyz", "abc123xyz"),
        ("passphrase='two words'", "two words"),
    ],
)
def test_redact_masks_sensitive_values(text, secret):
    out = redact(text)
    assert secret not in out
    assert MASK in out


@pytest.mark.parametrize(
    "text",
    [
        "node aimesh-root online, 3 clients, 2 radios",
        "asus.password_file: file not found: /etc/aimesh/asus_password",
        "snmp.v3.auth_key_file=/run/credentials/x/snmp_auth_key",
        "state_dir=/var/lib/aimesh-snmp-proxy",
        "Basic auth is disabled",
        f"pin mismatch: expected {FINGERPRINT}",
        "uptime 12:34:56, fe80::1 reachable",
    ],
)
def test_redact_leaves_ordinary_text_alone(text):
    assert redact(text) == text


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("client aa:bb:cc:dd:ee:ff joined", "client aa:bb:cc:**:**:** joined"),
        ("client AA-BB-CC-DD-EE-FF left", "client AA-BB-CC-**-**-** left"),
        ("mac=00:00:5E:00:53:01.", "mac=00:00:5E:**:**:**."),
    ],
)
def test_redact_masks_device_part_of_mac_addresses(text, expected):
    assert redact(text) == expected


def test_redact_is_idempotent():
    text = "password=hunter2x Cookie: asus_token=abc123 aa:bb:cc:dd:ee:ff"
    once = redact(text)
    assert redact(once) == once


def test_registered_secret_is_masked_anywhere():
    register_secret(CANARY)
    assert redact(f"error near {CANARY}!") == f"error near {MASK}!"
    assert redact(f"x{CANARY}{CANARY}y") == f"x{MASK}{MASK}y"


def test_longer_registered_secret_wins_over_its_prefix():
    register_secret("abcd1234")
    register_secret("abcd1234-long")
    assert redact("v=abcd1234-long.") == f"v={MASK}."


def test_register_secret_ignores_empty_value():
    register_secret("")
    assert redact("plain text") == "plain text"


def test_secret_str_never_reveals_value():
    secret = SecretStr(CANARY)
    assert secret.get_secret_value() == CANARY
    for rendered in (
        repr(secret),
        str(secret),
        f"{secret}",
        f"{secret!r}",
        "%s" % secret,  # noqa: UP031 - logging formats args with %
    ):
        assert CANARY not in rendered
    assert repr(secret) == "SecretStr('***')"


def test_secret_str_registers_value_for_redaction():
    SecretStr(CANARY)
    assert CANARY not in redact(f"leaked {CANARY}")


def test_filter_masks_message_args_and_clears_them():
    register_secret(CANARY)
    record = make_record("login failed for pass %s on %s", CANARY, "192.168.50.1")
    assert RedactionFilter().filter(record) is True
    assert record.getMessage() == f"login failed for pass {MASK} on 192.168.50.1"
    assert record.args == ()


def test_filter_masks_sensitive_extras_recursively():
    record = make_record(
        "poll",
        password="hunter2x",
        host="192.168.50.1",
        detail={"asus_token": "tok-1", "items": ["password=abc12345", 3, None]},
        raw=b"asus_token=tok-2",
    )
    RedactionFilter().filter(record)
    assert record.password == MASK
    assert record.host == "192.168.50.1"
    assert record.detail == {
        "asus_token": MASK,
        "items": [f"password={MASK}", 3, None],
    }
    assert "tok-2" not in record.raw


def test_filter_masks_objects_by_their_text():
    class Leaky:
        def __str__(self):
            return f"Leaky(token={CANARY})"

    record = make_record("obj", thing=Leaky())
    RedactionFilter().filter(record)
    assert CANARY not in record.thing


def test_filter_survives_bad_format_args():
    record = make_record("two %s %s", "only-one")
    assert RedactionFilter().filter(record) is True
    assert "two %s %s" in record.getMessage()


def test_filter_masks_exception_text_and_drops_exc_info():
    register_secret(CANARY)
    try:
        raise RuntimeError(f"router said password={CANARY}")
    except RuntimeError:
        record = make_record("boom", exc_info=sys.exc_info())
    RedactionFilter().filter(record)
    assert record.exc_info is None
    assert "RuntimeError" in record.exc_text
    assert CANARY not in record.exc_text


def test_filter_masks_cached_exception_and_stack_text():
    register_secret(CANARY)
    record = make_record("boom")
    record.exc_text = f"Traceback: {CANARY}"
    record.stack_info = f"Stack: {CANARY}"
    RedactionFilter().filter(record)
    assert CANARY not in record.exc_text
    assert CANARY not in record.stack_info


def test_json_formatter_alone_still_redacts():
    register_secret(CANARY)
    line = JsonFormatter().format(make_record("pass %s", CANARY, token="tok-3"))
    entry = json.loads(line)
    assert entry["msg"] == f"pass {MASK}"
    assert entry["token"] == MASK
    assert entry["level"] == "INFO"
    assert entry["logger"] == "test"
    assert entry["ts"].endswith("Z")


def test_setup_logging_emits_redacted_json_lines(root_logger):
    stream = io.StringIO()
    setup_logging("DEBUG", stream=stream)
    register_secret(CANARY)
    log = logging.getLogger("asusrouter.connection")
    log.debug("payload login_authorization=%s", "YWRtaW46cGFzcw==")
    log.info("node up", extra={"node": "aimesh-root", "asus_token": "tok-4"})
    try:
        secret_local = CANARY
        raise ValueError("login rejected for " + secret_local)
    except ValueError:
        log.exception("poll failed")
    output = stream.getvalue()
    assert CANARY not in output
    assert "YWRtaW46cGFzcw" not in output
    assert "tok-4" not in output
    entries = [json.loads(line) for line in output.splitlines()]
    assert [e["level"] for e in entries] == ["DEBUG", "INFO", "ERROR"]
    assert entries[1]["node"] == "aimesh-root"
    assert entries[1]["asus_token"] == MASK
    assert "ValueError" in entries[2]["exc"]


def test_setup_logging_masks_warnings(root_logger):
    stream = io.StringIO()
    setup_logging("INFO", stream=stream)
    register_secret(CANARY)
    with warnings.catch_warnings():
        warnings.simplefilter("always")
        warnings.warn(f"leaky {CANARY}", UserWarning, stacklevel=1)
    assert "leaky" in stream.getvalue()
    assert CANARY not in stream.getvalue()


def test_setup_logging_replaces_its_own_handler(root_logger):
    first = setup_logging("INFO", stream=io.StringIO())
    second = setup_logging("WARNING", stream=io.StringIO())
    assert first not in root_logger.handlers
    assert second in root_logger.handlers
    assert root_logger.level == logging.WARNING


def test_setup_logging_adds_filter_to_existing_root_handlers(root_logger):
    other = logging.StreamHandler(io.StringIO())
    root_logger.addHandler(other)
    try:
        setup_logging("INFO", stream=io.StringIO())
        assert any(isinstance(f, RedactionFilter) for f in other.filters)
        setup_logging("INFO", stream=io.StringIO())
        assert sum(isinstance(f, RedactionFilter) for f in other.filters) == 1
    finally:
        root_logger.removeHandler(other)


def test_setup_logging_keeps_pysnmp_debug_off(root_logger):
    setup_logging("DEBUG", stream=io.StringIO())
    assert not logging.getLogger("pysnmp").isEnabledFor(logging.DEBUG)


@pytest.mark.parametrize("level", ["UNSAFE", "TRACE", "5", ""])
def test_setup_logging_rejects_unknown_levels(level, root_logger):
    with pytest.raises(ValueError, match="log level must be one of"):
        setup_logging(level, stream=io.StringIO())


def test_setup_logging_accepts_lowercase_level(root_logger):
    setup_logging("debug", stream=io.StringIO())
    assert root_logger.level == logging.DEBUG


def test_json_output_includes_redacted_stack(root_logger):
    stream = io.StringIO()
    setup_logging("INFO", stream=stream)
    logging.getLogger("t").info("where", stack_info=True)
    entry = json.loads(stream.getvalue())
    assert entry["stack"].startswith("Stack (most recent call last)")


# --- H3/H4: router secrets, asusrouter Sensitive wrappers, canaries -----------


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("wl0_wpa_psk=Wifi-Key-77", "Wifi-Key-77"),
        ('{"wl1.1_wpa_psk": "Guest Key 88"}', "Guest Key 88"),
        ("wgs_psk: c2VjcmV0LXdn", "c2VjcmV0LXdn"),
        ("wgc1_psk=c2VjcmV0LXdn", "c2VjcmV0LXdn"),
        ("ap0_security=<3>psk2>aes>Sdn-Key-99", "Sdn-Key-99"),
        ("vpn_serverx_clientlist=<alice>Vpn-Pass-1<bob>Vpn-Pass-2", "Vpn-Pass"),
        ("vpnc_clientlist=<work>1>0>bob>Vpn-Pass-3", "Vpn-Pass-3"),
        ("private_key = wG-Priv-Key-4", "wG-Priv-Key-4"),
        ("http_passwd=Admin-Pass-5", "Admin-Pass-5"),
        ("ddns_passwd_x=Ddns-Pass-6", "Ddns-Pass-6"),
        ("secret_code=1234-5678", "1234-5678"),
        ("wl0_key1=0123456789", "0123456789"),
    ],
)
def test_redact_masks_router_secret_keys(text, secret):
    out = redact(text)
    assert secret not in out
    assert MASK in out


def test_asusrouter_sensitive_wrappers_are_masked_in_args_and_extras():
    from asusrouter.tools.identifiers.password import Password
    from asusrouter.tools.security.sensitive import Sensitive

    raw = Sensitive("raw-payload-canary")
    record = make_record(
        "payload %s nested %s",
        raw,
        {"items": [Sensitive("nested-canary")], "n": 1},
        reply=Sensitive("extra-canary"),
        deep={"password": Password("pw-canary"), "list": [Sensitive("deep-canary")]},
    )
    RedactionFilter().filter(record)
    rendered = record.getMessage() + repr(record.reply) + repr(record.deep)
    for canary in ("raw-payload", "nested-canary", "extra-canary", "deep-canary"):
        assert canary not in rendered
    assert "pw-canary" not in rendered
    assert (
        record.getMessage() == f"payload {MASK} nested {{'items': ['{MASK}'], 'n': 1}}"
    )


def test_sensitive_wrapper_as_message_and_mapping_args():
    from asusrouter.tools.security.sensitive import Sensitive

    record = make_record(Sensitive("msg-canary"))
    RedactionFilter().filter(record)
    assert record.getMessage() == MASK
    record = logging.LogRecord(
        "t", logging.INFO, __file__, 1, "%(v)s", ({"v": Sensitive("map-canary")},), None
    )
    RedactionFilter().filter(record)
    assert record.getMessage() == MASK


def test_plain_containers_in_args_are_left_intact():
    from collections import namedtuple

    Point = namedtuple("Point", "x y")
    record = make_record("p %s", Point(1, 2))
    RedactionFilter().filter(record)
    assert record.getMessage() == "p Point(x=1, y=2)"


def test_canary_secrets_never_reach_the_log_output(root_logger):
    from asusrouter.tools.security.sensitive import Sensitive

    stream = io.StringIO()
    setup_logging("DEBUG", stream=stream)
    password = SecretStr("canary-admin-Pw-1")
    community = SecretStr("canary-community-2")
    log = logging.getLogger("asusrouter.connection")
    log.debug("POST login.cgi login_authorization=%s", "Y2FuYXJ5LWJsb2I=")
    log.debug("headers %s", {"Authorization": "Basic Y2FuYXJ5LWJhc2lj", "x": "1"})
    log.debug("Set-Cookie: asus_token=canary-token-3; HttpOnly")
    log.debug("reply %s", Sensitive({"wl0_wpa_psk": "canary-psk-4"}))
    log.debug("nvram wl1_wpa_psk=canary-psk-5 vpn_serverx_clientlist=<a>canary-vpn-6")
    log.info("login as %s with %s", "admin", password)
    log.info("community %r", community)
    log.warning("poll", extra={"asus_token": "canary-token-7", "psk": "canary-psk-8"})
    try:
        raise ConnectionError(
            f"router rejected {password.get_secret_value()} "
            "X-Auth-Token: canary-token-9 private_key=canary-wg-10"
        )
    except ConnectionError:
        log.exception("login failed for %s", community.get_secret_value())
    output = stream.getvalue()
    canaries = [
        "canary-admin-Pw-1",
        "canary-community-2",
        "canary-token-3",
        "canary-psk-4",
        "canary-psk-5",
        "canary-vpn-6",
        "canary-token-7",
        "canary-psk-8",
        "canary-token-9",
        "canary-wg-10",
        "Y2FuYXJ5",
    ]
    assert [c for c in canaries if c in output] == []
    assert len(output.splitlines()) == 9
    assert "ConnectionError" in output


def test_containers_too_deep_to_inspect_fail_closed():
    from asusrouter.tools.security.sensitive import Sensitive

    deep = [Sensitive("deep-raw-canary")]
    for _ in range(12):
        deep = [deep]
    record = make_record("deep %s", deep, nested=deep)
    RedactionFilter().filter(record)
    assert "deep-raw-canary" not in record.getMessage()
    assert "deep-raw-canary" not in repr(record.nested)
    assert MASK in record.getMessage()
