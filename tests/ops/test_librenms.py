import json
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from aimesh_snmp_proxy import config
from aimesh_snmp_proxy.config import ConfigError, RouterPin
from aimesh_snmp_proxy.logsafe import SecretStr
from aimesh_snmp_proxy.ops import librenms
from aimesh_snmp_proxy.ops.librenms import (
    ApiError,
    AuthError,
    Device,
    LibreNMSClient,
    TransportError,
    parse_base_url,
)

API = "/api/v0/devices"
# GET /api/v0/devices in the shape LibreNMS 26.11 serves it (Resources/Device.php).
RECORDED = Path(__file__).resolve().parents[1] / "fixtures" / "librenms_devices.json"


@pytest.fixture
def token(canaries):
    return SecretStr(canaries["onboard_token"])


@pytest.fixture
def community(canaries):
    return SecretStr(canaries["snmp_community"])


@pytest.fixture
def client(fake, token, community):
    return LibreNMSClient(fake.url, token, allow_http=True, secrets=(community,))


def test_get_device_sends_the_token_only_in_x_auth_token(fake, client, canaries):
    device_id = fake.add_existing("aimesh-000001", community="x")
    assert client.get_device("aimesh-000001") == Device(device_id, "aimesh-000001")
    (seen,) = fake.requests
    assert (seen.method, seen.path) == ("GET", f"{API}/aimesh-000001")
    assert seen.headers["X-Auth-Token"] == canaries["onboard_token"]
    assert seen.headers["Accept"] == "application/json"
    assert "Authorization" not in seen.headers
    assert canaries["onboard_token"] not in seen.path


def test_get_device_returns_none_for_a_librenms_404(client):
    assert client.get_device("aimesh-000001") is None


def test_hostnames_are_quoted_into_one_path_segment(fake, client):
    client.get_device("a/b?c")
    assert fake.requests[0].path == f"{API}/a%2Fb%3Fc"


def test_a_404_that_is_not_librenms_json_is_a_transport_error(fake, client):
    fake.routes["GET", f"{API}/x"] = lambda seen: (404, {}, b"<html>nginx</html>")
    with pytest.raises(TransportError, match="not a LibreNMS API answer"):
        client.get_device("x")


def test_add_device_posts_json_and_returns_the_new_device(fake, client):
    body = {"hostname": "aimesh-000001", "port": 16102, "snmpver": "v2c"}
    assert client.add_device(body) == Device(500, "aimesh-000001", port=16102)
    (seen,) = fake.requests
    assert (seen.method, seen.path) == ("POST", API)
    assert seen.headers["Content-Type"] == "application/json"
    assert seen.json() == body


def test_device_ids_given_as_strings_are_accepted(fake, client):
    fake.routes["GET", f"{API}/x"] = lambda seen: fake.reply(
        200, {"status": "ok", "devices": [{"device_id": "57", "hostname": "x"}]}
    )
    assert client.get_device("x") == Device(57, "x")


@pytest.mark.parametrize(
    "doc",
    [
        {"status": "ok"},
        {"status": "ok", "devices": []},
        {"status": "ok", "devices": [{"hostname": "x"}]},
        {"status": "ok", "devices": [{"device_id": True, "hostname": "x"}]},
        {"status": "ok", "devices": [{"device_id": 0, "hostname": "x"}]},
        {"status": "ok", "devices": [{"device_id": 5, "hostname": 7}]},
        [1, 2],
    ],
)
def test_an_unexpected_device_shape_is_an_api_error(fake, client, doc):
    fake.routes["GET", f"{API}/x"] = lambda seen: fake.reply(200, doc)
    with pytest.raises(ApiError, match="unexpected answer"):
        client.get_device("x")


def test_api_errors_carry_the_scrubbed_server_message(fake, client, canaries):
    community, token = canaries["snmp_community"], canaries["onboard_token"]
    leak = f"no reply with community {community} for {token}"
    fake.routes["POST", API] = lambda seen: fake.reply(
        400, {"status": "error", "message": leak + "\x1b[31m"}
    )
    with pytest.raises(ApiError) as caught:
        client.add_device({"hostname": "x"})
    text = str(caught.value)
    assert caught.value.status == 400
    assert text.startswith("HTTP 400: no reply with community *** for ***")
    assert "\x1b" not in text
    for value in canaries.values():
        assert value not in text


def test_validation_messages_given_as_objects_are_shown(fake, client):
    fake.routes["POST", API] = lambda seen: fake.reply(
        422, {"status": "error", "message": {"port": ["The port must be an integer."]}}
    )
    with pytest.raises(ApiError, match=r"HTTP 422: .*port must be an integer"):
        client.add_device({"hostname": "x"})


def test_long_server_messages_are_truncated(fake, client):
    fake.routes["POST", API] = lambda seen: fake.reply(500, {"message": "x" * 5000})
    with pytest.raises(ApiError) as caught:
        client.add_device({"hostname": "x"})
    assert len(str(caught.value)) < 300


@pytest.mark.parametrize("status", [401, 403])
def test_401_and_403_raise_auth_error_after_one_request(fake, client, status):
    fake.routes["GET", f"{API}/x"] = lambda seen: fake.reply(
        status, {"status": "error", "message": "Insufficient permissions"}
    )
    with pytest.raises(AuthError) as caught:
        client.get_device("x")
    assert caught.value.status == status
    assert len(fake.requests) == 1


def test_a_wrong_token_is_rejected(fake, community):
    client = LibreNMSClient(fake.url, SecretStr("wrong-token-1234"), allow_http=True)
    with pytest.raises(AuthError, match="HTTP 401"):
        client.get_device("x")


def test_delete_device_reports_whether_it_was_there(fake, client):
    fake.add_existing("aimesh-000001")
    assert client.delete_device("aimesh-000001") is True
    assert client.delete_device("aimesh-000001") is False
    assert fake.calls() == [("DELETE", f"{API}/aimesh-000001")] * 2


def test_list_devices_reads_every_device_with_its_snmp_endpoint(fake, client, canaries):
    fake.load_recorded(RECORDED)
    devices = client.list_devices()
    assert [(d.device_id, d.hostname, d.overwrite_ip, d.port) for d in devices] == [
        (11, "192.168.50.1", "127.0.0.1", 16101),
        (1, "192.168.50.10", None, 161),
        (12, "192.168.50.101", "127.0.0.1", 16102),
        (14, "192.168.50.109", "127.0.0.1", 16201),
        (3, "192.168.50.21", None, 161),
        (2, "192.168.50.254", None, 161),
        (13, "aimesh-00000b", "127.0.0.1", 16103),
    ]
    (seen,) = fake.requests
    assert (seen.method, seen.path) == ("GET", API)
    assert seen.headers["X-Auth-Token"] == canaries["onboard_token"]


def test_list_devices_of_an_empty_librenms_is_an_empty_list(client):
    assert client.list_devices() == []


def test_list_devices_takes_a_port_given_as_a_digit_string(fake, client):
    fake.add_existing("a", overwrite_ip="127.0.0.1", port="16102")
    fake.add_existing("b", overwrite_ip=None, port=None)
    fake.add_existing("c", overwrite_ip=7, port=True)
    ends = [(d.hostname, d.overwrite_ip, d.port) for d in client.list_devices()]
    assert ends == [("a", "127.0.0.1", 16102), ("b", None, None), ("c", None, None)]


@pytest.mark.parametrize(
    "doc",
    [
        {"status": "ok"},
        {"status": "ok", "devices": "x"},
        {"status": "ok", "devices": [{"hostname": "x"}]},
        {"status": "ok", "devices": [{"device_id": 5, "hostname": 7}]},
        {"status": "ok", "devices": [{"device_id": 5, "hostname": "x"}, 3]},
        [1, 2],
    ],
)
def test_an_unexpected_device_list_is_an_api_error(fake, client, doc):
    fake.routes["GET", API] = lambda seen: fake.reply(200, doc)
    with pytest.raises(ApiError, match="unexpected answer"):
        client.list_devices()


@pytest.mark.parametrize("status", [401, 403])
def test_a_refused_device_list_raises_auth_error(fake, client, status):
    fake.routes["GET", API] = lambda seen: fake.reply(status, {"message": "no"})
    with pytest.raises(AuthError):
        client.list_devices()


def test_a_device_list_may_exceed_the_single_device_limit(fake, client, monkeypatch):
    monkeypatch.setattr("aimesh_snmp_proxy.ops.librenms.MAX_BODY_BYTES", 64)
    fake.load_recorded(RECORDED)
    assert len(client.list_devices()) == 7
    monkeypatch.setattr("aimesh_snmp_proxy.ops.librenms.MAX_LIST_BYTES", 64)
    with pytest.raises(TransportError, match="larger than 64 bytes"):
        client.list_devices()


def test_a_device_is_read_and_deleted_by_its_id(fake, client):
    fake.add_existing("renamed.example", overwrite_ip="127.0.0.1", port=16102)  # 500
    assert client.get_device_by_id(500) == Device(
        500, "renamed.example", "127.0.0.1", 16102
    )
    assert client.delete_device_by_id(500) is True
    assert client.get_device_by_id(500) is None
    assert client.delete_device_by_id(500) is False
    assert fake.calls() == [
        ("GET", f"{API}/500"),
        ("DELETE", f"{API}/500"),
        ("GET", f"{API}/500"),
        ("DELETE", f"{API}/500"),
    ]


def test_a_non_json_success_is_a_transport_error(fake, client):
    fake.routes["GET", f"{API}/x"] = lambda seen: (200, {}, b"<html>login</html>")
    with pytest.raises(TransportError, match="not JSON"):
        client.get_device("x")


def test_an_oversized_answer_is_refused(fake, client, monkeypatch):
    monkeypatch.setattr("aimesh_snmp_proxy.ops.librenms.MAX_BODY_BYTES", 64)
    fake.routes["GET", f"{API}/x"] = lambda seen: fake.reply(
        200, {"status": "ok", "pad": "x" * 200}
    )
    with pytest.raises(TransportError, match="larger than"):
        client.get_device("x")


# --- base URL policy -----------------------------------------------------------


def test_http_is_refused_without_the_opt_in(fake, token):
    with pytest.raises(ConfigError, match="--allow-http"):
        LibreNMSClient(fake.url, token)
    assert fake.requests == []


@pytest.mark.parametrize(
    ("url", "base", "origin"),
    [
        ("https://192.168.50.10", "https://192.168.50.10", "https://192.168.50.10:443"),
        (
            "https://LibreNMS.example.com:8443/",
            "https://LibreNMS.example.com:8443",
            "https://librenms.example.com:8443",
        ),
        (
            "http://127.0.0.1/librenms/",
            "http://127.0.0.1/librenms",
            "http://127.0.0.1:80",
        ),
    ],
)
def test_parse_base_url_normalizes(url, base, origin):
    assert parse_base_url(url, allow_http=True) == (base, origin)


@pytest.mark.parametrize(
    "url",
    [
        "ftp://192.168.50.10",
        "https://",
        "https://192.168.50.10/?x=1",
        "https://192.168.50.10/#top",
        "https://user:pw@192.168.50.10",
        "https://192.168.50.10:99999",
    ],
)
def test_parse_base_url_rejects(url):
    with pytest.raises(ConfigError, match=r"\[onboard\] url"):
        parse_base_url(url, allow_http=True)


# --- redirects -----------------------------------------------------------------


def test_same_origin_redirects_are_followed_for_get(fake, client):
    fake.add_existing("new")
    fake.routes["GET", f"{API}/old"] = lambda seen: (
        302,
        {"Location": f"{API}/new"},
        b"",
    )
    assert client.get_device("old").hostname == "new"
    assert fake.calls() == [("GET", f"{API}/old"), ("GET", f"{API}/new")]


def test_cross_origin_redirects_are_refused(make_fake, fake, client):
    other = make_fake()
    target = f"{other.url}{API}/x"
    fake.routes["GET", f"{API}/x"] = lambda seen: (302, {"Location": target}, b"")
    with pytest.raises(TransportError, match="redirect"):
        client.get_device("x")
    assert other.requests == []


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_redirects_on_post_are_refused(fake, client, status):
    fake.routes["POST", API] = lambda seen: (status, {"Location": API + "/x"}, b"")
    with pytest.raises(TransportError, match="redirect"):
        client.add_device({"hostname": "x"})
    assert len(fake.requests) == 1


def test_redirect_loops_stop(fake, client):
    fake.routes["GET", f"{API}/x"] = lambda seen: (302, {"Location": f"{API}/x"}, b"")
    with pytest.raises(TransportError, match="redirect"):
        client.get_device("x")
    assert len(fake.requests) <= 5


# --- transport -----------------------------------------------------------------


def test_a_slow_server_times_out_without_a_retry(fake, token):
    def slow(seen):
        time.sleep(0.6)
        return fake.reply(200, {"status": "ok"})

    fake.routes["GET", f"{API}/x"] = slow
    client = LibreNMSClient(fake.url, token, allow_http=True, timeout=0.2)
    with pytest.raises(TransportError, match="timed out"):
        client.get_device("x")
    time.sleep(0.6)
    assert len(fake.requests) == 1


def test_a_closed_port_is_a_transport_error(token):
    server = ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
    port = server.server_address[1]
    server.server_close()
    client = LibreNMSClient(f"http://127.0.0.1:{port}", token, allow_http=True)
    with pytest.raises(TransportError, match="GET"):
        client.get_device("x")


def test_proxy_environment_variables_are_ignored(fake, client, make_fake, monkeypatch):
    proxy = make_fake()
    for name in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY"):
        monkeypatch.setenv(name, proxy.url)
    for name in ("no_proxy", "NO_PROXY"):
        monkeypatch.delenv(name, raising=False)
    fresh = LibreNMSClient(fake.url, client._token, allow_http=True)
    assert fresh.get_device("x") is None
    assert proxy.requests == []
    assert len(fake.requests) == 1


# --- TLS -----------------------------------------------------------------------


def test_https_works_with_the_pinned_certificate(make_fake, token, librenms_cert):
    fake = make_fake(librenms_cert)
    client = LibreNMSClient(fake.url, token, ca_file=librenms_cert.cert_path)
    assert client.get_device("x") is None
    assert len(fake.requests) == 1


def test_https_refuses_a_certificate_that_is_not_pinned(
    make_fake, token, librenms_cert, other_cert
):
    fake = make_fake(librenms_cert)
    client = LibreNMSClient(fake.url, token, ca_file=other_cert.cert_path)
    with pytest.raises(TransportError, match="TLS pin check failed") as caught:
        client.get_device("x")
    assert fake.requests == []
    text = str(caught.value)
    assert f"pinned {other_cert.fingerprint}" in text
    assert f"presented {librenms_cert.fingerprint}" in text


def test_a_pinned_self_signed_cert_with_the_ip_only_in_its_cn_is_accepted(
    make_fake, token, ip_cn_cert
):
    # Live LibreNMS: CN=192.168.50.10, no SAN; Python matches IPs only by IP SAN.
    fake = make_fake(ip_cn_cert)
    client = LibreNMSClient(fake.url, token, ca_file=ip_cn_cert.cert_path)
    assert client.get_device("x") is None
    assert len(fake.requests) == 1


def test_a_pin_replaces_the_hostname_match(make_fake, token, librenms_cert):
    fake = make_fake(librenms_cert)  # names 127.0.0.1, not localhost
    url = fake.url.replace("127.0.0.1", "localhost")
    client = LibreNMSClient(url, token, ca_file=librenms_cert.cert_path)
    assert client.get_device("x") is None
    assert len(fake.requests) == 1


def test_a_cert_that_chains_to_the_pin_but_is_not_it_is_refused(
    make_fake, token, librenms_ca, ca_issued_cert
):
    fake = make_fake(ca_issued_cert)  # signed by the pinned CA, names 127.0.0.1
    client = LibreNMSClient(fake.url, token, ca_file=librenms_ca.cert_path)
    with pytest.raises(TransportError, match="not the pinned certificate") as caught:
        client.get_device("x")
    assert fake.requests == []
    text = str(caught.value)
    assert f"pinned {librenms_ca.fingerprint}" in text
    assert f"presented {ca_issued_cert.fingerprint}" in text


def test_a_pin_ignores_the_system_trust_store(
    make_fake, token, librenms_ca, ca_issued_cert, librenms_cert, monkeypatch
):
    monkeypatch.setenv("SSL_CERT_FILE", str(librenms_ca.cert_path))
    fake = make_fake(ca_issued_cert)  # trusted by the system store, names the host
    client = LibreNMSClient(fake.url, token, ca_file=librenms_cert.cert_path)
    with pytest.raises(TransportError, match="TLS pin check failed") as caught:
        client.get_device("x")
    assert fake.requests == []
    text = str(caught.value)
    assert f"pinned {librenms_cert.fingerprint}" in text
    assert f"presented {ca_issued_cert.fingerprint}" in text


def test_a_pin_failure_says_when_the_presented_cert_is_unavailable(
    make_fake, token, librenms_cert, other_cert, monkeypatch
):
    monkeypatch.setattr(librenms, "presented_fingerprint", lambda *args: None)
    fake = make_fake(librenms_cert)
    client = LibreNMSClient(fake.url, token, ca_file=other_cert.cert_path)
    with pytest.raises(TransportError, match="presented certificate unavailable"):
        client.get_device("x")


def test_without_a_pin_system_trust_and_the_hostname_match_apply(
    make_fake, token, librenms_ca, ca_issued_cert, monkeypatch
):
    monkeypatch.setenv("SSL_CERT_FILE", str(librenms_ca.cert_path))
    fake = make_fake(ca_issued_cert)  # IP SAN 127.0.0.1 only
    assert LibreNMSClient(fake.url, token).get_device("x") is None
    by_name = LibreNMSClient(fake.url.replace("127.0.0.1", "localhost"), token)
    with pytest.raises(TransportError, match="Hostname mismatch"):
        by_name.get_device("x")
    assert len(fake.requests) == 1


def test_a_pin_keeps_the_cross_origin_redirect_refusal(make_fake, token, librenms_cert):
    fake, other = make_fake(librenms_cert), make_fake(librenms_cert)
    target = f"{other.url}{API}/x"  # same pinned certificate, another origin
    fake.routes["GET", f"{API}/x"] = lambda seen: (302, {"Location": target}, b"")
    client = LibreNMSClient(fake.url, token, ca_file=librenms_cert.cert_path)
    with pytest.raises(TransportError, match="redirect"):
        client.get_device("x")
    assert len(fake.requests) == 1
    assert other.requests == []


def test_https_without_a_pin_uses_the_system_trust_store(
    make_fake, token, librenms_cert
):
    fake = make_fake(librenms_cert)
    client = LibreNMSClient(fake.url, token)
    with pytest.raises(TransportError, match="ca_file"):
        client.get_device("x")
    assert fake.requests == []


def test_a_pin_file_with_a_private_key_is_refused(token, librenms_cert, tmp_path):
    bad = tmp_path / "bad.pem"
    bad.write_text(librenms_cert.pem + librenms_cert.key_path.read_text())
    bad.chmod(0o600)
    with pytest.raises(ConfigError, match=r"onboard\.ca_file"):
        LibreNMSClient("https://127.0.0.1", token, ca_file=bad)


def test_the_client_exposes_no_token_in_its_repr(client, canaries):
    assert canaries["onboard_token"] not in repr(client)
    assert canaries["onboard_token"] not in repr(vars(client))


class _Echo(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"status": "ok"}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


def test_the_user_agent_names_the_tool(token):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Echo)
    seen = {}

    def capture(self):
        seen["ua"] = self.headers.get("User-Agent")
        _Echo.do_GET(self)

    server.RequestHandlerClass = type("Capture", (_Echo,), {"do_GET": capture})
    thread = threading.Thread(target=server.serve_forever, args=(0.02,), daemon=True)
    thread.start()
    try:
        client = LibreNMSClient(
            f"http://127.0.0.1:{server.server_address[1]}", token, allow_http=True
        )
        with pytest.raises(ApiError):
            client.get_device("x")
    finally:
        server.shutdown()
        server.server_close()
    assert seen["ua"].startswith("aimesh-snmp-proxy/")


def test_deeply_nested_json_is_a_transport_error(fake, client):
    fake.routes["GET", f"{API}/x"] = lambda seen: (200, {}, b"[" * 200_000)
    with pytest.raises(TransportError, match="not JSON"):
        client.get_device("x")


def closed_port() -> int:
    with socket.socket() as probe:  # bound, never listening, then closed
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def test_every_librenms_tls_context_requires_tls_1_2(lax_tls, router_cert):
    created = lax_tls(librenms, config)
    pin = RouterPin(router_cert.cert_pem, (router_cert.fingerprint,))
    librenms.tls_context(None)
    librenms.tls_context(pin)
    assert librenms.presented_fingerprint("127.0.0.1", closed_port(), 1.0) is None
    assert [c.minimum_version for c in created] == [ssl.TLSVersion.TLSv1_2] * 3
