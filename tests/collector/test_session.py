import asyncio
import logging
import socket
import ssl
from types import SimpleNamespace

import aiohttp
import pytest
from asusrouter.config import ARConfigKey
from asusrouter.config.connection import ARConnectionConfigKey as ARCCKey
from asusrouter.error import AsusRouterAccessError, AsusRouterError
from asusrouter.modules.aimesh import ARAiMeshSourceUniversal
from asusrouter.modules.endpoint import AREndpoint
from asusrouter.tools.security import ARSecurityLevel
from yarl import URL

from aimesh_snmp_proxy.collector import session as session_mod
from aimesh_snmp_proxy.collector.backoff import (
    Gate,
    LockoutStore,
    LoginRefusedError,
    Outcome,
    TargetGuard,
    classify,
)
from aimesh_snmp_proxy.collector.session import (
    READ_ENDPOINTS,
    RequestBlockedError,
    RouterSession,
    SessionClosedError,
    Target,
    fetch_certificate,
    fetch_chain,
    fetch_router_ca_file,
    fingerprint_der,
    guard_middleware,
    pin_verdict,
)
from aimesh_snmp_proxy.config import load_node_ca
from aimesh_snmp_proxy.logsafe import SecretStr

PASSWORD = "canary-router-Pa55-1"
END = "-----END CERTIFICATE-----\n"
# The read allowlist of 0.1.x; 0.2.0 adds the port status read and nothing else.
READS_0_1 = {
    "login.cgi",
    "Logout.asp",
    "appGet.cgi",
    "ajax_onboarding.asp",
    "ajax_coretmp.asp",
    "get_diag_content_data.cgi",
    "get_diag_eth_traffic.cgi",
    "get_diag_sta_traffic.cgi",
    "get_diag_wifi_traffic.cgi",
}


@pytest.fixture
def make_session(tmp_path, clock, pin):
    store = LockoutStore(tmp_path / "lockout.json", kdf_n=2)

    def _make(router, **kwargs):
        target = Target(
            name="root",
            host=router.host,
            port=router.port,
            username="admin",
            password=SecretStr(kwargs.pop("password", PASSWORD)),
            pin=kwargs.pop("pin", pin),
        )
        guard = TargetGuard("root", store, clock=clock)
        return RouterSession(target, guard, timeout_s=5.0, **kwargs)

    return _make


def run(coro):
    return asyncio.run(coro)


# --- pinned TLS, login, reuse ----------------------------------------------------


def test_fetch_logs_in_once_over_pinned_tls_and_reuses_the_session(
    mock_router, make_session
):
    async def scenario():
        async with mock_router() as router:
            session = make_session(router)
            first = await session.fetch(ARAiMeshSourceUniversal)
            await session.fetch(ARAiMeshSourceUniversal)
            await session.close()
            return router, first

    router, first = run(scenario())
    topology = first[ARAiMeshSourceUniversal]
    assert len(topology.nodes) == 3
    assert len(router.logins()) == 1
    assert router.logins()[0].method == "POST"
    data = [s for s in router.seen if s.path not in ("/login.cgi", "/Logout.asp")]
    assert data
    assert all("asus_token=tok1" in (s.cookie or "") for s in data)


def test_library_runs_fail_closed_and_quiet(mock_router, make_session):
    async def scenario():
        async with mock_router() as router:
            session = make_session(router)
            await session.fetch(ARAiMeshSourceUniversal)
            router_obj = session.router
            await session.close()
            return router_obj

    lib = run(scenario())
    cfg = lib.connection_config
    assert cfg.get(ARCCKey.VERIFY_SSL) is True
    assert cfg.get(ARCCKey.STRICT_SSL) is True
    assert cfg.get(ARCCKey.ALLOW_FALLBACK) is False
    assert cfg.get(ARCCKey.ALLOW_UPGRADE_HTTP_TO_HTTPS) is False
    assert lib.config.get(ARConfigKey.SECURITY_LEVEL_LOG) is ARSecurityLevel.STRICT
    assert lib._connection._response_callback is None


def test_wrong_certificate_sends_zero_login_posts(
    mock_router, make_session, rogue_cert
):
    async def scenario():
        async with mock_router(cert=rogue_cert) as router:
            session = make_session(router)
            with pytest.raises(AsusRouterError) as info:
                await session.fetch(ARAiMeshSourceUniversal)
            await session.close()
            return router, info.value

    router, exc = run(scenario())
    assert router.seen == []
    assert classify(exc).outcome is Outcome.PIN_MISMATCH


def test_closed_session_fails_closed_without_contacting_the_router(
    mock_router, make_session
):
    async def scenario():
        async with mock_router() as router:
            session = make_session(router)
            await session.fetch(ARAiMeshSourceUniversal)
            seen = len(router.seen)
            await session.http.close()  # a bug or a stray close elsewhere
            with pytest.raises(SessionClosedError):
                await session.fetch(ARAiMeshSourceUniversal)
            return router, seen

    router, seen = run(scenario())
    assert len(router.seen) == seen


def test_session_the_library_would_create_fails_tls_against_the_router(
    mock_router, make_session
):
    """Security test 3: bypass our check; VERIFY_SSL makes the swap fail TLS."""

    async def scenario():
        async with mock_router() as router:
            session = make_session(router)
            await session.fetch(ARAiMeshSourceUniversal)
            lib = session.router
            await session.http.close()
            lib._connection.reset_auth()
            with pytest.raises(AsusRouterError) as info:
                await lib.async_fetch_data(ARAiMeshSourceUniversal, force=True)
            await lib._connection.async_close_session()
            return router, info.value

    router, exc = run(scenario())
    assert len(router.logins()) == 1  # only the first, pinned login
    assert classify(exc).outcome is Outcome.PIN_MISMATCH


def test_logout_on_close_and_close_is_idempotent(mock_router, make_session):
    async def scenario():
        async with mock_router() as router:
            session = make_session(router)
            await session.fetch(ARAiMeshSourceUniversal)
            await session.close()
            await session.close()
            return router, session

    router, session = run(scenario())
    assert router.paths()[-1] == "/Logout.asp"
    assert session.closed
    assert session.http.closed
    with pytest.raises(SessionClosedError):
        run(session.fetch(ARAiMeshSourceUniversal))


def test_close_without_login_sends_nothing(mock_router, make_session):
    async def scenario():
        async with mock_router() as router:
            await make_session(router).close()
            return router

    assert run(scenario()).seen == []


# --- login guard ---------------------------------------------------------------


def test_exhausted_budget_blocks_the_login_post(mock_router, make_session):
    async def scenario():
        async with mock_router() as router:
            session = make_session(router)
            for _ in range(6):
                session.guard.before_login()
            with pytest.raises(LoginRefusedError) as info:
                await session.fetch(ARAiMeshSourceUniversal)
            await session.close()
            return router, info.value

    router, exc = run(scenario())
    assert router.logins() == []
    assert classify(exc).outcome is Outcome.BUDGET


def test_refused_credentials_latch_and_stop_further_logins(mock_router, make_session):
    async def scenario():
        async with mock_router() as router:
            session = make_session(router, password="wrong-password")
            with pytest.raises(AsusRouterAccessError) as first:
                await session.fetch(ARAiMeshSourceUniversal)
            session.guard.on_failure(classify(first.value))
            await session.close()
            fresh = make_session(router, password="wrong-password")  # a restart
            with pytest.raises(LoginRefusedError) as second:
                await fresh.fetch(ARAiMeshSourceUniversal)
            await fresh.close()
            return router, fresh, second.value

    router, session, exc = run(scenario())
    assert len(router.logins()) == 1
    assert session.guard.gate() is Gate.LATCHED
    assert classify(exc).outcome is Outcome.BUDGET


def test_token_loss_relogs_in_once_and_counts_against_the_budget(
    mock_router, make_session
):
    async def scenario():
        async with mock_router() as router:
            session = make_session(router)
            await session.fetch(ARAiMeshSourceUniversal)
            router.expire_tokens()
            await session.fetch(ARAiMeshSourceUniversal)
            await session.close()
            return router, session

    router, session = run(scenario())
    assert len(router.logins()) == 2
    assert len(session.guard._s.logins) == 2


# --- request allowlist (H1, H4) --------------------------------------------------


def test_write_endpoints_never_leave_the_host(mock_router, make_session):
    async def scenario():
        async with mock_router() as router:
            session = make_session(router)
            await session.fetch(ARAiMeshSourceUniversal)
            for endpoint in (AREndpoint.PUSH_DATA, AREndpoint.START_APPLY):
                with pytest.raises(RequestBlockedError):
                    await session.read(endpoint, "{}")
            with pytest.raises(RequestBlockedError, match="nvram_dump"):
                await session.read(AREndpoint.FETCH_DATA, "hook=nvram_dump(appobj)")
            await session.close()
            return router

    router = run(scenario())
    assert "/applyapp.cgi" not in router.paths()
    assert "/start_apply.htm" not in router.paths()
    assert not any("nvram_dump" in seen.body for seen in router.seen)


def fake_request(url, *, ssl=True, body=b"", method="POST"):
    return SimpleNamespace(
        url=URL(url),
        ssl=ssl,
        method=method,
        body=aiohttp.payload.BytesPayload(body) if body else b"",
    )


@pytest.mark.parametrize(
    ("url", "ssl", "why"),
    [
        ("http://192.168.50.1:80/login.cgi", True, "HTTPS"),
        ("https://192.168.50.1:80/login.cgi", True, "HTTPS"),
        ("https://192.168.50.7:8443/login.cgi", True, "HTTPS"),
        ("https://192.168.50.1:8443/login.cgi", False, "unverified"),
        ("https://192.168.50.1:8443/apply.cgi", True, "allowlisted"),
    ],
)
def test_middleware_refuses_before_any_connection(tmp_path, clock, pin, url, ssl, why):
    target = Target("root", "192.168.50.1", 8443, "admin", SecretStr(PASSWORD), pin)
    guard = TargetGuard("root", LockoutStore(tmp_path / "l.json", kdf_n=2), clock=clock)
    calls = []

    async def handler(req):
        calls.append(req)

    middleware = guard_middleware(target, guard)
    with pytest.raises(RequestBlockedError, match=why):
        run(middleware(fake_request(url, ssl=ssl), handler))
    assert calls == []
    assert guard._s.logins == []


def test_the_allowlist_adds_only_port_status_netdev_and_the_ports_page(
    tmp_path, clock, pin
):
    added = {"get_port_status.cgi", "update.cgi", "ajax_ethernet_ports.asp"}
    assert set(READ_ENDPOINTS) == READS_0_1 | added
    target = Target("root", "192.168.50.1", 8443, "admin", SecretStr(PASSWORD), pin)
    guard = TargetGuard("root", LockoutStore(tmp_path / "l.json", kdf_n=2), clock=clock)
    middleware = guard_middleware(target, guard)
    passed = []

    async def handler(req):
        passed.append(req.url.path)
        return "response"

    url = "https://192.168.50.1:8443/get_port_status.cgi?node_mac=all"
    assert run(middleware(fake_request(url), handler)) == "response"
    assert passed == ["/get_port_status.cgi"]


# The library's fallback for models without get_port_status.cgi: an empty POST only.
@pytest.mark.parametrize(
    ("method", "query", "body", "allowed"),
    [
        ("POST", "", b"", True),
        ("GET", "", b"", False),
        ("POST", "action_mode=apply", b"", False),
        ("POST", "", b"action_mode=apply", False),
    ],
)
def test_the_ports_page_passes_only_as_the_librarys_empty_post(
    tmp_path, clock, pin, method, query, body, allowed
):
    target = Target("root", "192.168.50.1", 8443, "admin", SecretStr(PASSWORD), pin)
    guard = TargetGuard("root", LockoutStore(tmp_path / "l.json", kdf_n=2), clock=clock)
    middleware = guard_middleware(target, guard)
    passed = []

    async def handler(req):
        passed.append(req.url.path)
        return "response"

    url = f"https://192.168.50.1:8443/ajax_ethernet_ports.asp?{query}".rstrip("?")
    request = fake_request(url, body=body, method=method)
    if allowed:
        assert run(middleware(request, handler)) == "response"
    else:
        with pytest.raises(RequestBlockedError, match=r"ports\.asp passes only as"):
            run(middleware(request, handler))
    assert passed == (["/ajax_ethernet_ports.asp"] if allowed else [])


# update.cgi runs the page handler that `output` names: only the byte counters pass.
@pytest.mark.parametrize(
    ("method", "query", "body", "allowed"),
    [
        ("GET", "output=netdev", b"", True),
        ("POST", "output=netdev", b"", False),
        ("GET", "output=nvram_get&arg0=http_passwd", b"", False),
        ("GET", "output=netdev&arg0=x", b"", False),
        ("GET", "output=netdev&output=wanlink", b"", False),
        ("GET", "", b"output=netdev", False),
        ("GET", "output=netdev", b"output=nvram_get", False),
    ],
)
def test_update_cgi_passes_only_as_the_netdev_byte_counters(
    tmp_path, clock, pin, method, query, body, allowed
):
    target = Target("root", "192.168.50.1", 8443, "admin", SecretStr(PASSWORD), pin)
    guard = TargetGuard("root", LockoutStore(tmp_path / "l.json", kdf_n=2), clock=clock)
    middleware = guard_middleware(target, guard)
    passed = []

    async def handler(req):
        passed.append(req.url.path)
        return "response"

    url = f"https://192.168.50.1:8443/update.cgi?{query}"
    request = fake_request(url, body=body, method=method)
    if allowed:
        assert run(middleware(request, handler)) == "response"
    else:
        with pytest.raises(RequestBlockedError, match=r"update\.cgi passes only as"):
            run(middleware(request, handler))
    assert passed == (["/update.cgi"] if allowed else [])


def test_middleware_records_the_login_before_sending(tmp_path, clock, pin):
    target = Target("root", "192.168.50.1", 8443, "admin", SecretStr(PASSWORD), pin)
    guard = TargetGuard("root", LockoutStore(tmp_path / "l.json", kdf_n=2), clock=clock)
    order = []

    async def handler(req):
        order.append(len(guard._s.logins))
        return "response"

    middleware = guard_middleware(target, guard)
    url = "https://192.168.50.1:8443/login.cgi"
    assert run(middleware(fake_request(url), handler)) == "response"
    assert order == [1]
    for _ in range(5):
        run(middleware(fake_request(url), handler))
    with pytest.raises(LoginRefusedError):
        run(middleware(fake_request(url), handler))
    assert len(order) == 6


# --- logging (H3) --------------------------------------------------------------


def test_library_debug_logging_is_clamped(make_session, mock_router, caplog):
    async def scenario():
        async with mock_router() as router:
            session = make_session(router, password="wrong-password")
            with pytest.raises(AsusRouterAccessError) as info:
                await session.fetch(ARAiMeshSourceUniversal)
            await session.close()
            return info.value

    with caplog.at_level(logging.DEBUG):
        exc = run(scenario())
    assert logging.getLogger("asusrouter").getEffectiveLevel() >= logging.INFO
    import base64

    login = base64.b64encode(b"admin:wrong-password").decode()
    assert "wrong-password" not in caplog.text
    assert login not in caplog.text
    assert "wrong-password" not in repr(exc)


def test_target_repr_hides_the_password(pin):
    target = Target("root", "192.168.50.1", 8443, "admin", SecretStr(PASSWORD), pin)
    assert PASSWORD not in repr(target)


# --- certificate fetch -----------------------------------------------------------


def test_fetch_certificate_returns_the_presented_cert_without_http(
    mock_router, rogue_cert
):
    async def scenario():
        async with mock_router(cert=rogue_cert) as router:
            der = await fetch_certificate(router.host, router.port, timeout_s=5.0)
            return router, der

    router, der = run(scenario())
    assert fingerprint_der(der) == rogue_cert.fingerprint
    assert router.seen == []


def test_pin_mismatch_logs_both_fingerprints(
    mock_router, make_session, rogue_cert, router_cert, caplog
):
    async def scenario():
        async with mock_router(cert=rogue_cert) as router:
            session = make_session(router)
            with caplog.at_level(logging.ERROR):
                await session_mod.log_pin_mismatch(session.target, timeout_s=5.0)
            return router

    router = run(scenario())
    assert rogue_cert.fingerprint in caplog.text
    assert router_cert.fingerprint in caplog.text
    assert router.seen == []


def test_pin_mismatch_logging_survives_an_unreachable_router(pin, caplog):
    target = Target("root", "127.0.0.1", 9, "admin", SecretStr(PASSWORD), pin)
    with caplog.at_level(logging.ERROR):
        run(session_mod.log_pin_mismatch(target, timeout_s=0.5))
    assert "unavailable" in caplog.text


# --- the node CA pin ---------------------------------------------------------------


@pytest.fixture
def node_pin(write_file, node_ca):
    return load_node_ca(write_file("asus_node_ca.pem", node_ca.cert_pem, 0o644))


def test_fetch_chain_returns_the_leaf_then_its_ca(mock_router, node_leaf, node_ca):
    async def scenario():
        async with mock_router(cert=node_leaf) as router:
            chain = await fetch_chain(router.host, router.port, timeout_s=5.0)
            return router, chain

    router, chain = run(scenario())
    assert [fingerprint_der(der) for der in chain] == [
        node_leaf.fingerprint,
        node_ca.fingerprint,
    ]
    assert router.seen == []  # a handshake only


def test_the_router_ca_file_comes_over_the_pinned_link_without_a_login(
    mock_router, pin, node_ca
):
    async def scenario():
        async with mock_router() as router:
            router.public["cert.crt"] = node_ca.cert_pem
            body = await fetch_router_ca_file(
                router.host, router.port, pin, timeout_s=5.0
            )
            return router, body

    router, body = run(scenario())
    assert body == node_ca.cert_pem.encode()
    assert router.paths() == ["/cert.crt"]
    assert router.logins() == []


@pytest.mark.parametrize(
    ("public", "error"),
    [({"cert.crt": None}, "HTTP 404"), ({"cert.crt": "x" * 20000}, "larger than")],
    ids=["missing", "oversized"],
)
def test_a_missing_or_oversized_router_ca_file_is_an_error(
    mock_router, pin, public, error
):
    async def scenario():
        async with mock_router() as router:
            router.public.update(public)
            await fetch_router_ca_file(router.host, router.port, pin, timeout_s=5.0)

    with pytest.raises(session_mod.CertFileError, match=error):
        run(scenario())


def test_the_router_ca_file_is_never_fetched_from_an_unpinned_router(
    mock_router, rogue_cert, pin, node_ca
):
    async def scenario():
        async with mock_router(cert=rogue_cert) as router:
            router.public["cert.crt"] = node_ca.cert_pem
            with pytest.raises(aiohttp.ClientError):
                await fetch_router_ca_file(router.host, router.port, pin, timeout_s=5.0)
            return router

    assert run(scenario()).seen == []


@pytest.mark.parametrize(
    ("leaf", "verdict"),
    [
        ("node_leaf", "issued by the node CA"),
        ("nameless_leaf", "issued by the node CA"),
        ("foreign_leaf", "not issued by the node CA"),
    ],
)
def test_the_verdict_on_a_node_certificate_names_its_issuer(
    request, node_pin, leaf, verdict
):
    pem = request.getfixturevalue(leaf).cert_pem
    der = ssl.PEM_cert_to_DER_cert(pem.split("-----END CERTIFICATE-----")[0] + END)
    assert pin_verdict(node_pin, der) == verdict


def test_the_verdict_on_a_router_certificate_compares_fingerprints(
    pin, router_cert, rogue_cert
):
    for cert, verdict in ((router_cert, "matches"), (rogue_cert, "MISMATCH")):
        assert pin_verdict(pin, ssl.PEM_cert_to_DER_cert(cert.cert_pem)) == verdict


def test_a_node_tls_failure_logs_the_node_ca_and_what_was_presented(
    mock_router, nameless_leaf, node_ca, node_pin, caplog
):
    async def scenario():
        async with mock_router(cert=nameless_leaf) as router:
            target = Target(
                "node:x",
                router.host,
                router.port,
                "admin",
                SecretStr(PASSWORD),
                node_pin,
            )
            with caplog.at_level(logging.ERROR):
                await session_mod.log_pin_mismatch(target, timeout_s=5.0)

    run(scenario())
    assert f"node CA {node_ca.fingerprint}" in caplog.text
    assert nameless_leaf.fingerprint in caplog.text
    assert "issued by the node CA" in caplog.text
    assert "must name 127.0.0.1" in caplog.text


def test_unparsable_reply_is_logged_without_its_content(
    mock_router, make_session, caplog
):
    async def scenario():
        async with mock_router() as router:
            session = make_session(router)
            await session.fetch(ARAiMeshSourceUniversal)
            router.raw_replies["appGet.cgi"] = "garbage canary-client-name-Kitchen"
            with caplog.at_level(logging.DEBUG):
                await session.read(AREndpoint.FETCH_DATA, "hook=get_clientlist()")
            await session.close()

    run(scenario())
    assert "canary-client-name" not in caplog.text
    assert "content withheld" in caplog.text


# --- shared use, token drop, retirement --------------------------------------------


def test_drop_auth_keeps_the_router_and_concurrent_jobs_share_one_relogin(
    mock_router, make_session
):
    async def scenario():
        async with mock_router() as router:
            session = make_session(router)
            await session.fetch(ARAiMeshSourceUniversal)
            lib = session.router
            router.expire_tokens()  # the router dropped it; drop_auth follows suit
            session.drop_auth()
            await asyncio.gather(
                session.fetch(ARAiMeshSourceUniversal),
                session.fetch(ARAiMeshSourceUniversal),
            )
            same = session.router is lib
            await session.close()
            return router, same

    router, same = run(scenario())
    assert same
    assert len(router.logins()) == 2  # the first login and one shared re-login
    assert router.tokens == set()


def test_retire_waits_for_running_jobs_then_logs_out(mock_router, make_session):
    async def scenario():
        async with mock_router() as router:
            session = make_session(router)
            release = asyncio.Event()

            async def job():
                async with session.use():
                    await session.fetch(ARAiMeshSourceUniversal)
                    await release.wait()

            running = asyncio.create_task(job())
            for _ in range(500):  # bounded: a broken job must fail the test, not hang
                if router.logins() or running.done():
                    break
                await asyncio.sleep(0.01)
            assert not running.done()
            retiring = asyncio.create_task(session.retire(timeout_s=5))
            await asyncio.sleep(0.1)
            early = "/Logout.asp" in router.paths()
            release.set()
            await asyncio.wait_for(asyncio.gather(running, retiring), timeout=10)
            return router, early

    router, early = run(scenario())
    assert not early
    assert router.paths()[-1] == "/Logout.asp"
    assert router.tokens == set()


def test_retire_gives_up_waiting_after_the_timeout(mock_router, make_session):
    async def scenario():
        async with mock_router() as router:
            session = make_session(router)
            await session.fetch(ARAiMeshSourceUniversal)
            async with session.use():
                await session.retire(timeout_s=0.05)
            return router, session

    router, session = run(scenario())
    assert session.closed
    assert router.paths()[-1] == "/Logout.asp"


def test_the_unverified_chain_fetch_still_requires_tls_1_2(lax_tls):
    created = lax_tls(session_mod)
    with socket.socket() as probe:  # bound, never listening, then closed
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with pytest.raises(ConnectionRefusedError):
        asyncio.run(session_mod.fetch_chain("127.0.0.1", port, timeout_s=5))
    assert [c.minimum_version for c in created] == [ssl.TLSVersion.TLSv1_2]
