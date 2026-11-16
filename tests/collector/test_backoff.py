import json
import logging
import ssl

import aiohttp
import pytest
from asusrouter.error import (
    AsusRouter404Error,
    AsusRouterAccessError,
    AsusRouterConnectionError,
    AsusRouterLogoutError,
    AsusRouterSSLCertificateError,
    AsusRouterTimeoutError,
)
from asusrouter.modules.endpoint.error import ARAccessError

from aimesh_snmp_proxy.collector import backoff
from aimesh_snmp_proxy.collector.backoff import (
    Failure,
    Gate,
    Latch,
    LockoutStore,
    LoginRefusedError,
    Outcome,
    TargetGuard,
    classify,
)

HOUR = 3600.0


def access(code, attrs=None):
    """The exception the library raises for an ASUS ``error_status`` reply."""
    return AsusRouterAccessError("Access error", code, attrs or {})


def chained(outer, cause):
    try:
        raise outer from cause
    except type(outer) as exc:
        return exc


@pytest.fixture
def store(tmp_path):
    return LockoutStore(tmp_path / "state" / "lockout.json", kdf_n=2)


def guard(store, clock, rng=None, **kwargs):
    return TargetGuard("root", store, clock=clock, rng=rng, **kwargs)


# --- classify -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("exc", "outcome"),
    [
        (access(ARAccessError.CREDENTIALS), Outcome.CREDENTIALS),
        (access(ARAccessError.ANOTHER), Outcome.ANOTHER),
        (access(ARAccessError.CAPTCHA), Outcome.CAPTCHA),
        (access(ARAccessError.RESET_REQUIRED), Outcome.RESET_REQUIRED),
        (access(ARAccessError.NO_TOKEN), Outcome.TOKEN_LOSS),
        (access(ARAccessError.AUTHORIZATION), Outcome.TOKEN_LOSS),
        (AsusRouterLogoutError("Session is logged out"), Outcome.TOKEN_LOSS),
        (access(ARAccessError.REFERER_FAILED), Outcome.NETWORK),
        (
            AsusRouterAccessError("Cannot access appGet.cgi, status 500"),
            Outcome.NETWORK,
        ),
        (AsusRouterConnectionError("down"), Outcome.NETWORK),
        (AsusRouterTimeoutError("slow"), Outcome.NETWORK),
        (TimeoutError(), Outcome.NETWORK),
        (aiohttp.ClientOSError(), Outcome.NETWORK),
        (AsusRouter404Error("Endpoint login.cgi not found"), Outcome.UNSUPPORTED),
        (LoginRefusedError("budget", 5.0), Outcome.BUDGET),
        (ValueError("bug"), Outcome.NETWORK),
    ],
)
def test_classify_maps_library_errors(exc, outcome):
    assert classify(exc).outcome is outcome


def test_classify_try_again_keeps_the_router_lock_time():
    failure = classify(access(ARAccessError.TRY_AGAIN, {"timeout": 120}))
    assert failure == Failure(Outcome.TRY_AGAIN, lock_s=120.0, detail="code 7")


@pytest.mark.parametrize(
    "exc",
    [
        chained(
            AsusRouterAccessError("Cannot access login.cgi due to the SSL error"),
            AsusRouterSSLCertificateError("verify failed"),
        ),
        chained(AsusRouterConnectionError("x"), ssl.SSLCertVerificationError("bad")),
    ],
)
def test_classify_tls_verification_failure_as_pin_mismatch(exc):
    assert classify(exc).outcome is Outcome.PIN_MISMATCH


def test_classify_detail_never_carries_the_message():
    failure = classify(ValueError("canary-router-Pa55-1"))
    assert "canary" not in failure.detail
    assert failure.detail == "ValueError"


# --- login budget ---------------------------------------------------------------


def test_six_logins_per_hour_then_refused_until_the_oldest_ages_out(store, clock):
    g = guard(store, clock)
    first = clock.time()
    for _ in range(backoff.LOGINS_PER_WINDOW):
        g.before_login()
        clock.advance(60)
    with pytest.raises(LoginRefusedError) as info:
        g.before_login()
    assert info.value.retry_at == pytest.approx(first + HOUR)
    clock.set_wall(first + HOUR + 1)
    g.before_login()


def test_login_is_recorded_before_it_is_sent_so_restarts_share_the_budget(store, clock):
    for _ in range(backoff.LOGINS_PER_WINDOW):
        guard(store, clock).before_login()  # a fresh process each time
    with pytest.raises(LoginRefusedError):
        guard(store, clock).before_login()


def test_budget_failure_blocks_the_gate_until_retry(store, clock):
    g = guard(store, clock)
    g.on_failure(Failure(Outcome.BUDGET, retry_at=clock.time() + 500))
    assert g.gate() is Gate.BLOCKED
    clock.advance(501)
    assert g.gate() is Gate.OPEN


def test_login_refused_while_backing_off(store, clock, rng_high):
    g = guard(store, clock, rng_high)
    g.on_failure(Failure(Outcome.NETWORK))
    with pytest.raises(LoginRefusedError, match="backoff"):
        g.before_login()


# --- network backoff ------------------------------------------------------------


def test_network_backoff_doubles_from_30_s_to_a_15_min_cap(store, clock, rng_high):
    g = guard(store, clock, rng_high)
    delays = []
    for _ in range(7):
        g.on_failure(Failure(Outcome.NETWORK))
        delays.append(g.blocked_until - clock.time())
        clock.set_wall(g.blocked_until)
    assert delays == [30, 60, 120, 240, 480, 900, 900]


def test_full_jitter_can_retry_at_once(store, clock, rng_low):
    g = guard(store, clock, rng_low)
    g.on_failure(Failure(Outcome.NETWORK))
    assert g.gate() is Gate.OPEN


def test_seeded_jitter_stays_within_the_ceiling(store, clock):
    import random

    g = guard(store, clock, random.Random(7))  # noqa: S311 - jitter, not crypto
    for attempt in range(10):
        g.on_failure(Failure(Outcome.NETWORK))
        ceiling = min(900, 30 * 2**attempt)
        assert 0 <= g.blocked_until - clock.time() <= ceiling
        clock.set_wall(g.blocked_until)


def test_failures_while_blocked_do_not_escalate(store, clock, rng_high):
    g = guard(store, clock, rng_high)
    g.on_failure(Failure(Outcome.NETWORK))
    g.on_failure(Failure(Outcome.PIN_MISMATCH))  # a concurrent job, same outage
    assert g.blocked_until - clock.time() == 30


def test_success_resets_the_backoff(store, clock, rng_high):
    g = guard(store, clock, rng_high)
    g.on_failure(Failure(Outcome.NETWORK))
    clock.set_wall(g.blocked_until)
    g.on_success()
    g.on_failure(Failure(Outcome.NETWORK))
    assert g.blocked_until - clock.time() == 30


# --- token loss, TRY_AGAIN, ANOTHER ---------------------------------------------


def test_token_loss_allows_one_relogin_then_backs_off(store, clock, rng_high):
    g = guard(store, clock, rng_high)
    g.on_failure(Failure(Outcome.TOKEN_LOSS))
    assert g.gate() is Gate.OPEN
    g.on_failure(Failure(Outcome.TOKEN_LOSS))
    assert g.gate() is Gate.BLOCKED
    assert g.blocked_until - clock.time() == 30


def test_try_again_waits_10_min_doubling_to_60_min(store, clock):
    g = guard(store, clock)
    delays = []
    for _ in range(5):
        g.on_failure(Failure(Outcome.TRY_AGAIN))
        delays.append(g.blocked_until - clock.time())
        clock.set_wall(g.blocked_until)
    assert delays == [600, 1200, 2400, 3600, 3600]


def test_try_again_honours_a_longer_router_lock(store, clock):
    g = guard(store, clock)
    g.on_failure(Failure(Outcome.TRY_AGAIN, lock_s=5000))
    assert g.blocked_until - clock.time() == 5000


@pytest.mark.parametrize(("rng_name", "delay"), [("rng_low", 120), ("rng_high", 300)])
def test_another_session_waits_2_to_5_min(store, clock, request, rng_name, delay):
    g = guard(store, clock, request.getfixturevalue(rng_name))
    g.on_failure(Failure(Outcome.ANOTHER))
    assert g.blocked_until - clock.time() == delay


def test_unsupported_login_backs_off_on_the_root(store, clock, rng_high):
    g = guard(store, clock, rng_high)
    g.on_failure(Failure(Outcome.UNSUPPORTED))
    assert g.latch is None
    assert g.gate() is Gate.BLOCKED


# --- latches --------------------------------------------------------------------


def test_credentials_latch_blocks_logins_and_survives_restarts(store, clock):
    fp = store.fingerprint("old-password")
    g = guard(store, clock, password_fp=fp)
    g.on_failure(Failure(Outcome.CREDENTIALS))
    assert g.gate() is Gate.LATCHED
    with pytest.raises(LoginRefusedError, match="credentials"):
        g.before_login()
    clock.advance(10 * HOUR)
    assert guard(store, clock, password_fp=fp).gate() is Gate.LATCHED


def test_credentials_latch_clears_when_the_password_changes(store, clock):
    g = guard(store, clock, password_fp=store.fingerprint("old-password"))
    g.on_failure(Failure(Outcome.CREDENTIALS))
    restarted = guard(store, clock, password_fp=store.fingerprint("new-password"))
    assert restarted.gate() is Gate.OPEN
    g.set_password_fp(store.fingerprint("new-password"))
    assert g.gate() is Gate.OPEN


def test_sighup_clears_any_latch_and_persists(store, clock):
    g = guard(store, clock)
    g.on_failure(Failure(Outcome.CAPTCHA))
    g.clear_latch("SIGHUP")
    assert g.gate() is Gate.OPEN
    assert guard(store, clock).gate() is Gate.OPEN


def test_lockout_file_never_holds_the_password(store, clock):
    g = guard(store, clock, password_fp=store.fingerprint("canary-router-Pa55-1"))
    g.on_failure(Failure(Outcome.CREDENTIALS))
    assert "canary" not in store.path.read_text()


@pytest.mark.parametrize("outcome", [Outcome.CAPTCHA, Outcome.RESET_REQUIRED])
def test_captcha_latch_probes_hourly_and_logs_critical_once(
    store, clock, caplog, outcome
):
    g = guard(store, clock)
    with caplog.at_level(logging.CRITICAL):
        g.on_failure(Failure(outcome))
        g.on_failure(Failure(outcome))
    assert len([r for r in caplog.records if r.levelno == logging.CRITICAL]) == 1
    assert g.latch is Latch(outcome.value)
    assert g.gate() is Gate.LATCHED
    clock.advance(HOUR)
    assert g.gate() is Gate.PROBE
    g.probed()
    assert g.gate() is Gate.LATCHED


@pytest.mark.parametrize(
    "outcome",
    [Outcome.CREDENTIALS, Outcome.CAPTCHA, Outcome.UNSUPPORTED, Outcome.PIN_MISMATCH],
)
def test_node_refusal_turns_the_node_off_for_24_h(store, clock, outcome):
    g = TargetGuard("node:00:00:5e:00:53:02", store, clock=clock, node=True)
    g.on_failure(Failure(outcome))
    assert g.latch is Latch.REFUSED
    clock.advance(backoff.NODE_REFUSAL_HOLD_S - 1)
    assert g.gate() is Gate.LATCHED
    clock.advance(2)
    assert g.gate() is Gate.OPEN
    assert g.latch is None


# --- persistence edge cases -----------------------------------------------------


def test_wall_clock_stepping_back_cannot_block_beyond_a_day(store, clock):
    g = guard(store, clock)
    g.on_failure(Failure(Outcome.TRY_AGAIN, lock_s=3000))
    clock.set_wall(clock.time() - 10 * 365 * 24 * HOUR)  # RTC-less boot
    restarted = guard(store, clock)
    assert restarted.blocked_until - clock.time() <= backoff.MAX_HOLD_S


def test_corrupt_lockout_file_starts_fresh_and_logs(tmp_path, clock, caplog):
    path = tmp_path / "lockout.json"
    path.write_text("{oops")
    with caplog.at_level(logging.ERROR):
        g = TargetGuard("root", LockoutStore(path, kdf_n=2), clock=clock)
    assert g.gate() is Gate.OPEN
    assert "lockout.json" in caplog.text


def test_garbage_fields_in_the_lockout_file_fall_back_to_defaults(tmp_path, clock):
    path = tmp_path / "lockout.json"
    doc = {
        "version": 1,
        "salt": "AAAA",
        "targets": {
            "root": {"latch": "nope", "logins": ["x", 5], "blocked_until": "y"}
        },
    }
    path.write_text(json.dumps(doc))
    g = TargetGuard("root", LockoutStore(path, kdf_n=2), clock=clock)
    assert g.latch is None
    assert g.gate() is Gate.OPEN


def test_targets_are_isolated(store, clock):
    TargetGuard("root", store, clock=clock).on_failure(Failure(Outcome.CAPTCHA))
    other = TargetGuard("node:00:00:5e:00:53:02", store, clock=clock, node=True)
    assert other.gate() is Gate.OPEN


def test_fingerprint_is_salted_and_stable(tmp_path):
    a = LockoutStore(tmp_path / "a.json", kdf_n=2)
    b = LockoutStore(tmp_path / "b.json", kdf_n=2)
    assert a.fingerprint("pw") == a.fingerprint("pw")
    assert a.fingerprint("pw") != b.fingerprint("pw")
    assert LockoutStore(a.path, kdf_n=2).fingerprint("pw") == a.fingerprint("pw")
