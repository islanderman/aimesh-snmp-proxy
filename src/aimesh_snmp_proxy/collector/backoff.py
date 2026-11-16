"""Protect the router from the collector: backoff, a login budget, error latches.

Design section 3 and security M1. Decisions use wall-clock seconds and persist
in ``state_dir/lockout.json`` before the next login leaves, so a restart loop
can neither reset a latch nor exceed the login budget.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import logging
import math
import random
import secrets
import ssl
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

import aiohttp
from asusrouter.error import (
    AsusRouter404Error,
    AsusRouterAccessError,
    AsusRouterLogoutError,
    AsusRouterSSLCertificateError,
)
from asusrouter.modules.endpoint.error import ARAccessError

from aimesh_snmp_proxy.collector import statefile

_LOG = logging.getLogger(__name__)

FORMAT_VERSION = 1
NETWORK_BASE_S = 30.0
NETWORK_CAP_S = 900.0
TRY_AGAIN_BASE_S = 600.0
TRY_AGAIN_CAP_S = 3600.0
ANOTHER_MIN_S = 120.0
ANOTHER_MAX_S = 300.0
PROBE_INTERVAL_S = 3600.0
LOGIN_WINDOW_S = 3600.0
LOGINS_PER_WINDOW = 6
NODE_REFUSAL_HOLD_S = 86400.0
MAX_HOLD_S = 86400.0  # bounds a persisted block after the wall clock steps back
KDF_N = 2**14
_SALT_BYTES = 16


class Clock(Protocol):
    """Monotonic seconds for scheduling, wall seconds for anything persisted."""

    def monotonic(self) -> float: ...

    def time(self) -> float: ...

    async def sleep(self, seconds: float) -> None: ...


class SystemClock:
    """The real clocks."""

    def monotonic(self) -> float:
        return time.monotonic()

    def time(self) -> float:
        return time.time()

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)


class Outcome(StrEnum):
    """What a failed request means for the next attempt."""

    NETWORK = "network"
    PIN_MISMATCH = "pin_mismatch"
    UNSUPPORTED = "unsupported"
    TOKEN_LOSS = "token_loss"  # noqa: S105 - an outcome name, not a secret
    CREDENTIALS = "credentials"
    TRY_AGAIN = "try_again"
    ANOTHER = "another"
    CAPTCHA = "captcha"
    RESET_REQUIRED = "reset_required"
    BUDGET = "budget"


class Latch(StrEnum):
    """A stop that only time (REFUSED) or an operator clears."""

    CREDENTIALS = "credentials"
    CAPTCHA = "captcha"
    RESET_REQUIRED = "reset_required"
    REFUSED = "refused"


class Gate(StrEnum):
    """Whether a job may talk to the target now."""

    OPEN = "open"
    BLOCKED = "blocked"
    LATCHED = "latched"
    PROBE = "probe"


@dataclass(frozen=True)
class Failure:
    """A classified failure; ``detail`` is log-safe and never a reply body."""

    outcome: Outcome
    lock_s: float | None = None
    retry_at: float | None = None
    detail: str = ""


class LoginRefusedError(RuntimeError):
    """No login was sent: the guard refused it (budget, backoff, or latch)."""

    def __init__(self, reason: str, retry_at: float | None = None) -> None:
        super().__init__(f"login refused locally: {reason}")
        self.reason = reason
        self.retry_at = retry_at


_CODE_OUTCOMES = {
    ARAccessError.NO_TOKEN: Outcome.TOKEN_LOSS,
    ARAccessError.AUTHORIZATION: Outcome.TOKEN_LOSS,
    ARAccessError.LOGOUT: Outcome.TOKEN_LOSS,
    ARAccessError.CREDENTIALS: Outcome.CREDENTIALS,
    ARAccessError.TRY_AGAIN: Outcome.TRY_AGAIN,
    ARAccessError.ANOTHER: Outcome.ANOTHER,
    ARAccessError.CAPTCHA: Outcome.CAPTCHA,
    ARAccessError.RESET_REQUIRED: Outcome.RESET_REQUIRED,
}
_TLS_ERRORS = (
    AsusRouterSSLCertificateError,
    ssl.SSLCertVerificationError,
    aiohttp.ClientConnectorCertificateError,
)


def _chain(exc: BaseException | None) -> Iterator[BaseException]:
    seen: set[int] = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        yield exc
        exc = exc.__cause__ or exc.__context__


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value) if math.isfinite(value) else None


def _positive(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) and number > 0 else None


def classify(exc: BaseException) -> Failure:
    """Map a library, aiohttp, or guard exception to an :class:`Outcome`."""
    chain = list(_chain(exc))
    for item in chain:
        if isinstance(item, LoginRefusedError):
            return Failure(Outcome.BUDGET, retry_at=item.retry_at, detail=item.reason)
    for item in chain:
        if isinstance(item, _TLS_ERRORS):
            reason = getattr(item, "verify_message", None) or "verification failed"
            return Failure(Outcome.PIN_MISMATCH, detail=f"TLS {reason}")
    if isinstance(exc, AsusRouterLogoutError):
        return Failure(Outcome.TOKEN_LOSS, detail="code 8")
    if isinstance(exc, AsusRouter404Error):
        return Failure(Outcome.UNSUPPORTED, detail="HTTP 404")
    if isinstance(exc, AsusRouterAccessError):
        code = next((a for a in exc.args if isinstance(a, ARAccessError)), None)
        if code is not None:
            outcome = _CODE_OUTCOMES.get(code, Outcome.NETWORK)
            attrs = next((a for a in exc.args if isinstance(a, dict)), {})
            lock = attrs.get("timeout") if outcome is Outcome.TRY_AGAIN else None
            return Failure(outcome, lock_s=_positive(lock), detail=f"code {int(code)}")
    return Failure(Outcome.NETWORK, detail=type(exc).__name__)


# --- persistence --------------------------------------------------------------


def _b64decode(value: Any) -> bytes | None:
    if not isinstance(value, str):
        return None
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None


class LockoutStore:
    """Every target's login state in one atomic ``lockout.json``.

    The password fingerprint is salted scrypt, so the file reveals neither the
    password nor a cheap hash of it; it only tells whether the password changed.
    """

    def __init__(self, path: Path, *, kdf_n: int = KDF_N) -> None:
        self.path = path
        self._kdf_n = kdf_n
        doc = statefile.read_json(path)
        if doc is not None and not (
            isinstance(doc, dict) and doc.get("version") == FORMAT_VERSION
        ):
            _LOG.error("%s: unsupported lockout format; starting fresh", path)
            doc = None
        doc = doc or {}
        targets = doc.get("targets")
        self._targets: dict[str, Any] = (
            dict(targets) if isinstance(targets, dict) else {}
        )
        salt = _b64decode(doc.get("salt"))
        self._salt = salt if salt is not None and len(salt) >= _SALT_BYTES else None

    def get(self, name: str) -> Any:
        return self._targets.get(name)

    def put(self, name: str, state: dict[str, Any]) -> None:
        self._targets[name] = state
        self._write()

    def fingerprint(self, secret: str) -> str:
        """Salted scrypt of ``secret``; the salt persists on first use."""
        if self._salt is None:
            self._salt = secrets.token_bytes(_SALT_BYTES)
            self._write()
        digest = hashlib.scrypt(
            secret.encode(), salt=self._salt, n=self._kdf_n, r=8, p=1, dklen=32
        )
        return base64.b64encode(digest).decode()

    def _write(self) -> None:
        salt = base64.b64encode(self._salt).decode() if self._salt else None
        doc = {"version": FORMAT_VERSION, "salt": salt, "targets": self._targets}
        statefile.write_json(self.path, doc)


@dataclass
class _State:
    latch: Latch | None = None
    latched_at: float | None = None
    password_fp: str | None = None
    blocked_until: float = 0.0
    network_failures: int = 0
    try_again_failures: int = 0
    token_losses: int = 0
    logins: list[float] = field(default_factory=list)
    last_probe: float | None = None

    @classmethod
    def load(cls, doc: Any, now: float) -> _State:
        """Parse defensively: the file is ours, but a bad field must not crash."""
        d = doc if isinstance(doc, dict) else {}

        def count(key: str) -> int:
            value = d.get(key)
            ok = isinstance(value, int) and not isinstance(value, bool) and value > 0
            return value if ok else 0

        def stamp(key: str) -> float | None:
            value = _number(d.get(key))
            return None if value is None else min(value, now)

        try:
            latch = Latch(d.get("latch"))
        except ValueError:
            latch = None
        fp = d.get("password_fp")
        raw_logins = d.get("logins")
        logins = raw_logins if isinstance(raw_logins, list) else []
        blocked = _number(d.get("blocked_until")) or 0.0
        return cls(
            latch=latch,
            latched_at=stamp("latched_at") if latch else None,
            password_fp=fp if isinstance(fp, str) else None,
            blocked_until=min(blocked, now + MAX_HOLD_S),
            network_failures=count("network_failures"),
            try_again_failures=count("try_again_failures"),
            token_losses=count("token_losses"),
            logins=sorted(min(t, now) for t in map(_number, logins) if t is not None),
            last_probe=stamp("last_probe"),
        )

    def dump(self) -> dict[str, Any]:
        return {
            "latch": self.latch.value if self.latch else None,
            "latched_at": self.latched_at,
            "password_fp": self.password_fp,
            "blocked_until": self.blocked_until,
            "network_failures": self.network_failures,
            "try_again_failures": self.try_again_failures,
            "token_losses": self.token_losses,
            "logins": self.logins,
            "last_probe": self.last_probe,
        }


# --- the guard ------------------------------------------------------------------

_REFUSALS = frozenset(
    {
        Outcome.CREDENTIALS,
        Outcome.CAPTCHA,
        Outcome.RESET_REQUIRED,
        Outcome.UNSUPPORTED,
        Outcome.PIN_MISMATCH,
    }
)


class TargetGuard:
    """Login protection for one target: the root router or one per_node node.

    ``node=True`` turns every refusal into a 24 h REFUSED latch that expires by
    itself; on the root, CREDENTIALS, CAPTCHA, and RESET_REQUIRED latch until
    the password changes or an operator sends SIGHUP.
    """

    def __init__(
        self,
        name: str,
        store: LockoutStore,
        *,
        clock: Clock,
        rng: random.Random | None = None,
        node: bool = False,
        password_fp: str | None = None,
    ) -> None:
        self.name = name
        self._store = store
        self._clock = clock
        self._rng = rng if rng is not None else random.SystemRandom()
        self._node = node
        self._password_fp = password_fp
        self._announced = False
        self.last_failure: Failure | None = None
        self._s = _State.load(store.get(name), clock.time())
        self._expire(clock.time())
        if self._s.latch is not None:
            self._announce(f"still latched ({self._s.latch}) from an earlier run")

    @property
    def latch(self) -> Latch | None:
        return self._s.latch

    @property
    def blocked_until(self) -> float:
        return self._s.blocked_until

    def gate(self) -> Gate:
        now = self._clock.time()
        self._expire(now)
        s = self._s
        if s.latch is not None:
            due = s.last_probe is None or now - s.last_probe >= PROBE_INTERVAL_S
            if s.latch in (Latch.CAPTCHA, Latch.RESET_REQUIRED) and due:
                return Gate.PROBE
            return Gate.LATCHED
        return Gate.BLOCKED if now < s.blocked_until else Gate.OPEN

    def before_login(self) -> None:
        """Record a login before it is sent, or raise :class:`LoginRefusedError`."""
        now = self._clock.time()
        gate = self.gate()
        if gate in (Gate.LATCHED, Gate.PROBE):
            raise LoginRefusedError(f"{self._s.latch} latch")
        if gate is Gate.BLOCKED:
            raise LoginRefusedError("backoff", self._s.blocked_until)
        logins = [t for t in self._s.logins if now - t < LOGIN_WINDOW_S]
        if len(logins) >= LOGINS_PER_WINDOW:
            self._s.logins = logins
            raise LoginRefusedError("login budget", logins[0] + LOGIN_WINDOW_S)
        self._s.logins = [*logins, now]
        if not self._save():
            self._s.logins = logins
            raise LoginRefusedError("login state not persisted", now + NETWORK_BASE_S)

    def on_success(self) -> None:
        self.last_failure = None
        s = self._s
        if (
            s.network_failures
            or s.try_again_failures
            or s.token_losses
            or s.blocked_until
        ):
            s.network_failures = s.try_again_failures = s.token_losses = 0
            s.blocked_until = 0.0
            self._save()

    def on_failure(self, failure: Failure) -> None:
        self.last_failure = failure
        now = self._clock.time()
        s = self._s
        outcome = failure.outcome
        if self._node and outcome in _REFUSALS:
            self._latch(Latch.REFUSED, now, failure)
        elif outcome is Outcome.CREDENTIALS:
            self._latch(Latch.CREDENTIALS, now, failure)
        elif outcome in (Outcome.CAPTCHA, Outcome.RESET_REQUIRED):
            self._latch(Latch(outcome.value), now, failure)
        elif outcome is Outcome.TRY_AGAIN:
            s.try_again_failures += 1
            step = TRY_AGAIN_BASE_S * 2 ** (s.try_again_failures - 1)
            delay = max(min(step, TRY_AGAIN_CAP_S), failure.lock_s or 0.0)
            self._block(now, now + delay, failure)
        elif outcome is Outcome.ANOTHER:
            delay = self._rng.uniform(ANOTHER_MIN_S, ANOTHER_MAX_S)
            self._block(now, now + delay, failure)
        elif outcome is Outcome.BUDGET:
            self._block(now, failure.retry_at or now + NETWORK_BASE_S, failure)
        elif outcome is Outcome.TOKEN_LOSS and s.token_losses == 0:
            s.token_losses = 1
            _LOG.info("%s: session token lost; one re-login allowed", self.name)
            self._save()
        elif now >= s.blocked_until:  # concurrent failures of one outage count once
            if outcome is Outcome.TOKEN_LOSS:
                s.token_losses += 1
            ceiling = min(NETWORK_CAP_S, NETWORK_BASE_S * 2**s.network_failures)
            s.network_failures += 1
            self._block(now, now + self._rng.uniform(0.0, ceiling), failure)

    def probed(self) -> None:
        """A credential-free probe ran; the next one is due in an hour."""
        self._s.last_probe = self._clock.time()
        self._save()

    def clear_latch(self, reason: str) -> None:
        """Operator reset (SIGHUP): drop the latch and any backoff."""
        if self._s.latch is not None or self._s.blocked_until:
            _LOG.warning("%s: login state reset (%s)", self.name, reason)
        self._s = _State(logins=self._s.logins)
        self._announced = False
        self._save()

    def set_password_fp(self, fingerprint: str) -> None:
        self._password_fp = fingerprint
        self._expire(self._clock.time())

    # --- internals ------------------------------------------------------------

    def _expire(self, now: float) -> None:
        s = self._s
        if (
            s.latch is Latch.REFUSED
            and s.latched_at is not None
            and now - s.latched_at >= NODE_REFUSAL_HOLD_S
        ):
            self.clear_latch("24 h refusal hold elapsed")
        elif (
            s.latch is Latch.CREDENTIALS
            and s.password_fp is not None
            and self._password_fp is not None
            and s.password_fp != self._password_fp
        ):
            self.clear_latch("password changed")

    def _latch(self, latch: Latch, now: float, failure: Failure) -> None:
        s = self._s
        s.latch, s.latched_at, s.last_probe = latch, now, now
        s.password_fp = self._password_fp if latch is Latch.CREDENTIALS else None
        self._save()
        if latch is Latch.REFUSED:
            _LOG.warning(
                "%s: refused (%s, %s); per_node off for this node for 24 h",
                self.name,
                failure.outcome,
                failure.detail,
            )
        elif latch is Latch.CREDENTIALS:
            _LOG.error(
                "%s: router refused the credentials (%s); no login until the "
                "password file changes or SIGHUP",
                self.name,
                failure.detail,
            )
        else:
            self._announce(f"router requires {latch} ({failure.detail})")

    def _announce(self, what: str) -> None:
        if (
            self._s.latch in (Latch.CAPTCHA, Latch.RESET_REQUIRED)
            and not self._announced
        ):
            self._announced = True
            _LOG.critical(
                "%s: %s; logins stop, a credential-free probe runs hourly, "
                "SIGHUP after fixing it on the router",
                self.name,
                what,
            )

    def _block(self, now: float, until: float, failure: Failure) -> None:
        s = self._s
        s.blocked_until = max(s.blocked_until, min(until, now + MAX_HOLD_S))
        self._save()
        _LOG.warning(
            "%s: %s (%s); next attempt in %.0f s",
            self.name,
            failure.outcome,
            failure.detail,
            s.blocked_until - now,
        )

    def _save(self) -> bool:
        try:
            self._store.put(self.name, self._s.dump())
        except statefile.StateFileError as exc:
            _LOG.error("%s: cannot persist login state: %s", self.name, exc)
            return False
        return True
