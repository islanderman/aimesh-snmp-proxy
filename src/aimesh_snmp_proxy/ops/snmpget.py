"""SNMP queries of one proxy endpoint: GET and GETBULK walks, v2c or v3.

``onboard --force`` runs :func:`get_identity` before it sets ``force_add``:
LibreNMS then skips its own checks, so this GET proves the node answers.
``selftest`` awaits :func:`get` and :func:`walk` in the loop that runs its
engines. Errors never echo pysnmp text, which can hold the community.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
from collections.abc import AsyncIterator, Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    bulk_cmd,
    get_cmd,
)
from pysnmp.proto import rfc1902, rfc1905

from aimesh_snmp_proxy.logsafe import SecretStr
from aimesh_snmp_proxy.snmp.engines import AUTH_PROTOCOLS, PRIV_PROTOCOLS, V3User

SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
TIMEOUT_S = 2.0
RETRIES = 1
MAX_WALK_ROWS = 10_000
BULK_REPETITIONS = 25
_GUARD_S = 2.0  # slack on top of pysnmp's own timeout x attempts
# pysnmp execs MIB modules found through these variables (security finding L3).
_MIB_ENV = ("PYSNMP_MIB_PKGS", "PYSNMP_MIB_DIRS", "PYSNMP_MIB_DIR")

Credentials = SecretStr | V3User  # a v2c community, or a v3 authPriv user


class SnmpCheckError(RuntimeError):
    """A query failed; the message never holds a community or a key."""


@dataclass(frozen=True)
class Identity:
    """What the endpoint says it is: an OID, and its sysName when served."""

    sys_object_id: str
    sys_name: str | None


def _auth(credentials: Credentials) -> CommunityData | UsmUserData:
    if isinstance(credentials, V3User):
        return UsmUserData(
            credentials.user,
            credentials.auth_key.get_secret_value(),
            credentials.priv_key.get_secret_value(),
            authProtocol=AUTH_PROTOCOLS[credentials.auth],
            privProtocol=PRIV_PROTOCOLS[credentials.priv],
        )
    # S508: v2c is the design choice for loopback-only SNMP (security L1).
    return CommunityData(credentials.get_secret_value(), mpModel=1)  # noqa: S508


@contextlib.asynccontextmanager
async def _client(
    host: str, port: int, timeout: float, retries: int
) -> AsyncIterator[tuple[SnmpEngine, UdpTransportTarget]]:
    """One client engine for a burst of requests; pysnmp text never escapes."""
    for name in _MIB_ENV:
        os.environ.pop(name, None)
    snmp = SnmpEngine()
    try:
        target = await UdpTransportTarget.create(
            (host, port), timeout=timeout, retries=retries
        )
        yield snmp, target
    except (SnmpCheckError, asyncio.CancelledError):
        raise
    except Exception as exc:  # pysnmp raises many types; never echo their text
        raise SnmpCheckError(f"SNMP request failed: {type(exc).__name__}") from None
    finally:
        snmp.close_dispatcher()


def _check(
    error: Any, status: Any, index: Any, where: str, timeout: float, retries: int
) -> None:
    if error is not None:
        tries = retries + 1
        raise SnmpCheckError(
            f"no SNMP reply from {where} "
            f"({tries} {'try' if tries == 1 else 'tries'} of {timeout:g} s)"
        )
    if int(status):
        raise SnmpCheckError(f"SNMP error {status.prettyPrint()} at varbind {index}")


async def get(
    host: str,
    port: int,
    credentials: Credentials,
    oids: Sequence[str],
    *,
    timeout: float = TIMEOUT_S,
    retries: int = RETRIES,
) -> dict[str, Any]:
    """GET ``oids`` in one request; values keyed by dotted OID, in request order."""
    async with _client(host, port, timeout, retries) as (snmp, target):
        error, status, index, var_binds = await get_cmd(
            snmp,
            _auth(credentials),
            target,
            ContextData(),
            *(ObjectType(ObjectIdentity(oid.strip("."))) for oid in oids),
            lookupMib=False,
        )
    _check(error, status, index, f"{host}:{port}", timeout, retries)
    return {str(name): value for name, value in var_binds}


async def walk(
    host: str,
    port: int,
    credentials: Credentials,
    root: str,
    *,
    timeout: float = TIMEOUT_S,
    retries: int = RETRIES,
    max_rows: int = MAX_WALK_ROWS,
) -> list[tuple[str, Any]]:
    """Every row under ``root`` by GETBULK, in OID order."""
    prefix = tuple(int(part) for part in root.strip(".").split("."))
    rows: list[tuple[str, Any]] = []
    cursor = prefix
    async with _client(host, port, timeout, retries) as (snmp, target):
        auth = _auth(credentials)
        while True:
            error, status, index, table = await bulk_cmd(
                snmp,
                auth,
                target,
                ContextData(),
                0,
                BULK_REPETITIONS,
                ObjectType(ObjectIdentity(cursor)),
                lookupMib=False,
            )
            _check(error, status, index, f"{host}:{port}", timeout, retries)
            if not table:
                return rows
            for name, value in table:
                oid = tuple(name)
                end = value.tagSet == rfc1905.endOfMibView.tagSet
                if end or oid[: len(prefix)] != prefix:
                    return rows
                if oid <= cursor:
                    raise SnmpCheckError(f"{host}:{port}: OIDs are not increasing")
                rows.append((".".join(map(str, oid)), value))
                if len(rows) > max_rows:
                    raise SnmpCheckError(f"{host}:{port}: more than {max_rows} rows")
                cursor = oid


def get_identity(
    host: str,
    port: int,
    community: SecretStr,
    *,
    timeout: float = TIMEOUT_S,
    retries: int = RETRIES,
) -> Identity:
    """GET sysObjectID.0 and sysName.0 from outside any event loop."""
    limit = timeout * (retries + 1) + _GUARD_S
    query = get(
        host,
        port,
        community,
        [SYS_OBJECT_ID, SYS_NAME],
        timeout=timeout,
        retries=retries,
    )
    try:
        values = asyncio.run(asyncio.wait_for(query, limit))
    except SnmpCheckError:
        raise
    except TimeoutError:
        raise SnmpCheckError(f"no SNMP reply from {host}:{port}") from None
    except Exception as exc:  # never echo the text of an unexpected error
        raise SnmpCheckError(f"SNMP GET failed: {type(exc).__name__}") from None
    return _parse(values.items())


def _parse(var_binds: Iterable[tuple[Any, Any]]) -> Identity:
    values = {str(name): value for name, value in var_binds}
    oid = values.get(SYS_OBJECT_ID)
    if oid is None or oid.tagSet != rfc1902.ObjectIdentifier.tagSet:
        raise SnmpCheckError("no sysObjectID.0 in the answer")
    return Identity(str(oid), text(values.get(SYS_NAME)))


def text(value: Any) -> str | None:
    """An OCTET STRING as lenient UTF-8; None for any other type or an exception."""
    if value is None or value.tagSet != rfc1902.OctetString.tagSet:
        return None
    return bytes(value.asOctets()).decode("utf-8", "replace")
