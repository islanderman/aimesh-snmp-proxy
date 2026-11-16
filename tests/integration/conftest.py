"""Loopback fixtures: a fake snapshot source, sample snapshots, specs, and clients.

Every server here binds 127.0.0.1 only. Secrets are canaries, never real keys.
"""

from __future__ import annotations

import asyncio
import socket
import time
from collections.abc import Callable, Coroutine
from typing import Any

import pysnmp.hlapi.v3arch.asyncio as hlapi
import pytest
from pysnmp.proto import rfc1905

from aimesh_snmp_proxy.logsafe import SecretStr
from aimesh_snmp_proxy.model import (
    Backhaul,
    Link,
    NodeSnapshot,
    Radio,
    Stat,
    Temperature,
)
from aimesh_snmp_proxy.snmp.engines import BIND_ADDRESS, EngineSpec, V3User

CANARY_COMMUNITY = "canary-loop-community-71"
CANARY_AUTH_KEY = "canary-loop-auth-key-72"
CANARY_PRIV_KEY = "canary-priv-aaaaaaaa"
V3_USER = "librenms"


class FakeSource:
    """The collector store's contract: a snapshot per node, or None when SILENT."""

    def __init__(self) -> None:
        self.snapshots: dict[str, NodeSnapshot] = {}

    def current(self, node_id: str) -> NodeSnapshot | None:
        return self.snapshots.get(node_id)


def _snapshot(node_id: str = "aimesh-0053a1", **overrides: Any) -> NodeSnapshot:
    fields: dict[str, Any] = {
        "node_id": node_id,
        "sys_name": "from-snapshot",
        "mac": "00:00:5e:00:53:01",
        "online": True,
        "role": "node",
        "level": 1,
        "collected_at": time.monotonic(),
        "model": "RT-AX58U",
        "firmware": "3.0.0.4.388_10000",
        "uptime_s": 86_400,
        "cpu_pct": 12.0,
        "mem_pct": 40.0,
        "temps_c": (Temperature("cpu", 58.5),),
        "backhaul": Backhaul(
            medium="wireless", band="5g1", rssi_dbm=-58, link_bps=10**9
        ),
        "radios": (
            Radio(
                0,
                "2g1",
                "00:00:5e:00:53:10",
                True,
                clients=2,
                freq_mhz=2437,
                client_rssi_dbm=Stat(-70, -60, -50),
                client_tx_bps=Stat(1_000_000, 6_000_000, 11_000_000),
                client_rx_bps=Stat(2_000_000, 7_000_000, 12_000_000),
            ),
            Radio(1, "5g1", "00:00:5e:00:53:11", True, clients=0, freq_mhz=5180),
        ),
        "links": (
            Link("wired", in_octets=1_000, out_octets=2_000),
            Link("backhaul", in_octets=2**33, out_octets=5),
            Link("wl0", in_octets=10, out_octets=20),
        ),
    }
    fields.update(overrides)
    return NodeSnapshot(**fields)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((BIND_ADDRESS, 0))
        return sock.getsockname()[1]


@pytest.fixture
def source() -> FakeSource:
    return FakeSource()


@pytest.fixture
def snapshot() -> Callable[..., NodeSnapshot]:
    return _snapshot


@pytest.fixture
def make_spec() -> Callable[..., EngineSpec]:
    """A spec on a free port with the canary community and a v3 user."""

    def _make(
        node_id: str = "aimesh-0053a1",
        mac: str = "00:00:5e:00:53:01",
        auth: str = "SHA-256",
        **overrides: Any,
    ) -> EngineSpec:
        fields: dict[str, Any] = {
            "node_id": node_id,
            "sys_name": node_id,
            "mac": mac,
            "port": _free_port(),
            "community": SecretStr(CANARY_COMMUNITY),
            "v3": V3User(
                V3_USER,
                SecretStr(CANARY_AUTH_KEY),
                SecretStr(CANARY_PRIV_KEY),
                auth=auth,
            ),
        }
        fields.update(overrides)
        return EngineSpec(**fields)

    return _make


@pytest.fixture
def run() -> Callable[[Coroutine[Any, Any, Any]], Any]:
    return asyncio.run


# v2c on loopback is the lead's default; the degraded entries below are negative tests.
V2C = hlapi.CommunityData(CANARY_COMMUNITY, mpModel=1)  # noqa: S508
V3_SHA256 = hlapi.UsmUserData(
    V3_USER,
    CANARY_AUTH_KEY,
    CANARY_PRIV_KEY,
    authProtocol=hlapi.USM_AUTH_HMAC192_SHA256,
    privProtocol=hlapi.USM_PRIV_CFB128_AES,
)


class PySnmpClient:
    """A pysnmp manager talking to one loopback port; values come back raw."""

    def __init__(self, port: int, auth: Any = V2C, timeout: float = 0.5) -> None:
        self.port = port
        self.auth = auth
        self.timeout = timeout

    async def __aenter__(self) -> PySnmpClient:
        self.engine = hlapi.SnmpEngine()
        self.target = await hlapi.UdpTransportTarget.create(
            (BIND_ADDRESS, self.port), timeout=self.timeout, retries=0
        )
        return self

    async def __aexit__(self, *exc: object) -> None:
        self.engine.close_dispatcher()

    @staticmethod
    def _types(oids: tuple[tuple[int, ...], ...]) -> list[hlapi.ObjectType]:
        return [hlapi.ObjectType(hlapi.ObjectIdentity(oid)) for oid in oids]

    async def get(self, *oids: tuple[int, ...]) -> tuple:
        return await hlapi.get_cmd(
            self.engine,
            self.auth,
            self.target,
            hlapi.ContextData(),
            *self._types(oids),
            lookupMib=False,
        )

    async def bulk(
        self, non_repeaters: int, reps: int, *oids: tuple[int, ...]
    ) -> tuple:
        return await hlapi.bulk_cmd(
            self.engine,
            self.auth,
            self.target,
            hlapi.ContextData(),
            non_repeaters,
            reps,
            *self._types(oids),
            lookupMib=False,
        )

    async def set(self, oid: tuple[int, ...], value: Any) -> tuple:
        return await hlapi.set_cmd(
            self.engine,
            self.auth,
            self.target,
            hlapi.ContextData(),
            hlapi.ObjectType(hlapi.ObjectIdentity(oid), value),
            lookupMib=False,
        )

    async def walk(self) -> list[tuple[tuple[int, ...], Any]]:
        """Every row from the top, by GETBULK, until endOfMibView."""
        rows: list[tuple[tuple[int, ...], Any]] = []
        cursor: tuple[int, ...] = (1, 0)  # LLDP-MIB is at 1.0.8802, before 1.3.6
        while True:
            err, status, _, var_binds = await self.bulk(0, 25, cursor)
            assert not err, err
            assert not int(status), status
            for name, value in var_binds:
                if value.tagSet == rfc1905.endOfMibView.tagSet:
                    return rows
                rows.append((tuple(name), value))
            cursor = rows[-1][0]


@pytest.fixture
def client() -> type[PySnmpClient]:
    return PySnmpClient


@pytest.fixture
def auth() -> Any:
    """Client credentials by name: ``v2c``, ``v3``, and degraded variants."""
    return {
        "v2c": V2C,
        "v3": V3_SHA256,
        "v1": hlapi.CommunityData(CANARY_COMMUNITY, mpModel=0),  # noqa: S508
        "wrong-community": hlapi.CommunityData("wrong", mpModel=1),  # noqa: S508
        "v3-auth-no-priv": hlapi.UsmUserData(
            V3_USER, CANARY_AUTH_KEY, authProtocol=hlapi.USM_AUTH_HMAC192_SHA256
        ),
        "v3-no-auth": hlapi.UsmUserData(V3_USER),  # noqa: S509
        "v3-unknown-user": hlapi.UsmUserData(
            "intruder",
            CANARY_AUTH_KEY,
            CANARY_PRIV_KEY,
            authProtocol=hlapi.USM_AUTH_HMAC192_SHA256,
            privProtocol=hlapi.USM_PRIV_CFB128_AES,
        ),
    }
