import asyncio
import os
import socket
import threading

import pytest
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity import config, engine
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.proto import rfc1902, rfc1905

from aimesh_snmp_proxy.logsafe import SecretStr
from aimesh_snmp_proxy.ops import snmpget
from aimesh_snmp_proxy.ops.snmpget import Identity, SnmpCheckError, get_identity
from aimesh_snmp_proxy.snmp.engines import V3User

MERLIN_OID = "1.3.6.1.4.1.8072.3.2.10"
V3_AUTH = "canary-v3-auth-key-81"
V3_PRIV = "canary-v3-priv-key-82"


def _free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Agent:
    """A pysnmp agent on 127.0.0.1 in its own thread and event loop.

    v2c with ``community``; ``v3=True`` adds the canary SHA-256/AES-128 user.
    """

    def __init__(
        self, community, sys_name, sys_oid=MERLIN_OID, view=(1, 3, 6), v3=False
    ):
        self.port = _free_udp_port()
        self._args = (community, sys_name, sys_oid, view)
        self._v3 = v3
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        assert self._ready.wait(5)

    def _run(self):
        asyncio.set_event_loop(self._loop)
        community, sys_name, sys_oid, view = self._args
        snmp = engine.SnmpEngine()
        transport = udp.UdpTransport().open_server_mode(("127.0.0.1", self.port))
        config.add_transport(snmp, udp.DOMAIN_NAME, transport)
        config.add_v1_system(snmp, "area", community)
        config.add_vacm_user(snmp, 2, "area", "noAuthNoPriv", view)
        if self._v3:
            config.add_v3_user(
                snmp,
                "librenms",
                config.USM_AUTH_HMAC192_SHA256,
                V3_AUTH,
                config.USM_PRIV_CFB128_AES,
                V3_PRIV,
            )
            config.add_vacm_user(snmp, 3, "librenms", "authPriv", view)
        ctx = context.SnmpContext(snmp)
        builder = ctx.get_mib_instrum().get_mib_builder()
        name, oid = builder.import_symbols("__SNMPv2-MIB", "sysName", "sysObjectID")
        name.syntax = name.syntax.clone(sys_name)
        oid.syntax = oid.syntax.clone(sys_oid)
        cmdrsp.GetCommandResponder(snmp, ctx)
        cmdrsp.NextCommandResponder(snmp, ctx)
        cmdrsp.BulkCommandResponder(snmp, ctx)
        self._loop.call_soon(self._ready.set)
        self._loop.run_forever()
        snmp.close_dispatcher()

    def stop(self):
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(5)


@pytest.fixture
def community(canaries):
    return SecretStr(canaries["snmp_community"])


@pytest.fixture
def agent(community):
    running = Agent(community.get_secret_value(), "aimesh-000001")
    yield running
    running.stop()


def test_get_identity_reads_sys_object_id_and_sys_name(agent, community):
    found = get_identity("127.0.0.1", agent.port, community, timeout=1, retries=0)
    assert found == Identity(MERLIN_OID, "aimesh-000001")


def test_a_silent_port_times_out(community):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as silent:
        silent.bind(("127.0.0.1", 0))
        port = silent.getsockname()[1]
        with pytest.raises(
            SnmpCheckError, match=rf"no SNMP reply from 127\.0\.0\.1:{port}"
        ):
            get_identity("127.0.0.1", port, community, timeout=0.2, retries=0)


def test_a_wrong_community_times_out_without_echoing_it(agent, canaries):
    wrong = SecretStr("wrong-community-77")
    with pytest.raises(SnmpCheckError) as caught:
        get_identity("127.0.0.1", agent.port, wrong, timeout=0.2, retries=0)
    assert "wrong-community-77" not in str(caught.value)
    assert canaries["snmp_community"] not in str(caught.value)


def test_an_snmp_error_status_is_reported(community):
    restricted = Agent(community.get_secret_value(), "x", view=(1, 3, 6, 1, 2, 1, 1, 5))
    try:
        with pytest.raises(SnmpCheckError, match="noAccess"):
            get_identity("127.0.0.1", restricted.port, community, timeout=1, retries=0)
    finally:
        restricted.stop()


def test_pysnmp_mib_path_variables_are_dropped_before_the_engine_starts(
    agent, community, monkeypatch, tmp_path
):
    for name in ("PYSNMP_MIB_PKGS", "PYSNMP_MIB_DIRS", "PYSNMP_MIB_DIR"):
        monkeypatch.setenv(name, str(tmp_path))
    get_identity("127.0.0.1", agent.port, community, timeout=1, retries=0)
    assert not {"PYSNMP_MIB_PKGS", "PYSNMP_MIB_DIRS", "PYSNMP_MIB_DIR"} & set(
        os.environ
    )


def test_an_unexpected_exception_is_reported_by_type_only(community, monkeypatch):
    async def boom(*args, **kwargs):
        raise RuntimeError(f"secret {community.get_secret_value()}")

    monkeypatch.setattr(snmpget, "get_cmd", boom)
    with pytest.raises(SnmpCheckError, match="RuntimeError") as caught:
        get_identity("127.0.0.1", 1, community)
    assert community.get_secret_value() not in str(caught.value)


# --- async get and walk ------------------------------------------------------------


def test_get_returns_each_value_by_oid(agent, community):
    oids = [snmpget.SYS_DESCR, snmpget.SYS_NAME]
    values = asyncio.run(
        snmpget.get("127.0.0.1", agent.port, community, oids, timeout=1, retries=0)
    )
    assert list(values) == oids
    assert str(values[snmpget.SYS_NAME]) == "aimesh-000001"


def test_get_and_walk_accept_a_v3_user(community):
    v3 = Agent(community.get_secret_value(), "aimesh-v3", v3=True)
    user = V3User("librenms", SecretStr(V3_AUTH), SecretStr(V3_PRIV))
    try:
        values = asyncio.run(
            snmpget.get("127.0.0.1", v3.port, user, [snmpget.SYS_NAME], timeout=1)
        )
        rows = asyncio.run(
            snmpget.walk("127.0.0.1", v3.port, user, "1.3.6.1.2.1.1", timeout=1)
        )
    finally:
        v3.stop()
    assert str(values[snmpget.SYS_NAME]) == "aimesh-v3"
    assert snmpget.SYS_NAME in [oid for oid, _ in rows]


def _key(oid):
    return tuple(int(part) for part in oid.split("."))


def test_walk_returns_the_subtree_in_order(agent, community):
    rows = asyncio.run(
        snmpget.walk(
            "127.0.0.1", agent.port, community, "1.3.6.1.2.1.1", timeout=1, retries=0
        )
    )
    oids = [oid for oid, _ in rows]
    assert oids == sorted(oids, key=_key)
    assert all(oid.startswith("1.3.6.1.2.1.1.") for oid in oids)
    assert {snmpget.SYS_DESCR, snmpget.SYS_OBJECT_ID, snmpget.SYS_NAME} <= set(oids)


def test_walk_runs_to_the_end_of_the_view(agent, community):
    everything = asyncio.run(
        snmpget.walk("127.0.0.1", agent.port, community, ".1.3.6", timeout=1)
    )
    system = asyncio.run(
        snmpget.walk("127.0.0.1", agent.port, community, "1.3.6.1.2.1.1", timeout=1)
    )
    assert len(everything) > len(system)


def test_walk_caps_the_row_count(agent, community):
    with pytest.raises(SnmpCheckError, match="more than 3 rows"):
        asyncio.run(
            snmpget.walk(
                "127.0.0.1", agent.port, community, "1.3.6", timeout=1, max_rows=3
            )
        )


def test_walk_refuses_oids_that_do_not_increase(community, monkeypatch):
    same = rfc1902.ObjectName("1.3.6.1.2.1.1.1.0")

    async def looping(*args, **kwargs):
        return None, 0, 0, [(same, rfc1902.OctetString("x"))] * 2

    monkeypatch.setattr(snmpget, "bulk_cmd", looping)
    with pytest.raises(SnmpCheckError, match="not increasing"):
        asyncio.run(snmpget.walk("127.0.0.1", 1, community, "1.3.6", timeout=1))


def test_walk_of_a_silent_port_times_out(community):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as silent:
        silent.bind(("127.0.0.1", 0))
        port = silent.getsockname()[1]
        with pytest.raises(SnmpCheckError, match="no SNMP reply"):
            asyncio.run(
                snmpget.walk("127.0.0.1", port, community, "1.3.6", timeout=0.2)
            )


def test_async_failures_never_echo_exception_text(community, monkeypatch):
    async def boom(*args, **kwargs):
        raise RuntimeError(f"secret {community.get_secret_value()}")

    monkeypatch.setattr(snmpget, "get_cmd", boom)
    with pytest.raises(SnmpCheckError, match="RuntimeError") as caught:
        asyncio.run(snmpget.get("127.0.0.1", 1, community, [snmpget.SYS_NAME]))
    assert community.get_secret_value() not in str(caught.value)


# --- parsing the answer ----------------------------------------------------------


def _vb(oid, value):
    return rfc1902.ObjectName(oid), value


def test_parse_accepts_a_missing_sys_name():
    found = snmpget._parse(
        [
            _vb(snmpget.SYS_OBJECT_ID, rfc1902.ObjectIdentifier(MERLIN_OID)),
            _vb(snmpget.SYS_NAME, rfc1905.NoSuchObject()),
        ]
    )
    assert found == Identity(MERLIN_OID, None)


@pytest.mark.parametrize(
    "value",
    [rfc1905.NoSuchObject(), rfc1905.NoSuchInstance(), rfc1902.OctetString("x")],
)
def test_parse_requires_an_object_identifier(value):
    with pytest.raises(SnmpCheckError, match=r"no sysObjectID\.0"):
        snmpget._parse([_vb(snmpget.SYS_OBJECT_ID, value)])


def test_parse_decodes_utf8_sys_names_leniently():
    found = snmpget._parse(
        [
            _vb(snmpget.SYS_OBJECT_ID, rfc1902.ObjectIdentifier(MERLIN_OID)),
            _vb(snmpget.SYS_NAME, rfc1902.OctetString(b"caf\xc3\xa9\xff")),
        ]
    )
    assert found.sys_name == "café�"
