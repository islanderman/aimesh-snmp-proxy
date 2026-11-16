import asyncio
import logging
import socket

import pytest
from pysnmp import debug

from aimesh_snmp_proxy.logsafe import SecretStr
from aimesh_snmp_proxy.snmp.engines import (
    BIND_ADDRESS,
    EngineSpec,
    SnmpServer,
    V3User,
    cap_pysnmp_logging,
)

COMMUNITY = SecretStr("canary-unit-community-61")
AUTH_KEY = SecretStr("canary-unit-auth-62")
PRIV_KEY = SecretStr("canary-unit-priv-63")


def spec(**overrides):
    fields = {
        "node_id": "aimesh-0053a1",
        "sys_name": "aimesh-0053a1",
        "mac": "00:00:5e:00:53:01",
        "port": 16101,
        "community": COMMUNITY,
    }
    fields.update(overrides)
    return EngineSpec(**fields)


def v3(**overrides):
    fields = {"user": "librenms", "auth_key": AUTH_KEY, "priv_key": PRIV_KEY}
    fields.update(overrides)
    return V3User(**fields)


class NoSnapshots:
    def current(self, node_id):
        return None


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((BIND_ADDRESS, 0))
        return sock.getsockname()[1]


def test_engine_id_is_the_net_snmp_enterprise_plus_the_mac():
    s = spec(mac="00-00-5E-00-53-0A")
    assert s.mac == "00:00:5e:00:53:0a"
    assert s.engine_id == bytes.fromhex("80001f880300005e00530a")


def test_defaults():
    s = spec()
    assert s.profile == "asuswrt-merlin"
    assert s.v3 is None
    assert v3().auth == "SHA-256"
    assert v3().priv == "AES-128"


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"node_id": ""}, "node_id"),
        ({"sys_name": ""}, "sys_name"),
        ({"sys_name": "a\nb"}, "sys_name"),
        ({"sys_name": "x" * 256}, "sys_name"),
        ({"mac": "00:00:5e:00:53"}, "mac"),
        ({"port": 1023}, "port"),
        ({"port": 65536}, "port"),
        ({"port": True}, "port"),
        ({"port": "16101"}, "port"),
        ({"community": None}, "community or a v3 user"),
    ],
)
def test_invalid_specs_are_rejected(overrides, message):
    with pytest.raises(ValueError, match=message):
        spec(**overrides)


def test_secrets_must_be_secret_strings():
    with pytest.raises(TypeError, match="community"):
        spec(community="canary-plain-64")
    with pytest.raises(TypeError, match="auth_key"):
        v3(auth_key="canary-plain-65")


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"user": ""}, "user"),
        ({"user": "bad user"}, "user"),
        ({"user": "u" * 33}, "user"),
        ({"auth": "MD5"}, "auth"),
        ({"priv": "DES"}, "priv"),
        ({"auth_key": SecretStr("short")}, "auth_key"),
        ({"priv_key": SecretStr("1234567")}, "priv_key"),
    ],
)
def test_invalid_v3_users_are_rejected(overrides, message):
    with pytest.raises(ValueError, match=message):
        v3(**overrides)


@pytest.mark.parametrize("auth", ["SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"])
def test_supported_auth_protocols(auth):
    assert v3(auth=auth).auth == auth


def test_reprs_hide_secrets():
    text = repr(spec(v3=v3()))
    for secret in (COMMUNITY, AUTH_KEY, PRIV_KEY):
        assert secret.get_secret_value() not in text


@pytest.mark.parametrize(
    "bind", ["0.0.0.0", "127.0.0.2", "::1", "localhost", "192.168.50.10", ""]
)
def test_only_127_0_0_1_is_accepted(bind):
    with pytest.raises(ValueError, match=r"127\.0\.0\.1"):
        SnmpServer(NoSnapshots(), bind=bind)


@pytest.fixture
def pysnmp_logger():
    logger = logging.getLogger("pysnmp")
    saved = logger.level, list(logger.filters), debug.logger
    yield logger
    logger.setLevel(saved[0])
    logger.filters[:] = saved[1]
    debug.set_logger(saved[2])


def test_pysnmp_debug_is_capped_at_info(pysnmp_logger):
    debug.set_logger(debug.Debug("all", printer=lambda _msg: None))
    pysnmp_logger.setLevel(logging.DEBUG)
    cap_pysnmp_logging()
    cap_pysnmp_logging()
    assert debug.logger == 0
    assert pysnmp_logger.level == logging.INFO
    assert len(pysnmp_logger.filters) == len(set(pysnmp_logger.filters))
    pysnmp_logger.setLevel(logging.DEBUG)  # as pysnmp's own debug Printer does
    record = pysnmp_logger.makeRecord("pysnmp", logging.DEBUG, "f", 1, "pdu", (), None)
    assert not pysnmp_logger.filter(record)
    info = pysnmp_logger.makeRecord("pysnmp", logging.INFO, "f", 1, "ok", (), None)
    assert pysnmp_logger.filter(info)


def test_a_quieter_pysnmp_logger_stays_quiet(pysnmp_logger):
    pysnmp_logger.setLevel(logging.ERROR)
    cap_pysnmp_logging()
    assert pysnmp_logger.level == logging.ERROR


def test_creating_a_server_caps_pysnmp_logging(pysnmp_logger):
    debug.set_logger(debug.Debug("all", printer=lambda _msg: None))
    SnmpServer(NoSnapshots())
    assert debug.logger == 0


def run(coro):
    return asyncio.run(coro)


def test_add_refuses_duplicates_and_unknown_profiles(tmp_path):
    async def scenario():
        async with SnmpServer(NoSnapshots(), state_dir=tmp_path) as server:
            port = free_port()
            await server.add(spec(port=port))
            with pytest.raises(ValueError, match="already served"):
                await server.add(spec(port=free_port()))
            with pytest.raises(ValueError, match=f"port {port}"):
                await server.add(
                    spec(node_id="other", mac="00:00:5e:00:53:02", port=port)
                )
            with pytest.raises(ValueError, match="mac"):
                await server.add(spec(node_id="other", port=free_port()))
            with pytest.raises(ValueError, match="unknown profile"):
                await server.add(
                    spec(
                        node_id="other",
                        mac="00:00:5e:00:53:02",
                        port=free_port(),
                        profile="zebra",
                    )
                )

    run(scenario())


def test_add_reports_a_port_in_use(tmp_path):
    async def scenario():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as taken:
            taken.bind((BIND_ADDRESS, 0))
            port = taken.getsockname()[1]
            async with SnmpServer(NoSnapshots(), state_dir=tmp_path) as server:
                with pytest.raises(OSError, match=f"aimesh-0053a1.*127.0.0.1:{port}"):
                    await server.add(spec(port=port))
                # The failed node holds nothing: it can be added once the port is free.
                taken.close()
                await server.add(spec(port=port))

    run(scenario())


def test_a_failed_endpoint_leaves_nothing_registered(tmp_path, monkeypatch):
    async def scenario():
        loop = asyncio.get_running_loop()
        real = loop.create_datagram_endpoint

        async def broken(*args, **kwargs):
            raise RuntimeError("loop is closing")

        async with SnmpServer(NoSnapshots(), state_dir=tmp_path) as server:
            port = free_port()
            monkeypatch.setattr(loop, "create_datagram_endpoint", broken)
            with pytest.raises(RuntimeError, match="closing"):
                await server.add(spec(port=port))
            monkeypatch.setattr(loop, "create_datagram_endpoint", real)
            await server.add(spec(port=port))

    run(scenario())


def test_engine_boots_persist_under_the_state_dir(tmp_path):
    async def scenario():
        async with SnmpServer(NoSnapshots(), state_dir=tmp_path) as server:
            await server.add(spec(port=free_port()))

    run(scenario())
    boots = tmp_path / "__pysnmp" / "0x80001f880300005e005301" / "boots"
    first = int(boots.read_text())
    run(scenario())
    assert int(boots.read_text()) == first + 1


def test_close_is_idempotent_and_the_server_can_restart(tmp_path):
    async def scenario():
        server = SnmpServer(NoSnapshots(), state_dir=tmp_path)
        port = free_port()
        await server.add(spec(port=port))
        server.close()
        server.close()
        await asyncio.sleep(0)
        await server.add(spec(port=port))
        server.close()

    run(scenario())


def test_the_gate_drops_datagrams_for_unknown_transports():
    server = SnmpServer(NoSnapshots())
    assert server._route((1, 3, 6, 1, 6, 1, 1, 9), ("127.0.0.1", 1), b"") == "blackhole"
