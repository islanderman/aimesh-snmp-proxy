"""The serving layer end to end over loopback UDP, driven by a pysnmp manager."""

import logging

import pytest
from pysnmp.proto import rfc1902

from aimesh_snmp_proxy.model import Neighbor
from aimesh_snmp_proxy.profiles import PROFILES
from aimesh_snmp_proxy.snmp.engines import SnmpServer
from aimesh_snmp_proxy.snmp.oidtable import MAX_BULK_VARBINDS

SYS_OBJECT_ID = (1, 3, 6, 1, 2, 1, 1, 2, 0)
SYS_UPTIME = (1, 3, 6, 1, 2, 1, 1, 3, 0)
SYS_NAME = (1, 3, 6, 1, 2, 1, 1, 5, 0)
MERLIN_INFO = (1, 3, 6, 1, 4, 1, 2021, 7890, 1, 101, 1)
LLDP_LOC_SYS_NAME = (1, 0, 8802, 1, 1, 2, 1, 3, 3, 0)
LLDP_REM_SYS_NAME = (1, 0, 8802, 1, 1, 2, 1, 4, 1, 1, 9, 0, 2, 1)
TIMEOUT = "No SNMP response received before timeout"


def values(var_binds):
    return {tuple(name): value for name, value in var_binds}


def test_a_serving_node_answers_v2c(run, source, snapshot, make_spec, client, tmp_path):
    spec = make_spec()
    source.snapshots[spec.node_id] = snapshot()

    async def scenario():
        async with SnmpServer(source, state_dir=tmp_path) as server:
            await server.add(spec)
            async with client(spec.port) as c:
                return await c.get(SYS_NAME, SYS_OBJECT_ID, MERLIN_INFO)

    err, status, _, var_binds = run(scenario())
    assert not err
    assert int(status) == 0
    got = values(var_binds)
    assert bytes(got[SYS_NAME]) == spec.sys_name.encode()  # the spec wins
    assert tuple(got[SYS_OBJECT_ID]) == (1, 3, 6, 1, 4, 1, 8072, 3, 2, 10)
    assert bytes(got[MERLIN_INFO]) == b"ASUSWRT-Merlin RT-AX58U 3.0.0.4.388_10000"


@pytest.mark.parametrize("auth_name", ["v2c", "v3"])
def test_a_silent_node_never_answers(
    run, source, make_spec, client, auth, tmp_path, auth_name
):
    spec = make_spec()

    async def scenario():
        async with SnmpServer(source, state_dir=tmp_path) as server:
            await server.add(spec)
            async with client(spec.port, auth[auth_name]) as c:
                return await c.get(SYS_NAME)

    err, _, _, var_binds = run(scenario())
    assert str(err) == TIMEOUT  # v3 too: no discovery Report leaks
    assert not var_binds


def test_v3_sha256_aes128(run, source, snapshot, make_spec, client, auth, tmp_path):
    spec = make_spec(auth="SHA-256")
    source.snapshots[spec.node_id] = snapshot()

    async def scenario():
        async with SnmpServer(source, state_dir=tmp_path) as server:
            await server.add(spec)
            async with client(spec.port, auth["v3"]) as c:
                return await c.get(SYS_NAME)

    err, status, _, var_binds = run(scenario())
    assert not err
    assert int(status) == 0
    assert bytes(values(var_binds)[SYS_NAME]) == spec.sys_name.encode()


@pytest.mark.parametrize(
    "auth_name",
    ["wrong-community", "v3-unknown-user", "v3-no-auth", "v3-auth-no-priv", "v1"],
)
def test_weaker_or_wrong_credentials_get_no_data(
    run, source, snapshot, make_spec, client, auth, tmp_path, auth_name
):
    spec = make_spec()
    source.snapshots[spec.node_id] = snapshot()

    async def scenario():
        async with SnmpServer(source, state_dir=tmp_path) as server:
            await server.add(spec)
            async with client(spec.port, auth[auth_name]) as c:
                return await c.get(SYS_NAME)

    err, status, _, var_binds = run(scenario())
    assert err or int(status) != 0
    leaked = [v for _, v in var_binds if isinstance(v, rfc1902.OctetString)]
    assert spec.sys_name.encode() not in [bytes(v) for v in leaked]


@pytest.mark.parametrize("auth_name", ["v3-auth-no-priv", "v3-no-auth"])
def test_v3_below_auth_priv_is_refused(
    run, source, snapshot, make_spec, client, auth, tmp_path, auth_name
):
    spec = make_spec()
    source.snapshots[spec.node_id] = snapshot()

    async def scenario():
        async with SnmpServer(source, state_dir=tmp_path) as server:
            await server.add(spec)
            async with client(spec.port, auth[auth_name]) as c:
                return await c.get(SYS_NAME)

    err, _, _, var_binds = run(scenario())
    assert str(err) == "Unsupported SNMP security level"
    assert not var_binds


def test_walk_returns_the_rendered_table_in_order(
    run, source, snapshot, make_spec, client, tmp_path
):
    spec = make_spec()
    snap = snapshot()
    source.snapshots[spec.node_id] = snap

    async def scenario():
        async with SnmpServer(source, state_dir=tmp_path) as server:
            await server.add(spec)
            async with client(spec.port) as c:
                return await c.walk()

    rows = run(scenario())
    expected = PROFILES[spec.profile].render(snap, sys_name=spec.sys_name)
    oids = [oid for oid, _ in rows]
    assert oids == sorted(oid for oid, _ in expected)
    assert len(set(oids)) == len(oids)
    served = dict(rows)
    for oid, value in expected:
        if oid not in (SYS_UPTIME, (1, 3, 6, 1, 2, 1, 25, 1, 1, 0)):
            assert served[oid] == value, oid
            assert served[oid].tagSet == value.tagSet, oid


def test_getbulk_is_capped_at_64_varbinds(
    run, source, snapshot, make_spec, client, tmp_path
):
    spec = make_spec()
    source.snapshots[spec.node_id] = snapshot()

    async def scenario():
        async with SnmpServer(source, state_dir=tmp_path) as server:
            await server.add(spec)
            async with client(spec.port) as c:
                return await c.bulk(0, 500, (1, 3, 6))

    err, status, _, var_binds = run(scenario())
    assert not err
    assert int(status) == 0
    assert len(var_binds) == MAX_BULK_VARBINDS == 64


def test_set_is_never_applied(run, source, snapshot, make_spec, client, tmp_path):
    spec = make_spec()
    source.snapshots[spec.node_id] = snapshot()

    async def scenario():
        async with SnmpServer(source, state_dir=tmp_path) as server:
            await server.add(spec)
            async with client(spec.port) as c:
                set_result = await c.set(SYS_NAME, rfc1902.OctetString(b"pwned"))
                get_result = await c.get(SYS_NAME)
                return set_result, get_result

    (set_err, set_status, _, _), (_, _, _, var_binds) = run(scenario())
    assert set_err or int(set_status) != 0
    assert bytes(values(var_binds)[SYS_NAME]) == spec.sys_name.encode()


def test_the_full_walk_exposes_no_secrets_or_engine_tables(
    run, source, snapshot, make_spec, client, tmp_path
):
    spec = make_spec()
    source.snapshots[spec.node_id] = snapshot()

    async def scenario():
        async with SnmpServer(source, state_dir=tmp_path) as server:
            await server.add(spec)
            async with client(spec.port) as c:
                return await c.walk()

    rows = run(scenario())
    blob = b"".join(bytes(v) for _, v in rows if isinstance(v, rfc1902.OctetString))
    for secret in (spec.community, spec.v3.auth_key, spec.v3.priv_key):
        assert secret.get_secret_value().encode() not in blob
    assert not [oid for oid, _ in rows if oid[:6] == (1, 3, 6, 1, 6, 3)]


@pytest.mark.parametrize("auth_name", ["v2c", "v3"])
def test_lldp_rows_are_readable_and_name_the_served_peer(
    run, source, snapshot, make_spec, client, auth, tmp_path, auth_name
):
    parent = make_spec("aimesh-root", mac="00:00:5e:00:53:01")
    child = make_spec("aimesh-005302", mac="00:00:5e:00:53:02")
    link = Neighbor("backhaul", parent.mac, "wl1", "192.168.50.1", "5g1")
    source.snapshots[child.node_id] = snapshot(
        child.node_id, mac=child.mac, neighbors=(link,)
    )

    async def scenario():
        async with SnmpServer(source, state_dir=tmp_path) as server:
            await server.add(parent)
            await server.add(child)
            async with client(child.port, auth[auth_name]) as c:
                return await c.get(LLDP_LOC_SYS_NAME, LLDP_REM_SYS_NAME)

    err, status, _, var_binds = run(scenario())
    assert not err
    assert int(status) == 0
    got = values(var_binds)
    assert bytes(got[LLDP_LOC_SYS_NAME]) == b"aimesh-005302"
    assert bytes(got[LLDP_REM_SYS_NAME]) == b"aimesh-root"  # the parent's spec name


def test_state_transitions_follow_the_source(
    run, source, snapshot, make_spec, client, tmp_path, caplog
):
    spec = make_spec()
    caplog.set_level(logging.INFO, logger="aimesh_snmp_proxy.snmp.engines")

    async def scenario():
        async with SnmpServer(source, state_dir=tmp_path) as server:
            await server.add(spec)
            async with client(spec.port) as c:
                silent = await c.get(SYS_NAME)
                source.snapshots[spec.node_id] = snapshot(uptime_s=None)
                first = await c.get(SYS_NAME)
                again = await c.get(SYS_NAME)
                del source.snapshots[spec.node_id]
                silent_again = await c.get(SYS_NAME)
                return silent, first, again, silent_again

    silent, first, again, silent_again = run(scenario())
    assert str(silent[0]) == TIMEOUT
    assert not first[0]
    assert not again[0]
    assert str(silent_again[0]) == TIMEOUT
    messages = [r.getMessage() for r in caplog.records]
    assert messages == [
        f"node {spec.node_id}: SNMP answering",
        f"node {spec.node_id}: SNMP silent",
    ]


def test_unknown_uptime_counts_from_when_the_node_started_answering(
    run, source, snapshot, make_spec, client, tmp_path
):
    spec = make_spec()
    clock = [5000.0]
    source.snapshots[spec.node_id] = snapshot(uptime_s=None, collected_at=5000.0)

    async def scenario():
        async with SnmpServer(
            source, state_dir=tmp_path, clock=lambda: clock[0]
        ) as server:
            await server.add(spec)
            async with client(spec.port) as c:
                await c.get(SYS_NAME)
                clock[0] = 5030.0
                source.snapshots[spec.node_id] = snapshot(
                    uptime_s=None, collected_at=5030.0
                )
                return await c.get(SYS_UPTIME)

    _, _, _, var_binds = run(scenario())
    assert int(values(var_binds)[SYS_UPTIME]) == 3000


def test_a_stale_snapshot_is_silent(run, source, snapshot, make_spec, client, tmp_path):
    spec = make_spec()
    clock = [10_000.0]
    source.snapshots[spec.node_id] = snapshot(collected_at=9_000.0)

    async def scenario():
        server = SnmpServer(
            source, state_dir=tmp_path, stale_after_s=180, clock=lambda: clock[0]
        )
        async with server:
            await server.add(spec)
            async with client(spec.port) as c:
                stale = await c.get(SYS_NAME)
                clock[0] = 9_100.0
                fresh = await c.get(SYS_NAME)
                return stale, fresh

    stale, fresh = run(scenario())
    assert str(stale[0]) == TIMEOUT
    assert not fresh[0]


def test_a_failing_source_means_silent(run, make_spec, client, tmp_path, caplog):
    class Broken:
        def current(self, node_id):
            raise RuntimeError("store exploded")

    spec = make_spec()

    async def scenario():
        async with SnmpServer(Broken(), state_dir=tmp_path) as server:
            await server.add(spec)
            async with client(spec.port) as c:
                return await c.get(SYS_NAME)

    err, _, _, _ = run(scenario())
    assert str(err) == TIMEOUT
    assert "snapshot source failed" in caplog.text


def test_a_snapshot_that_cannot_render_means_silent_and_logs_once(
    run, source, snapshot, make_spec, client, tmp_path, caplog, monkeypatch
):
    def broken_render(*args, **kwargs):
        raise ValueError("duplicate OID 1.3.6.1.2.1.1.5.0")

    monkeypatch.setattr(PROFILES["asuswrt-merlin"], "render", broken_render)
    spec = make_spec()
    source.snapshots[spec.node_id] = snapshot()

    async def scenario():
        async with SnmpServer(source, state_dir=tmp_path) as server:
            await server.add(spec)
            async with client(spec.port) as c:
                return [await c.get(SYS_NAME) for _ in range(2)]

    results = run(scenario())
    assert [str(r[0]) for r in results] == [TIMEOUT, TIMEOUT]
    assert caplog.text.count("cannot render") == 1


def test_nodes_are_independent(run, source, snapshot, make_spec, client, tmp_path):
    serving = make_spec("aimesh-0053a1", "00:00:5e:00:53:01")
    silent = make_spec("aimesh-0053a2", "00:00:5e:00:53:02")
    other = make_spec("aimesh-0053a3", "00:00:5e:00:53:03")
    source.snapshots[serving.node_id] = snapshot(serving.node_id)
    source.snapshots[other.node_id] = snapshot(other.node_id)

    async def scenario():
        async with SnmpServer(source, state_dir=tmp_path) as server:
            for spec in (serving, silent, other):
                await server.add(spec)
            results = []
            for spec in (serving, silent, other):
                async with client(spec.port) as c:
                    results.append(await c.get(SYS_NAME))
            return results

    a, b, c = run(scenario())
    assert bytes(values(a[3])[SYS_NAME]) == b"aimesh-0053a1"
    assert str(b[0]) == TIMEOUT
    assert bytes(values(c[3])[SYS_NAME]) == b"aimesh-0053a3"
