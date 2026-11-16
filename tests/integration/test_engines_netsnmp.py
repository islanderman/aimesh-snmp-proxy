"""The serving layer against the local NET-SNMP command-line tools.

NET-SNMP 5.6.2.1 (as macOS ships it) lacks SHA-2, so v3 here is SHA-1/AES-128; the
pysnmp tests cover SHA-256. Skipped when the tools are not installed.
"""

import asyncio
import os
import shutil

import pytest

from aimesh_snmp_proxy.model import Neighbor
from aimesh_snmp_proxy.profiles import PROFILES
from aimesh_snmp_proxy.profiles.base import LLDP_MIB
from aimesh_snmp_proxy.snmp.engines import BIND_ADDRESS, SnmpServer
from aimesh_snmp_proxy.snmp.oidtable import OidTable, format_oid

TOOLS = {
    name: shutil.which(name)
    for name in ("snmpget", "snmpgetnext", "snmpbulkget", "snmpbulkwalk", "snmpset")
}
pytestmark = pytest.mark.skipif(
    not all(TOOLS.values()), reason="NET-SNMP command-line tools not installed"
)

COMMUNITY = "canary-loop-community-71"
AUTH_KEY = "canary-loop-auth-key-72"
PRIV_KEY = "canary-priv-aaaaaaaa"
SYS_NAME = ".1.3.6.1.2.1.1.5.0"
IF_DESCR = ".1.3.6.1.2.1.2.2.1.2"
END_OF_VIEW = "No more variables left in this MIB View"


def v2c(community=COMMUNITY):
    return ["-v2c", "-c", community]


def v3_sha1():
    return [
        "-v3",
        "-l",
        "authPriv",
        "-u",
        "librenms",
        "-a",
        "SHA",
        "-A",
        AUTH_KEY,
        "-x",
        "AES",
        "-X",
        PRIV_KEY,
    ]


@pytest.fixture
def net_snmp(tmp_path):
    """Run one tool against a port with numeric, unquoted-type output."""
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(tmp_path),
        "SNMPCONFPATH": str(tmp_path),
        "SNMP_PERSISTENT_DIR": str(tmp_path),
        "MIBS": "",
    }

    async def _run(tool, port, credentials, *oids, options=()):
        proc = await asyncio.create_subprocess_exec(
            TOOLS[tool],
            *credentials,
            *("-t", "1", "-r", "0", "-On", "-Oq", "-Oe", "-Ot"),
            *options,
            f"{BIND_ADDRESS}:{port}",
            *oids,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        out, err = await proc.communicate()
        return proc.returncode, out.decode(), err.decode()

    return _run


def served_oids(stdout):
    """OIDs of the printed rows, skipping endOfMibView markers."""
    return [
        line.split(" ", 1)[0]
        for line in stdout.splitlines()
        if line.startswith(".") and END_OF_VIEW not in line
    ]


def table_for(spec, snap):
    return OidTable(PROFILES[spec.profile].render(snap, sys_name=spec.sys_name))


def serve(source, spec, tmp_path, *commands):
    """Start one engine, run the commands in order, return their results."""

    async def scenario():
        async with SnmpServer(source, state_dir=tmp_path / "state") as server:
            await server.add(spec)
            return [await command() for command in commands]

    return asyncio.run(scenario())


def test_v2c_get(source, snapshot, make_spec, net_snmp, tmp_path):
    spec = make_spec()
    source.snapshots[spec.node_id] = snapshot()
    oids = [SYS_NAME, ".1.3.6.1.2.1.1.2.0", ".1.3.6.1.4.1.2021.7890.1.101.1"]
    [(code, out, err)] = serve(
        source, spec, tmp_path, lambda: net_snmp("snmpget", spec.port, v2c(), *oids)
    )
    assert code == 0, err
    assert out.splitlines() == [
        f'{SYS_NAME} "{spec.sys_name}"',
        ".1.3.6.1.2.1.1.2.0 .1.3.6.1.4.1.8072.3.2.10",
        '.1.3.6.1.4.1.2021.7890.1.101.1 "ASUSWRT-Merlin RT-AX58U 3.0.0.4.388_10000"',
    ]


def test_v3_sha1_aes128_get(source, snapshot, make_spec, net_snmp, tmp_path):
    spec = make_spec(auth="SHA-1")
    source.snapshots[spec.node_id] = snapshot()
    [(code, out, err)] = serve(
        source,
        spec,
        tmp_path,
        lambda: net_snmp("snmpget", spec.port, v3_sha1(), SYS_NAME),
    )
    assert code == 0, err
    assert out.strip() == f'{SYS_NAME} "{spec.sys_name}"'


@pytest.mark.parametrize("credentials", [v2c(), v3_sha1()], ids=["v2c", "v3"])
def test_a_silent_node_times_out(source, make_spec, net_snmp, tmp_path, credentials):
    spec = make_spec(auth="SHA-1")
    [(code, out, err)] = serve(
        source,
        spec,
        tmp_path,
        lambda: net_snmp("snmpget", spec.port, credentials, SYS_NAME),
    )
    assert code != 0
    assert out == ""
    assert "Timeout" in err


def test_a_wrong_community_times_out(source, snapshot, make_spec, net_snmp, tmp_path):
    spec = make_spec()
    source.snapshots[spec.node_id] = snapshot()
    [(code, _, err)] = serve(
        source,
        spec,
        tmp_path,
        lambda: net_snmp("snmpget", spec.port, v2c("guess"), SYS_NAME),
    )
    assert code != 0
    assert "Timeout" in err


def test_bulkwalk_returns_every_row_in_oid_order(
    source, snapshot, make_spec, net_snmp, tmp_path
):
    spec = make_spec()
    snap = snapshot()
    source.snapshots[spec.node_id] = snap
    [(code, out, err)] = serve(
        source,
        spec,
        tmp_path,
        lambda: net_snmp("snmpbulkwalk", spec.port, v2c(), ".1.3.6", options=["-Cr10"]),
    )
    assert code == 0, err
    expected = [
        "." + format_oid(oid)
        for oid, _ in table_for(spec, snap)
        if oid[:3] == (1, 3, 6)  # the walk's root; LLDP-MIB sits at 1.0.8802
    ]
    assert served_oids(out) == expected


def test_bulkwalk_of_the_lldp_mib_returns_its_rows(
    source, snapshot, make_spec, net_snmp, tmp_path
):
    spec = make_spec()
    link = Neighbor("backhaul", "00:00:5e:00:53:09", "wl1", "192.168.50.1", "5g1")
    snap = snapshot(neighbors=(link,))
    source.snapshots[spec.node_id] = snap
    [(code, out, err)] = serve(
        source,
        spec,
        tmp_path,
        lambda: net_snmp("snmpbulkwalk", spec.port, v2c(), ".1.0.8802.1.1.2"),
    )
    assert code == 0, err
    lldp = [oid for oid, _ in table_for(spec, snap) if oid[:6] == LLDP_MIB]
    assert served_oids(out) == ["." + format_oid(oid) for oid in lldp]
    assert any(".1.4.2.1.3.0.2.1.1.4.192.168.50.1" in line for line in out.splitlines())


def test_bulkwalk_of_a_table_column_stays_in_the_column(
    source, snapshot, make_spec, net_snmp, tmp_path
):
    spec = make_spec()
    source.snapshots[spec.node_id] = snapshot()
    [(code, out, err)] = serve(
        source,
        spec,
        tmp_path,
        lambda: net_snmp("snmpbulkwalk", spec.port, v2c(), IF_DESCR),
    )
    assert code == 0, err
    assert out.splitlines() == [
        f'{IF_DESCR}.1 "wired"',
        f'{IF_DESCR}.2 "backhaul"',
        f'{IF_DESCR}.10 "wl0"',
        f'{IF_DESCR}.11 "wl1"',
    ]


def test_getnext_and_get_follow_table_semantics(
    source, snapshot, make_spec, net_snmp, tmp_path
):
    spec = make_spec()
    source.snapshots[spec.node_id] = snapshot()
    results = serve(
        source,
        spec,
        tmp_path,
        lambda: net_snmp("snmpgetnext", spec.port, v2c(), IF_DESCR),
        lambda: net_snmp("snmpgetnext", spec.port, v2c(), f"{IF_DESCR}.2"),
        lambda: net_snmp("snmpget", spec.port, v2c(), f"{IF_DESCR}.99"),
    )
    (_, first, _), (_, after_two, _), (_, missing, _) = results
    assert first.strip() == f'{IF_DESCR}.1 "wired"'
    assert after_two.strip() == f'{IF_DESCR}.10 "wl0"'
    assert "No Such Object" in missing


def test_one_getbulk_returns_64_varbinds_like_the_table(
    source, snapshot, make_spec, net_snmp, tmp_path
):
    spec = make_spec()
    snap = snapshot()
    source.snapshots[spec.node_id] = snap
    [(code, out, err)] = serve(
        source,
        spec,
        tmp_path,
        lambda: net_snmp(
            "snmpbulkget", spec.port, v2c(), ".1.3.6", options=["-Cn0", "-Cr200"]
        ),
    )
    assert code == 0, err
    reference = table_for(spec, snap).get_bulk([(1, 3, 6)], 0, 200)
    assert len(reference) == 64
    assert served_oids(out) == ["." + format_oid(oid) for oid, _ in reference]


def test_set_is_refused_and_changes_nothing(
    source, snapshot, make_spec, net_snmp, tmp_path
):
    spec = make_spec()
    source.snapshots[spec.node_id] = snapshot()
    results = serve(
        source,
        spec,
        tmp_path,
        lambda: net_snmp("snmpset", spec.port, v2c(), SYS_NAME, "s", "pwned"),
        lambda: net_snmp("snmpget", spec.port, v2c(), SYS_NAME),
    )
    (set_code, _, _), (_, after, _) = results
    assert set_code != 0
    assert after.strip() == f'{SYS_NAME} "{spec.sys_name}"'
