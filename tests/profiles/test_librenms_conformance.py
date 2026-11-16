"""Conformance with LibreNMS's own asuswrt-merlin fixture, read at test time.

Set ``LIBRENMS_SRC`` to a LibreNMS checkout (or a directory holding
``asuswrt-merlin.snmprec``). No GPL fixture data is copied into this repo.
"""

import os
from pathlib import Path

import pytest

from aimesh_snmp_proxy.model import NodeSnapshot, Radio, Stat
from aimesh_snmp_proxy.profiles.asuswrt_merlin import AsuswrtMerlin
from aimesh_snmp_proxy.profiles.snmprec import snmprec
from aimesh_snmp_proxy.snmp.oidtable import OidTable

LIBRENMS_SRC = os.environ.get("LIBRENMS_SRC")
pytestmark = pytest.mark.skipif(
    not LIBRENMS_SRC, reason="set LIBRENMS_SRC to compare with LibreNMS fixtures"
)

FIXTURE_NAMES = ("tests/snmpsim/asuswrt-merlin.snmprec", "asuswrt-merlin.snmprec")
MERLIN_PREFIXES = ("1.3.6.1.4.1.2021.7890.", "1.3.6.1.4.1.8072.1.3.2.3.1.")
EXTEND_LINE = "1.3.6.1.4.1.8072.1.3.2.3.1.1."
NEVER_SERVED = {
    f"{kind}-{iface}{stat}"
    for iface in ("eth1", "eth2")
    for kind, stats in (("snr", ("-min", "-max", "-avg")), ("noise-floor", ("",)))
    for stat in stats
}

# The fixture device's facts: an RT-AC68U with 4 + 1 clients on eth1/eth2.
FIXTURE_DEVICE = NodeSnapshot(
    node_id="fixture",
    sys_name="fixture",
    mac="00:00:5e:00:53:01",
    online=True,
    role="router",
    level=0,
    collected_at=0.0,
    model="RT-AC68U",
    firmware="384.17_0",
    radios=(
        Radio(
            0,
            "2g1",
            "00:00:5e:00:53:10",
            True,
            clients=4,
            freq_mhz=2447,
            client_tx_bps=Stat(1_000_000, 80_400_000, 144_400_000),
            client_rx_bps=Stat(1_000_000, 51_050_000, 130_000_000),
        ),
        Radio(
            1,
            "5g1",
            "00:00:5e:00:53:11",
            True,
            clients=1,
            freq_mhz=5745,
            client_tx_bps=Stat(433_300_000, 433_300_000, 433_300_000),
            client_rx_bps=Stat(433_300_000, 433_300_000, 433_300_000),
        ),
    ),
)


def fixture_lines() -> list[str]:
    for name in FIXTURE_NAMES:
        path = Path(LIBRENMS_SRC) / name
        if path.is_file():
            text = path.read_bytes().decode("ascii")
            return [
                line for line in text.splitlines() if line.startswith(MERLIN_PREFIXES)
            ]
    pytest.fail(f"no asuswrt-merlin.snmprec under LIBRENMS_SRC={LIBRENMS_SRC}")


def extend_name(line: str) -> str | None:
    oid = line.split("|", 1)[0]
    if not oid.startswith(EXTEND_LINE):
        return None
    arcs = [int(a) for a in oid[len(EXTEND_LINE) :].split(".")]
    return bytes(arcs[1:]).decode()


def test_merlin_oids_match_the_librenms_fixture_byte_for_byte():
    expected = fixture_lines()
    skipped = [line for line in expected if extend_name(line) in NEVER_SERVED]
    assert {extend_name(line) for line in skipped} == NEVER_SERVED

    profile = AsuswrtMerlin(iface_keys={0: "eth1", 1: "eth2"})
    rendered = snmprec(OidTable(profile.render(FIXTURE_DEVICE))).splitlines()
    served = [line for line in rendered if line.startswith(MERLIN_PREFIXES)]

    assert served == [line for line in expected if line not in skipped]
    assert len(served) == 19
