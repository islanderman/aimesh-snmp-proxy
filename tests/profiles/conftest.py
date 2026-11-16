"""Snapshot builders and an snmprec view of profile rows."""

from __future__ import annotations

from collections.abc import Callable, Iterable

import pytest

from aimesh_snmp_proxy.model import NodeSnapshot, Radio
from aimesh_snmp_proxy.profiles.snmprec import snmprec_line
from aimesh_snmp_proxy.snmp.oidtable import OidTable


def _node(**overrides) -> NodeSnapshot:
    fields = {
        "node_id": "aimesh-0053a1",
        "sys_name": "aimesh-0053a1",
        "mac": "00:00:5e:00:53:01",
        "online": True,
        "role": "node",
        "level": 1,
        "collected_at": 1000.0,
    }
    fields.update(overrides)
    return NodeSnapshot(**fields)


def _radio(unit: int, band: str = "2g1", **overrides) -> Radio:
    fields = {
        "unit": unit,
        "band": band,
        "mac": f"00:00:5e:00:53:1{unit}",
        "state": True,
    }
    fields.update(overrides)
    return Radio(**fields)


@pytest.fixture
def node() -> Callable[..., NodeSnapshot]:
    return _node


@pytest.fixture
def radio() -> Callable[..., Radio]:
    return _radio


@pytest.fixture
def served() -> Callable[[Iterable], dict[str, str]]:
    """Rows as ``{dotted OID: "tag|value"}``; building the table rejects duplicates."""

    def _served(rows: Iterable) -> dict[str, str]:
        out = {}
        for oid, value in OidTable(rows):
            dotted, rest = snmprec_line(oid, value).split("|", 1)
            out[dotted] = rest
        return out

    return _served
