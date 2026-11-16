"""pysnmp MIB instrumentation that answers from one node's current OidTable.

It replaces the engine's default context, so pysnmp's own tables (USM users,
communities, VACM) are never reachable over SNMP. Nothing is writable.
"""

from __future__ import annotations

from typing import Any

from pysnmp.proto import rfc1905
from pysnmp.smi.instrum import AbstractMibInstrumController

from aimesh_snmp_proxy.snmp.oidtable import Oid, OidTable, Row


class TableController(AbstractMibInstrumController):
    """GET and GETNEXT over ``table``; the SNMP layer swaps ``table`` atomically.

    Every varbind passes the VACM ``acFun`` check, as pysnmp's own MIB tree
    does, so the security level each user needs is enforced per request.
    """

    def __init__(self, table: OidTable | None = None) -> None:
        self.table = table if table is not None else OidTable()

    def read_variables(self, *var_binds: Any, **context: Any) -> list[Row]:
        table = self.table
        out = []
        for idx, (name, _) in enumerate(var_binds):
            value = table.get(tuple(name))
            # Check even missing OIDs so a denied caller learns nothing.
            if _hidden(context, idx, tuple(name), value) or value is None:
                value = rfc1905.noSuchObject
            out.append((name, value))
        return out

    def read_next_variables(self, *var_binds: Any, **context: Any) -> list[Row]:
        table = self.table
        out = []
        for idx, (name, _) in enumerate(var_binds):
            row = _next_visible(table, tuple(name), idx, context)
            out.append(row if row is not None else (name, rfc1905.endOfMibView))
        return out


def _hidden(context: dict[str, Any], idx: int, oid: Oid, value: Any) -> bool:
    """True when VACM puts ``oid`` outside the view; denial errors propagate."""
    ac_fun = context.get("acFun")
    return bool(ac_fun and ac_fun("read", (oid, value), **{**context, "idx": idx}))


def _next_visible(
    table: OidTable, oid: Oid, idx: int, context: dict[str, Any]
) -> Row | None:
    while (row := table.get_next(oid)) is not None:
        oid, value = row
        if not _hidden(context, idx, oid, value):
            return row
    return None
