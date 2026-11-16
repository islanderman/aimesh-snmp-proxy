"""snmprec text: the snmpsim format LibreNMS keeps its device fixtures in.

One ``oid|tag|value`` line per row. Printable ASCII strings use tag ``4``;
any other string is hex under ``4x``, as LibreNMS writes multi-line values.
"""

from __future__ import annotations

from typing import Any

from pysnmp.proto import rfc1902

from aimesh_snmp_proxy.snmp.oidtable import Oid, OidTable, format_oid

_TAGS: dict[type, str] = {
    rfc1902.Integer32: "2",
    rfc1902.Integer: "2",
    rfc1902.OctetString: "4",
    rfc1902.ObjectIdentifier: "6",
    rfc1902.Counter32: "65",
    rfc1902.Gauge32: "66",
    rfc1902.TimeTicks: "67",
    rfc1902.Counter64: "70",
}


def snmprec_line(oid: Oid, value: Any) -> str:
    """One snmprec line, without the newline."""
    tag = _TAGS.get(type(value))
    if tag is None:
        raise TypeError(f"cannot render {type(value).__name__} as snmprec")
    if tag == "4":
        data = value.asOctets()
        if all(0x20 <= byte <= 0x7E for byte in data):
            text = data.decode("ascii")
        else:
            tag, text = "4x", data.hex()
    elif tag == "6":
        text = format_oid(tuple(value))
    else:
        text = str(int(value))
    return f"{format_oid(oid)}|{tag}|{text}"


def snmprec(table: OidTable) -> str:
    """The whole table in OID order, newline-terminated lines."""
    return "".join(snmprec_line(oid, value) + "\n" for oid, value in table)
