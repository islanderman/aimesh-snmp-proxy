import pytest
from pysnmp.proto import rfc1902

from aimesh_snmp_proxy.profiles.snmprec import snmprec, snmprec_line
from aimesh_snmp_proxy.snmp.oidtable import OidTable

OID = (1, 3, 6, 1, 4, 1, 99, 1)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (rfc1902.Integer32(-85), "2|-85"),
        (rfc1902.Integer(7), "2|7"),
        (rfc1902.OctetString(b"ASUSWRT-Merlin RT-AC68U 384.17_0"), "4|ASUSWRT-Merlin"),
        (rfc1902.OctetString(b""), "4|"),
        (rfc1902.OctetString(b"a|b"), "4|a|b"),
        (rfc1902.OctetString(b"eth1,wl-2.4G\neth2,wl-5.0G"), "4x|657468312c776c2d"),
        (rfc1902.OctetString(b"\x00\x00\x5e\x00\x53\x01"), "4x|00005e005301"),
        (rfc1902.OctetString("café".encode()), "4x|636166c3a9"),
        (rfc1902.ObjectIdentifier((1, 3, 6, 1, 4, 1, 8072, 3, 2, 10)), "6|1.3.6.1.4"),
        (rfc1902.Counter32(2**32 - 1), "65|4294967295"),
        (rfc1902.Gauge32(1_000_000_000), "66|1000000000"),
        (rfc1902.TimeTicks(183954566), "67|183954566"),
        (rfc1902.Counter64(2**64 - 1), "70|18446744073709551615"),
    ],
)
def test_snmprec_line_types(value, expected):
    line = snmprec_line(OID, value)
    assert line.startswith(f"1.3.6.1.4.1.99.1|{expected}")


def test_snmprec_line_full_values():
    assert (
        snmprec_line(OID, rfc1902.OctetString(b"eth1,wl-2.4G\neth2,wl-5.0G"))
        == "1.3.6.1.4.1.99.1|4x|657468312c776c2d322e34470a657468322c776c2d352e3047"
    )
    assert (
        snmprec_line(OID, rfc1902.ObjectIdentifier((1, 3, 6, 1, 4, 1, 8072, 3, 2, 10)))
        == "1.3.6.1.4.1.99.1|6|1.3.6.1.4.1.8072.3.2.10"
    )


def test_unknown_value_type_is_rejected():
    with pytest.raises(TypeError, match="cannot render str"):
        snmprec_line(OID, "plain")


def test_snmprec_renders_a_table_in_oid_order_one_line_each():
    table = OidTable(
        [
            ((1, 3, 6, 1, 2, 1, 1, 5, 0), rfc1902.OctetString(b"node")),
            ((1, 3, 6, 1, 2, 1, 1, 3, 0), rfc1902.TimeTicks(5)),
        ]
    )
    assert snmprec(table) == "1.3.6.1.2.1.1.3.0|67|5\n1.3.6.1.2.1.1.5.0|4|node\n"


def test_snmprec_of_an_empty_table_is_empty():
    assert snmprec(OidTable()) == ""
