import pytest

from aimesh_snmp_proxy.snmp.oidtable import (
    END_OF_MIB_VIEW,
    MAX_BULK_VARBINDS,
    OidTable,
    format_oid,
    parse_oid,
)

SYS_DESCR = (1, 3, 6, 1, 2, 1, 1, 1, 0)
SYS_NAME = (1, 3, 6, 1, 2, 1, 1, 5, 0)
IF_DESCR = (1, 3, 6, 1, 2, 1, 2, 2, 1, 2)

ROWS = [
    (SYS_NAME, "name"),
    ((*IF_DESCR, 10), "wl0"),
    (SYS_DESCR, "descr"),
    ((*IF_DESCR, 2), "backhaul"),
    ((*IF_DESCR, 1), "wired"),
]


def counting_table(n):
    return OidTable([((1, 3, 6, 1, 4, 1, 99, i), i) for i in range(1, n + 1)])


def test_rows_iterate_in_snmp_oid_order():
    assert [value for _, value in OidTable(ROWS)] == [
        "descr",
        "name",
        "wired",
        "backhaul",
        "wl0",
    ]


def test_order_is_numeric_per_arc_not_textual():
    table = OidTable([((1, 3, 10), "ten"), ((1, 3, 9), "nine"), ((1, 3, 9, 0), "c")])
    assert [oid for oid, _ in table] == [(1, 3, 9), (1, 3, 9, 0), (1, 3, 10)]


def test_duplicate_oid_is_rejected():
    with pytest.raises(ValueError, match=r"duplicate OID 1\.3\.6\.1\.2\.1\.1\.5\.0"):
        OidTable([(SYS_NAME, "a"), (SYS_DESCR, "b"), (SYS_NAME, "c")])


def test_a_row_without_a_value_is_rejected():
    with pytest.raises(ValueError, match=r"OID 1\.3\.6\.1\.2\.1\.1\.5\.0 has no value"):
        OidTable([(SYS_NAME, None)])


@pytest.mark.parametrize(
    "oid",
    [
        (),
        (1,),
        (1, -1),
        (1, 2**32),
        (1, True),
        (1, 3.0),
        (1, "3"),
        tuple(range(129)),
    ],
)
def test_malformed_oid_is_rejected(oid):
    with pytest.raises(ValueError, match="invalid OID"):
        OidTable([(oid, "x")])


def test_largest_sub_identifier_and_length_are_accepted():
    oid = (1, 3, *([2**32 - 1] * 126))
    assert OidTable([(oid, "x")]).get(oid) == "x"


def test_get_returns_the_value_or_none():
    table = OidTable(ROWS)
    assert table.get(SYS_NAME) == "name"
    assert table.get(list(SYS_NAME)) == "name"
    assert table.get(SYS_NAME[:-1]) is None
    assert table.get((1, 3, 6, 1, 2, 1, 1, 7, 0)) is None


@pytest.mark.parametrize(
    ("start", "expected"),
    [
        ((0,), SYS_DESCR),
        ((1, 3, 6), SYS_DESCR),
        (SYS_DESCR, SYS_NAME),
        ((1, 3, 6, 1, 2, 1, 1, 2, 0), SYS_NAME),
        (IF_DESCR, (*IF_DESCR, 1)),
        ((*IF_DESCR, 2), (*IF_DESCR, 10)),
        ((*IF_DESCR, 2, 5), (*IF_DESCR, 10)),
    ],
)
def test_get_next_returns_the_first_row_after_the_oid(start, expected):
    table = OidTable(ROWS)
    oid, value = table.get_next(start)
    assert oid == expected
    assert value == table.get(expected)


def test_get_next_past_the_last_row_is_none():
    table = OidTable(ROWS)
    assert table.get_next((*IF_DESCR, 10)) is None
    assert table.get_next((2,)) is None


def test_empty_table():
    table = OidTable()
    assert len(table) == 0
    assert not table
    assert table.get(SYS_NAME) is None
    assert table.get_next((0,)) is None
    assert table.get_bulk([(0,)], 0, 5) == [((0,), END_OF_MIB_VIEW)] * 5


def test_table_is_immutable():
    table = OidTable(ROWS)
    with pytest.raises(AttributeError):
        table.extra = 1
    with pytest.raises(TypeError):
        table[SYS_NAME] = "x"


def test_len_and_repr():
    assert repr(END_OF_MIB_VIEW) == "END_OF_MIB_VIEW"
    table = OidTable(ROWS)
    assert len(table) == 5
    assert repr(table) == "OidTable(5 OIDs)"


def test_get_bulk_follows_rfc3416_non_repeaters_then_interleaved_repeaters():
    table = OidTable(ROWS)
    result = table.get_bulk([SYS_DESCR, (1, 3, 6, 1, 2, 1, 1), IF_DESCR], 1, 2)
    assert [oid for oid, _ in result] == [
        SYS_NAME,
        SYS_DESCR,
        (*IF_DESCR, 1),
        SYS_NAME,
        (*IF_DESCR, 2),
    ]


def test_get_bulk_fills_with_end_of_mib_view_at_the_end():
    table = OidTable(ROWS)
    result = table.get_bulk([(*IF_DESCR, 2)], 0, 3)
    assert result == [
        ((*IF_DESCR, 10), "wl0"),
        ((*IF_DESCR, 10), END_OF_MIB_VIEW),
        ((*IF_DESCR, 10), END_OF_MIB_VIEW),
    ]


def test_get_bulk_caps_a_single_repeater_at_64_varbinds():
    table = counting_table(200)
    result = table.get_bulk([(1, 3, 6)], 0, 1000)
    assert MAX_BULK_VARBINDS == 64
    assert [value for _, value in result] == list(range(1, 65))


def test_get_bulk_cap_divides_by_the_number_of_repeaters():
    result = counting_table(200).get_bulk([(1,), (1,), (1,)], 0, 1000)
    assert len(result) == 3 * (64 // 3)


def test_get_bulk_with_more_repeaters_than_the_cap_returns_non_repeaters_only():
    table = counting_table(3)
    result = table.get_bulk([(1,)] + [(2,)] * 65, 1, 10)
    assert result == [((1, 3, 6, 1, 4, 1, 99, 1), 1)]


def test_get_bulk_negative_counts_mean_zero():
    table = counting_table(3)
    assert table.get_bulk([(1,)], -5, 1) == [((1, 3, 6, 1, 4, 1, 99, 1), 1)]
    assert table.get_bulk([(1,)], 0, -1) == []


def test_get_bulk_non_repeaters_beyond_the_list_count_all_as_non_repeaters():
    table = counting_table(3)
    assert table.get_bulk([(1,), (2,)], 9, 50) == [
        ((1, 3, 6, 1, 4, 1, 99, 1), 1),
        ((2,), END_OF_MIB_VIEW),
    ]


@pytest.mark.parametrize("text", ["1.3.6.1.2.1.1.5.0", ".1.3.6.1.2.1.1.5.0"])
def test_parse_oid(text):
    assert parse_oid(text) == SYS_NAME


@pytest.mark.parametrize("text", ["", "1", "1..3", "1.a", "1.3.", " 1.3", "1.-3"])
def test_parse_oid_rejects_malformed_text(text):
    with pytest.raises(ValueError, match="invalid OID"):
        parse_oid(text)


def test_format_oid():
    assert format_oid(SYS_NAME) == "1.3.6.1.2.1.1.5.0"
