"""Immutable, sorted OID table: everything one node's SNMP engine serves.

A new snapshot gets a new table, swapped in by one reference assignment, so
every request reads one consistent table. Values are opaque here.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from collections.abc import Iterable, Iterator, Sequence
from itertools import pairwise
from typing import Any

Oid = tuple[int, ...]
Row = tuple[Oid, Any]

MAX_BULK_VARBINDS = 64  # pysnmp BulkCommandResponder.max_varbinds
MAX_OID_LEN = 128  # RFC 2578 section 3.5
MAX_SUB_ID = 2**32 - 1

_DOTTED = re.compile(r"\.?(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))+\Z")


class _EndOfMibView:
    __slots__ = ()

    def __repr__(self) -> str:
        return "END_OF_MIB_VIEW"


END_OF_MIB_VIEW: Any = _EndOfMibView()


def format_oid(oid: Sequence[int]) -> str:
    """Dotted form without a leading dot, as in snmprec files."""
    return ".".join(map(str, oid))


def _checked(oid: Sequence[int]) -> Oid:
    oid = tuple(oid)
    valid = 2 <= len(oid) <= MAX_OID_LEN and all(
        type(arc) is int and 0 <= arc <= MAX_SUB_ID for arc in oid
    )
    if not valid:
        raise ValueError(f"invalid OID {oid!r}")
    return oid


def parse_oid(text: str) -> Oid:
    """``1.3.6.1`` or ``.1.3.6.1`` as a tuple; ValueError when malformed."""
    if not _DOTTED.match(text):
        raise ValueError(f"invalid OID {text!r}")
    return _checked(int(arc) for arc in text.lstrip(".").split("."))


class OidTable:
    """Rows sorted in SNMP order; lookups by exact OID, next OID, and GETBULK."""

    __slots__ = ("_index", "_oids", "_values")

    def __init__(self, rows: Iterable[Row] = ()) -> None:
        pairs = sorted(((_checked(oid), value) for oid, value in rows), key=_key)
        for (prev, _), (cur, _) in pairwise(pairs):
            if prev == cur:
                raise ValueError(f"duplicate OID {format_oid(cur)}")
        for oid, value in pairs:
            if value is None:
                raise ValueError(f"OID {format_oid(oid)} has no value")
        self._oids: tuple[Oid, ...] = tuple(oid for oid, _ in pairs)
        self._values: tuple[Any, ...] = tuple(value for _, value in pairs)
        self._index: dict[Oid, Any] = dict(pairs)

    def __len__(self) -> int:
        return len(self._oids)

    def __iter__(self) -> Iterator[Row]:
        return zip(self._oids, self._values, strict=True)

    def __repr__(self) -> str:
        return f"OidTable({len(self)} OIDs)"

    def get(self, oid: Sequence[int]) -> Any | None:
        """The value at exactly ``oid``, or None."""
        return self._index.get(tuple(oid))

    def get_next(self, oid: Sequence[int]) -> Row | None:
        """The first row after ``oid`` in SNMP order, or None past the end."""
        i = bisect_right(self._oids, tuple(oid))
        return (self._oids[i], self._values[i]) if i < len(self._oids) else None

    def get_bulk(
        self, oids: Sequence[Sequence[int]], non_repeaters: int, max_repetitions: int
    ) -> list[Row]:
        """RFC 3416 GETBULK; repeaters stop at 64 varbinds, like pysnmp's responder.

        Rows past the end carry :data:`END_OF_MIB_VIEW` and the last OID reached.
        """
        n = min(max(non_repeaters, 0), len(oids))
        repeaters = len(oids) - n
        reps = 0
        if repeaters:
            reps = min(max(max_repetitions, 0), MAX_BULK_VARBINDS // repeaters)
        out = [self._next_or_end(oid) for oid in oids[:n]]
        cursors = [tuple(oid) for oid in oids[n:]]
        for _ in range(reps):
            step = [self._next_or_end(oid) for oid in cursors]
            out += step
            cursors = [oid for oid, _ in step]
        return out

    def _next_or_end(self, oid: Sequence[int]) -> Row:
        row = self.get_next(oid)
        return row if row is not None else (tuple(oid), END_OF_MIB_VIEW)


def _key(row: Row) -> Oid:
    return row[0]
