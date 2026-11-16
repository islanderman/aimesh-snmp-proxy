"""The LibreNMS ``asuswrt-merlin`` OS, emulated on top of the base MIBs.

Detection needs sysObjectID ``.1.3.6.1.4.1.8072.3.2.10`` plus an
``ASUSWRT-Merlin`` string; wireless sensors read NET-SNMP extend output
(LibreNMS ``AsuswrtMerlin.php``). SNR and noise floor are never served.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable, Mapping

from aimesh_snmp_proxy.model import NodeSnapshot, Radio
from aimesh_snmp_proxy.profiles.base import (
    NET_SNMP_LINUX,
    base_rows,
    display_string,
    radio_label,
)
from aimesh_snmp_proxy.snmp.oidtable import Oid, Row, parse_oid

MERLIN_INFO = parse_oid("1.3.6.1.4.1.2021.7890.1.101.1")
EXTEND_OUTPUT_1LINE = parse_oid("1.3.6.1.4.1.8072.1.3.2.3.1.1")
EXTEND_OUTPUT_FULL = parse_oid("1.3.6.1.4.1.8072.1.3.2.3.1.2")

_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}")
_RATE_PARTS = ("min", "max", "avg")


def encode_string(name: str) -> Oid:
    """LibreNMS ``Oid::encodeString``: the byte length, then each byte."""
    data = name.encode()
    return (len(data), *data)


def _word(text: str | None) -> str:
    """LibreNMS splits the info string on spaces, so each part stays one word."""
    return re.sub(r"\s", "_", (text or "").strip())


class AsuswrtMerlin:
    """Base MIBs plus the asuswrt-merlin detection and wireless extend OIDs.

    ``iface_keys`` renames a radio's extend key (default ``wl<unit>``); the
    LibreNMS conformance test uses it to match the fixture's ``eth1``/``eth2``.
    """

    name = "asuswrt-merlin"

    def __init__(self, iface_keys: Mapping[int, str] | None = None) -> None:
        keys = dict(iface_keys or {})
        for key in keys.values():
            if not _KEY.fullmatch(key):
                raise ValueError(f"invalid interface key {key!r}")
        self._keys = keys

    def render(
        self,
        snapshot: NodeSnapshot,
        *,
        now: float | None = None,
        serving_since: float | None = None,
        sys_name: str | None = None,
        peer_names: Mapping[str, str] | None = None,
    ) -> list[Row]:
        """Every row for ``snapshot``; arguments as in :func:`base_rows`."""
        rows = base_rows(
            snapshot,
            sys_object_id=NET_SNMP_LINUX,
            now=now,
            serving_since=serving_since,
            sys_name=sys_name,
            peer_names=peer_names,
        )
        model, firmware = _word(snapshot.model), _word(snapshot.firmware)
        # A firmware without a model would be read as the hardware name.
        info = " ".join(p for p in ("ASUSWRT-Merlin", model, model and firmware) if p)
        rows.append((MERLIN_INFO, display_string(info)))
        return rows + self._wireless(snapshot.radios)

    def _key(self, radio: Radio) -> str:
        return self._keys.get(radio.unit, f"wl{radio.unit}")

    def _wireless(self, radios: Iterable[Radio]) -> list[Row]:
        radios = list(radios)
        if not radios:
            return []
        # LF only and no trailing LF: LibreNMS splits on PHP_EOL, then on ",".
        lines = "\n".join(f"{self._key(r)},{radio_label(r)}" for r in radios)
        rows = [
            ((*EXTEND_OUTPUT_FULL, *encode_string("interfaces")), display_string(lines))
        ]

        def extend(name: str, value: int) -> None:
            rows.append(
                (
                    (*EXTEND_OUTPUT_1LINE, *encode_string(name)),
                    display_string(str(value)),
                )
            )

        extend("clients-wlan", sum(r.clients for r in radios))
        for radio in radios:
            key = self._key(radio)
            extend(f"clients-{key}", radio.clients)
            if radio.freq_mhz is not None:
                extend(f"frequency-{key}", radio.freq_mhz)
            if radio.clients < 1:
                continue
            for direction, stat in (
                ("tx", radio.client_tx_bps),
                ("rx", radio.client_rx_bps),
            ):
                for part in _RATE_PARTS if stat is not None else ():
                    value = getattr(stat, part)
                    if math.isfinite(value) and value >= 0:
                        extend(f"rate-{direction}-{key}-{part}", round(value))
        return rows
