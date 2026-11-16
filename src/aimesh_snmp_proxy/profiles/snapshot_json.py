"""Load a NodeSnapshot from JSON shaped like ``dataclasses.asdict(snapshot)``.

Strict on purpose: unknown keys, nulls in required fields, and wrong types
are errors, so a typo in a sanitized fixture cannot change what renders.
"""

from __future__ import annotations

import json
from dataclasses import fields
from pathlib import Path
from typing import Any

from aimesh_snmp_proxy.model import (
    Backhaul,
    EthPort,
    Link,
    Neighbor,
    NodeSnapshot,
    Radio,
    Stat,
    Temperature,
)

MAX_SNAPSHOT_BYTES = 1 << 20

_NESTED = {
    cls.__name__: cls
    for cls in (Backhaul, EthPort, Link, Neighbor, Radio, Stat, Temperature)
}
_SCALARS: dict[str, tuple[type, ...]] = {
    "str": (str,),
    "int": (int,),
    "float": (int, float),
    "bool": (bool,),
}


def load_snapshot(path: Path) -> NodeSnapshot:
    """Read and validate one snapshot file; OSError or ValueError on failure."""
    with path.open("rb") as fh:
        data = fh.read(MAX_SNAPSHOT_BYTES + 1)
    if len(data) > MAX_SNAPSHOT_BYTES:
        raise ValueError(f"{path}: larger than {MAX_SNAPSHOT_BYTES} bytes")
    try:
        raw = json.loads(data)
    except ValueError as exc:
        raise ValueError(f"{path}: invalid JSON: {exc}") from None
    return snapshot_from_dict(raw)


def snapshot_from_dict(data: Any) -> NodeSnapshot:
    """Build a snapshot from decoded JSON; ValueError names the bad key path."""
    return _build(NodeSnapshot, data, "snapshot")


def _build(cls: type, data: Any, where: str) -> Any:
    if not isinstance(data, dict):
        raise ValueError(f"{where}: expected an object")
    # model.py uses postponed annotations, so each field type is a string.
    hints = {f.name: str(f.type) for f in fields(cls)}
    unknown = sorted(set(data) - set(hints))
    if unknown:
        raise ValueError(f"{where}: unknown key(s): {', '.join(unknown)}")
    kwargs = {k: _convert(hints[k], v, f"{where}.{k}") for k, v in data.items()}
    try:
        return cls(**kwargs)
    except TypeError as exc:  # a missing required key
        raise ValueError(f"{where}: {exc}") from None


def _convert(hint: str, value: Any, where: str) -> Any:
    base = hint.removesuffix(" | None")
    if value is None:
        if base != hint:
            return None
        raise ValueError(f"{where}: must not be null")
    if base.startswith("tuple[") and base.endswith(", ...]"):
        if not isinstance(value, list):
            raise ValueError(f"{where}: expected a list")
        item = base[len("tuple[") : -len(", ...]")]
        return tuple(_convert(item, v, f"{where}[{i}]") for i, v in enumerate(value))
    if base in _NESTED:
        return _build(_NESTED[base], value, where)
    types = _SCALARS.get(base)
    if types is None:
        raise TypeError(f"{where}: unsupported field type {hint!r}")
    if not isinstance(value, types) or (isinstance(value, bool) and bool not in types):
        raise ValueError(f"{where}: expected {base}")
    return float(value) if base == "float" else value
