"""MIB profiles: render a NodeSnapshot as the OID rows one SNMP engine serves.

Profiles are pure functions of a snapshot: no I/O, no clock reads. This
module also holds the ``dump-snmprec`` command.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Protocol

from aimesh_snmp_proxy.model import NodeSnapshot
from aimesh_snmp_proxy.profiles.asuswrt_merlin import AsuswrtMerlin
from aimesh_snmp_proxy.profiles.snapshot_json import load_snapshot
from aimesh_snmp_proxy.profiles.snmprec import snmprec
from aimesh_snmp_proxy.snmp.oidtable import OidTable, Row

if TYPE_CHECKING:
    from aimesh_snmp_proxy.config import Config

DEFAULT_PROFILE = "asuswrt-merlin"
EXIT_FAILED = 1


class Profile(Protocol):
    """Renders one snapshot; see :func:`aimesh_snmp_proxy.profiles.base.base_rows`."""

    name: str

    def render(
        self,
        snapshot: NodeSnapshot,
        *,
        now: float | None = None,
        serving_since: float | None = None,
        sys_name: str | None = None,
        peer_names: Mapping[str, str] | None = None,
    ) -> list[Row]: ...


PROFILES: Mapping[str, Profile] = MappingProxyType(
    {AsuswrtMerlin.name: AsuswrtMerlin()}
)


def get_profile(name: str) -> Profile:
    """The registered profile called ``name``; ValueError names the known ones."""
    try:
        return PROFILES[name]
    except KeyError:
        known = ", ".join(sorted(PROFILES))
        raise ValueError(f"unknown profile {name!r}; known: {known}") from None


def cli_dump_snmprec(config: Config | None, argv: Sequence[str]) -> int:
    """``dump-snmprec --snapshot FILE [--profile NAME]``: print rendered OIDs.

    Reads only the profile name from ``config``, which may be None.
    """
    parser = argparse.ArgumentParser(
        prog="aimesh-snmp-proxy dump-snmprec",
        description="Print the OIDs a snapshot renders, in snmprec format.",
    )
    parser.add_argument(
        "--snapshot", type=Path, required=True, help="sanitized snapshot JSON file"
    )
    parser.add_argument(
        "--profile", help=f"profile (default: the config's, else {DEFAULT_PROFILE})"
    )
    args = parser.parse_args(argv)
    name = args.profile or (
        config.snmp.profile if config is not None else DEFAULT_PROFILE
    )
    try:
        profile = get_profile(name)
        text = snmprec(OidTable(profile.render(load_snapshot(args.snapshot))))
    except (OSError, ValueError) as exc:
        print(f"dump-snmprec: {exc}", file=sys.stderr)
        return EXIT_FAILED
    sys.stdout.write(text)
    return 0
