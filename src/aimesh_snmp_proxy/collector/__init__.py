"""Collector: poll the ASUS root router and turn its replies into NodeSnapshots.

``Collector`` runs the jobs, ``SnapshotStore`` is what the SNMP side reads,
and ``cli_discover`` is the read-only ``discover`` command.
"""

from aimesh_snmp_proxy.collector.discover import cli_discover
from aimesh_snmp_proxy.collector.service import Collector, CollectorSettings
from aimesh_snmp_proxy.collector.store import NodeIdentity, SnapshotStore

__all__ = [
    "Collector",
    "CollectorSettings",
    "NodeIdentity",
    "SnapshotStore",
    "cli_discover",
]
