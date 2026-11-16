"""The snapshot store the SNMP side reads (design section 3, SILENT rules).

``current(node_id)`` returns None, meaning SILENT, when the node is absent
from the latest AiMesh list, reported ``online=false`` in two topology polls
in a row, or has no snapshot younger than ``stale_after_s``. Stale data is
never served: an answer would fake liveness in LibreNMS. One event loop owns
the store, so reads and writes need no locks.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from aimesh_snmp_proxy.collector.mapping import MeshNode
from aimesh_snmp_proxy.config import default_sys_name
from aimesh_snmp_proxy.model import NodeSnapshot

_LOG = logging.getLogger(__name__)

OFFLINE_REPORTS_TO_SILENCE = 2  # flap guard (ha-asusrouter #881)


@dataclass(frozen=True, slots=True)
class NodeIdentity:
    """What the SNMP side needs to give a node an engine and a stable port."""

    node_id: str
    mac: str
    ip: str | None
    role: str
    sys_name: str
    model: str | None


class SnapshotStore:
    """Latest snapshot per node plus the AiMesh presence the SILENT rules need."""

    def __init__(
        self,
        *,
        stale_after_s: float = 180.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._stale_after_s = stale_after_s
        self._clock = clock
        self._snapshots: dict[str, NodeSnapshot] = {}
        self._identities: dict[str, NodeIdentity] = {}
        self._listed: frozenset[str] = frozenset()
        self._offline: dict[str, int] = {}
        self._serving: dict[str, bool] = {}

    def update_topology(
        self, nodes: Mapping[str, MeshNode], names: Mapping[str, str] | None = None
    ) -> None:
        """Record the latest AiMesh list: presence, online streaks, identities."""
        names = names or {}
        for mac, node in nodes.items():
            self._identities[mac] = NodeIdentity(
                node_id=mac,
                mac=mac,
                ip=node.ip,
                role=node.role,
                sys_name=names.get(mac) or default_sys_name(mac),
                model=node.model,
            )
            self._offline[mac] = 0 if node.online else self._offline.get(mac, 0) + 1
        self._listed = frozenset(nodes)

    def put(self, snapshot: NodeSnapshot) -> None:
        """Keep the newest snapshot; an older one never replaces it."""
        held = self._snapshots.get(snapshot.node_id)
        if held is None or snapshot.collected_at >= held.collected_at:
            self._snapshots[snapshot.node_id] = snapshot

    def current(self, node_id: str) -> NodeSnapshot | None:
        """The snapshot to serve, or None when the node must stay SILENT."""
        return (
            self._snapshots.get(node_id) if self._why_silent(node_id) is None else None
        )

    def identities(self) -> tuple[NodeIdentity, ...]:
        """Every node seen in an AiMesh list since start, sorted by node ID."""
        return tuple(self._identities[key] for key in sorted(self._identities))

    def serving(self) -> tuple[str, ...]:
        return tuple(i.node_id for i in self.identities() if self.current(i.node_id))

    def refresh_states(self) -> dict[str, bool]:
        """Evaluate every node and log SERVING/SILENT transitions once each."""
        states = {}
        for identity in self.identities():
            why = self._why_silent(identity.node_id)
            serving = why is None
            if self._serving.get(identity.node_id) != serving:
                if serving:
                    _LOG.info(
                        "node %s (%s): SERVING", identity.sys_name, identity.node_id
                    )
                else:
                    _LOG.info(
                        "node %s (%s): SILENT, %s",
                        identity.sys_name,
                        identity.node_id,
                        why,
                    )
            self._serving[identity.node_id] = serving
            states[identity.node_id] = serving
        return states

    def _why_silent(self, node_id: str) -> str | None:
        if node_id not in self._listed:
            return "absent from the AiMesh list"
        if self._offline.get(node_id, 0) >= OFFLINE_REPORTS_TO_SILENCE:
            return "offline in two AiMesh polls in a row"
        snapshot = self._snapshots.get(node_id)
        if snapshot is None:
            return "no snapshot yet"
        if not snapshot.is_fresh(self._clock(), self._stale_after_s):
            return f"stale (older than {self._stale_after_s:g} s)"
        return None
