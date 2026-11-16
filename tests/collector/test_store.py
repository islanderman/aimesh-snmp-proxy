import logging

import pytest

from aimesh_snmp_proxy.collector.mapping import MeshNode
from aimesh_snmp_proxy.collector.store import NodeIdentity, SnapshotStore
from aimesh_snmp_proxy.model import NodeSnapshot

ROOT = "00:00:5e:00:53:01"
NODE = "00:00:5e:00:53:02"


class Now:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def mesh(mac, online=True, role="node", ip=None, model=None):
    return MeshNode(mac=mac, online=online, role=role, level=1, ip=ip, model=model)


def snap(mac, at, online=True):
    return NodeSnapshot(
        node_id=mac,
        sys_name="x",
        mac=mac,
        online=online,
        role="node",
        level=1,
        collected_at=at,
    )


@pytest.fixture
def now():
    return Now()


@pytest.fixture
def store(now):
    return SnapshotStore(stale_after_s=180, clock=now)


def listed(store, *nodes):
    store.update_topology({n.mac: n for n in nodes})


def test_nothing_is_served_before_the_first_aimesh_list(store, now):
    store.put(snap(ROOT, now.t))
    assert store.current(ROOT) is None
    assert store.identities() == ()


def test_fresh_snapshot_of_a_listed_node_is_served(store, now):
    listed(store, mesh(ROOT, role="router"))
    s = snap(ROOT, now.t)
    store.put(s)
    assert store.current(ROOT) is s
    assert store.serving() == (ROOT,)


def test_node_absent_from_the_latest_list_goes_silent_but_keeps_its_identity(
    store, now
):
    listed(store, mesh(ROOT, role="router"), mesh(NODE))
    store.put(snap(NODE, now.t))
    listed(store, mesh(ROOT, role="router"))
    assert store.current(NODE) is None
    assert [i.node_id for i in store.identities()] == [ROOT, NODE]


def test_offline_once_keeps_serving_twice_in_a_row_silences(store, now):
    listed(store, mesh(NODE))
    store.put(snap(NODE, now.t))
    listed(store, mesh(NODE, online=False))
    assert store.current(NODE) is not None  # flap guard: one report is noise
    listed(store, mesh(NODE, online=False))
    assert store.current(NODE) is None
    listed(store, mesh(NODE, online=True))
    store.put(snap(NODE, now.t))
    assert store.current(NODE) is not None


def test_offline_streak_resets_when_the_node_reports_online(store, now):
    listed(store, mesh(NODE))
    store.put(snap(NODE, now.t))
    listed(store, mesh(NODE, online=False))
    listed(store, mesh(NODE, online=True))
    listed(store, mesh(NODE, online=False))
    assert store.current(NODE) is not None


def test_stale_snapshot_is_never_served_and_a_fresh_one_restores(store, now):
    listed(store, mesh(NODE))
    store.put(snap(NODE, now.t))
    now.t += 180
    assert store.current(NODE) is not None
    now.t += 0.5
    assert store.current(NODE) is None
    store.put(snap(NODE, now.t))
    assert store.current(NODE) is not None


def test_snapshot_from_the_future_is_not_served(store, now):
    listed(store, mesh(NODE))
    store.put(snap(NODE, now.t + 5))
    assert store.current(NODE) is None


def test_older_snapshot_never_replaces_a_newer_one(store, now):
    listed(store, mesh(NODE))
    newer = snap(NODE, now.t)
    store.put(newer)
    store.put(snap(NODE, now.t - 30))
    assert store.current(NODE) is newer


def test_unknown_node_id_is_silent(store):
    assert store.current("nope") is None


def test_identities_follow_the_latest_list(store):
    listed(
        store, mesh(NODE, ip="192.168.50.101", model="P2"), mesh(ROOT, role="router")
    )
    listed(
        store, mesh(NODE, ip="192.168.50.110", model="P2"), mesh(ROOT, role="router")
    )
    assert store.identities() == (
        NodeIdentity(ROOT, ROOT, None, "router", "aimesh-005301", None),
        NodeIdentity(NODE, NODE, "192.168.50.110", "node", "aimesh-005302", "P2"),
    )


def test_names_override_the_default_sys_name(store):
    store.update_topology({NODE: mesh(NODE)}, names={NODE: "aimesh-hall"})
    assert store.identities()[0].sys_name == "aimesh-hall"


def test_refresh_states_logs_each_transition_once(store, now, caplog):
    listed(store, mesh(NODE))
    store.put(snap(NODE, now.t))
    with caplog.at_level(logging.INFO):
        assert store.refresh_states() == {NODE: True}
        store.refresh_states()
        now.t += 500
        assert store.refresh_states() == {NODE: False}
    lines = [r.getMessage() for r in caplog.records]
    assert len([m for m in lines if "SERVING" in m]) == 1
    assert len([m for m in lines if "SILENT" in m]) == 1
    assert any("stale" in m for m in lines)
