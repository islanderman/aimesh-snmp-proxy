import json
import os
import stat

import pytest

from aimesh_snmp_proxy import ports
from aimesh_snmp_proxy.ports import MAX_INDEX, PortMap, PortMapError

BASE = 16101
EXPECTED = [f"192.168.50.{octet}" for octet in range(101, 111)]
ROOT = "00:00:5e:00:53:01"
A = "00:00:5e:00:53:0a"
B = "00:00:5e:00:53:0b"
C = "00:00:5e:00:53:0c"


@pytest.fixture
def path(tmp_path):
    return tmp_path / "state" / "ports.json"


def fresh(path, expected=EXPECTED):
    return PortMap.load(path, BASE, expected)


def on_disk(path):
    return json.loads(path.read_text())


def test_root_always_serves_port_base_and_is_not_persisted(path):
    pm = fresh(path)
    assert pm.root_port == BASE
    assert pm.assign(ROOT, ip="192.168.50.1", root=True) == BASE
    assert not path.exists()


@pytest.mark.parametrize(
    ("ip", "port"), [("192.168.50.101", 16102), ("192.168.50.110", 16111)]
)
def test_expected_ip_gets_its_reserved_index(path, ip, port):
    assert fresh(path).assign(A, ip=ip) == port
    assert fresh(path).expected_port(ip) == port


def test_other_nodes_take_the_next_index_above_the_reserved_range(path):
    pm = fresh(path)
    assert pm.assign(A, ip="192.168.50.50") == BASE + 11
    assert pm.assign(B, ip=None) == BASE + 12
    assert pm.expected_port("192.168.50.50") is None


def test_without_expected_ips_nodes_start_at_index_one(path):
    pm = fresh(path, expected=())
    assert pm.assign(A, ip="192.168.50.101") == BASE + 1
    assert pm.assign(B, ip="192.168.50.102") == BASE + 2


def test_mac_keeps_its_port_after_an_ip_change_and_restart(path):
    assert fresh(path).assign(A, ip="192.168.50.103") == 16104
    reloaded = fresh(path)
    assert reloaded.assign(A, ip="192.168.50.105") == 16104
    assert reloaded.port(A) == 16104


def test_new_mac_at_a_taken_expected_ip_never_moves_the_owner(path):
    pm = fresh(path)
    pm.assign(A, ip="192.168.50.103")
    assert pm.assign(B, ip="192.168.50.103") == BASE + 11
    assert pm.port(A) == 16104


def test_vanished_node_keeps_its_index_forever(path):
    pm = fresh(path)
    pm.assign(A, ip="192.168.50.50")
    pm.assign(B, ip="192.168.50.51")
    reloaded = fresh(path)
    assert reloaded.assign(C, ip="192.168.50.52") == BASE + 13
    assert reloaded.port(A) == BASE + 11


def test_index_freed_by_an_override_is_not_handed_to_strangers(path):
    pm = fresh(path)
    pm.assign(A, ip="192.168.50.50")
    pm.assign(A, pin=BASE + 40)
    assert pm.assign(B, ip="192.168.50.51") == BASE + 12


def test_override_pin_wins_and_displaced_node_moves(path):
    pm = fresh(path)
    pm.assign(A, ip="192.168.50.50")
    assert pm.assign(B, ip="192.168.50.51", pin=BASE + 11) == BASE + 11
    assert pm.port(A) == BASE + 12
    assert on_disk(path)["nodes"] == {A: 12, B: 11}


def test_unchanged_pin_does_not_rewrite_the_file(path):
    pm = fresh(path)
    pm.assign(A, pin=BASE + 20)
    before = path.stat().st_mtime_ns
    os.utime(path, ns=(1, 1))
    assert pm.assign(A, pin=BASE + 20) == BASE + 20
    assert path.stat().st_mtime_ns == 1
    assert before != 1


def test_pin_onto_a_free_expected_index_is_allowed(path):
    pm = fresh(path)
    assert pm.assign(A, ip="192.168.50.50", pin=16104) == 16104
    assert pm.assign(B, ip="192.168.50.103") == BASE + 11


@pytest.mark.parametrize("pin", [BASE, BASE - 1, BASE + MAX_INDEX + 1])
def test_pin_outside_the_node_range_is_rejected(path, pin):
    with pytest.raises(ValueError, match="outside"):
        fresh(path).assign(A, pin=pin)


def test_root_keeps_its_satellite_index_reserved(path):
    pm = fresh(path)
    pm.assign(A, ip="192.168.50.103")
    assert pm.assign(A, ip="192.168.50.1", root=True) == BASE
    assert pm.port(A) == 16104
    assert pm.assign(A, ip="192.168.50.103") == 16104


def test_root_ignores_override_pins(path):
    assert fresh(path).assign(ROOT, root=True, pin=BASE + 9) == BASE


def test_file_format_is_versioned_sorted_and_owner_only(path):
    pm = fresh(path)
    pm.assign(B, ip="192.168.50.50")
    pm.assign(A, ip="192.168.50.101")
    assert on_disk(path) == {"version": 1, "next_index": 12, "nodes": {A: 1, B: 11}}
    assert list(on_disk(path)["nodes"]) == [A, B]
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert pm.pinned() == {A: 16102, B: 16112}


def test_macs_are_normalized(path):
    pm = fresh(path)
    assert pm.assign("00-00-5E-00-53-0A", ip="192.168.50.101") == 16102
    assert pm.port("00005e00530a") == 16102
    assert on_disk(path)["nodes"] == {A: 1}


def test_invalid_mac_is_rejected(path):
    with pytest.raises(ValueError, match="not a MAC address"):
        fresh(path).assign("nonsense")
    with pytest.raises(ValueError, match="not a MAC address"):
        fresh(path).port("nonsense")


def test_unparsable_node_ip_is_treated_as_unexpected(path):
    assert fresh(path).assign(A, ip="not-an-ip") == BASE + 11


def test_index_space_exhaustion(path):
    nodes = {f"02:00:00:00:00:{i:02x}": i for i in range(1, MAX_INDEX + 1)}
    path.parent.mkdir(parents=True)
    doc = {"version": 1, "next_index": MAX_INDEX + 1, "nodes": nodes}
    path.write_text(json.dumps(doc))
    with pytest.raises(PortMapError, match="no free port index"):
        fresh(path, expected=()).assign(A)


def test_save_failure_leaves_disk_and_memory_unchanged(path, monkeypatch):
    pm = fresh(path)
    pm.assign(A, ip="192.168.50.101")
    before = path.read_bytes()

    def no_space(src, dst):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(ports.os, "replace", no_space)
    with pytest.raises(PortMapError, match="cannot write: No space left on device"):
        pm.assign(B, ip="192.168.50.50")
    assert pm.port(B) is None
    assert path.read_bytes() == before
    assert sorted(p.name for p in path.parent.iterdir()) == ["ports.json"]


def test_stale_temp_files_from_an_interrupted_write_are_removed(path):
    fresh(path).assign(A, ip="192.168.50.101")
    leftover = path.parent / ".ports.json.k3j2.tmp"
    leftover.write_text("{partial")
    unrelated = path.parent / "counters.json"
    unrelated.write_text("{}")
    assert fresh(path).port(A) == 16102
    assert not leftover.exists()
    assert unrelated.exists()


def test_growing_the_expected_range_never_moves_existing_ports(path):
    pm = fresh(path, expected=EXPECTED[:2])
    assert pm.assign(A, ip="192.168.50.50") == BASE + 3
    grown = fresh(path, expected=EXPECTED[:4])
    assert grown.port(A) == BASE + 3
    assert grown.assign(B, ip="192.168.50.103") == BASE + 5


@pytest.mark.parametrize(
    ("content", "problem"),
    [
        ("{not json", "not valid JSON"),
        (b"\xff\xfe", "not valid JSON"),
        ("[]", "unsupported format"),
        ('{"version": 2, "next_index": 1, "nodes": {}}', "unsupported format"),
        ('{"version": 1, "next_index": 1, "nodes": []}', "nodes must be an object"),
        ('{"version": 1, "next_index": 0, "nodes": {}}', "next_index"),
        ('{"version": 1, "next_index": true, "nodes": {}}', "next_index"),
        ('{"version": 1, "next_index": 1, "nodes": {}, "x": 1}', "unknown key"),
        ('{"version": 1, "next_index": 2, "nodes": {"bad": 1}}', "invalid MAC"),
        (
            f'{{"version": 1, "next_index": 2, "nodes": {{"{A.upper()}": 1}}}}',
            "invalid MAC",
        ),
        (f'{{"version": 1, "next_index": 2, "nodes": {{"{A}": 0}}}}', "out of range"),
        (f'{{"version": 1, "next_index": 2, "nodes": {{"{A}": 256}}}}', "out of range"),
        (f'{{"version": 1, "next_index": 2, "nodes": {{"{A}": "1"}}}}', "out of range"),
        (
            f'{{"version": 1, "next_index": 2, "nodes": {{"{A}": 3, "{B}": 3}}}}',
            "index 3 is pinned to two nodes",
        ),
    ],
)
def test_corrupt_file_fails_closed_and_is_kept(path, content, problem):
    path.parent.mkdir(parents=True)
    data = content.encode() if isinstance(content, str) else content
    path.write_bytes(data)
    with pytest.raises(PortMapError, match=problem) as exc:
        fresh(path)
    assert str(path) in str(exc.value)
    assert A not in str(exc.value)
    assert path.read_bytes() == data


def test_unreadable_file_fails_closed(path):
    path.parent.mkdir(parents=True)
    path.write_text("{}")
    path.chmod(0o000)
    try:
        if os.access(path, os.R_OK):
            pytest.skip("running with privileges that ignore file modes")
        with pytest.raises(PortMapError, match="cannot read"):
            fresh(path)
    finally:
        path.chmod(0o600)


def test_next_index_from_file_is_kept(path):
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"version": 1, "next_index": 30, "nodes": {A: 11}}))
    assert fresh(path).assign(B, ip="192.168.50.50") == BASE + 30


@pytest.mark.parametrize(
    ("port_base", "expected", "message"),
    [
        (65535 - MAX_INDEX + 1, (), "port_base"),
        (0, (), "port_base"),
        (BASE, ["192.168.50.101", "192.168.50.101"], "duplicate expected IP"),
        (BASE, ["192.168.50.999"], "not an IPv4 address"),
        (BASE, [f"10.0.{i >> 8}.{i & 0xFF}" for i in range(MAX_INDEX + 1)], "at most"),
    ],
)
def test_invalid_construction(path, port_base, expected, message):
    with pytest.raises(ValueError, match=message):
        PortMap(path, port_base, expected)


def test_next_free_skips_indexes_taken_by_pins(path):
    pm = fresh(path)
    pm.assign(A, pin=BASE + 11)
    assert pm.assign(B, ip="192.168.50.50") == BASE + 12


def test_read_only_load_never_touches_temp_files(path):
    fresh(path).assign(A, ip="192.168.50.101")
    in_flight = path.parent / ".ports.json.w1r2.tmp"
    in_flight.write_text("{}")
    pm = PortMap.load(path, BASE, EXPECTED, read_only=True)
    assert pm.port(A) == 16102
    assert in_flight.exists()


def test_clean_temp_false_still_keeps_temp_files(path):
    fresh(path).assign(A, ip="192.168.50.101")
    in_flight = path.parent / ".ports.json.w1r2.tmp"
    in_flight.write_text("{}")
    PortMap.load(path, BASE, EXPECTED, clean_temp=False)
    assert in_flight.exists()


def snapshot(directory):
    """Every entry under ``directory`` with its bytes and mtime, or None if absent."""
    if not directory.exists():
        return None
    return {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in directory.iterdir()}


def test_read_only_load_of_a_missing_file_creates_nothing(path):
    pm = PortMap.load(path, BASE, EXPECTED, read_only=True)
    assert pm.pinned() == {}
    assert pm.read_only
    assert not path.parent.exists()


def test_read_only_assign_previews_in_memory_and_writes_nothing(path):
    writer = fresh(path)
    writer.assign(A, ip="192.168.50.101")
    before = snapshot(path.parent)
    preview = PortMap.load(path, BASE, EXPECTED, read_only=True)
    assert preview.assign(A, ip="192.168.50.101") == 16102
    assert preview.assign(B, ip="192.168.50.50") == BASE + 11
    assert preview.assign(C, pin=BASE + 1) == BASE + 1  # moves A, in memory only
    assert preview.port(A) == BASE + 12
    assert snapshot(path.parent) == before
    assert PortMap.load(path, BASE, EXPECTED).pinned() == {A: 16102}


def test_a_read_only_preview_matches_what_the_writer_pins(path, tmp_path):
    steps = [
        (A, "192.168.50.50", None),
        (B, "192.168.50.102", None),
        (C, None, BASE + 2),
    ]
    preview = PortMap.load(path, BASE, EXPECTED, read_only=True)
    writer = PortMap.load(tmp_path / "other" / "ports.json", BASE, EXPECTED)
    for mac, ip, pin in steps:
        assert preview.assign(mac, ip=ip, pin=pin) == writer.assign(mac, ip=ip, pin=pin)
    assert preview.pinned() == writer.pinned()
    assert not path.parent.exists()


def test_a_corrupt_file_still_fails_closed_when_read_only(path):
    path.parent.mkdir(parents=True)
    path.write_text("{")
    with pytest.raises(PortMapError, match="not valid JSON"):
        PortMap.load(path, BASE, EXPECTED, read_only=True)
    assert path.read_text() == "{"


def test_root_is_recognized_by_the_router_ip(path):
    pm = PortMap.load(path, BASE, EXPECTED, root_ip="192.168.50.1")
    assert pm.assign(ROOT, ip="192.168.50.1") == BASE
    assert pm.assign(A, ip="192.168.50.101") == 16102
    assert pm.port(ROOT) is None
    assert on_disk(path)["nodes"] == {A: 1}


def test_root_ip_inside_the_expected_range_still_gets_index_zero(path):
    pm = PortMap.load(path, BASE, EXPECTED, root_ip="192.168.50.105")
    assert pm.assign(ROOT, ip="192.168.50.105") == BASE


def test_hostname_root_needs_the_root_flag(path):
    pm = PortMap.load(path, BASE, EXPECTED, root_ip="router.asus.com")
    assert pm.assign(ROOT, ip="192.168.50.1") == BASE + 11
    assert pm.assign(B, ip="192.168.50.7", root=True) == BASE
