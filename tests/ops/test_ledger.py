import json
import os
import stat

import pytest

from aimesh_snmp_proxy.ops import ledger as ledger_mod
from aimesh_snmp_proxy.ops.ledger import Entry, Ledger, LedgerError

ORIGIN = "https://192.168.50.10:443"


def entry(hostname="aimesh-00000a", device_id=500, port=16102):
    return Entry(hostname, device_id, port, ORIGIN, "2026-11-13T20:00:00Z")


@pytest.fixture
def path(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    return state / "onboarded.json"


def test_a_missing_file_is_an_empty_ledger(path):
    assert Ledger.load(path).entries() == []
    assert not path.exists()


def test_record_writes_an_owner_only_file_that_loads_back(path):
    ledger = Ledger.load(path)
    ledger.record(entry())
    ledger.record(entry("aimesh-root", 499, 16101))
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    doc = json.loads(path.read_text())
    assert doc["version"] == 1
    assert doc["devices"]["aimesh-00000a"] == {
        "device_id": 500,
        "port": 16102,
        "origin": ORIGIN,
        "added": "2026-11-13T20:00:00Z",
    }
    assert Ledger.load(path).entries() == [entry("aimesh-root", 499, 16101), entry()]
    assert sorted(p.name for p in path.parent.iterdir()) == ["onboarded.json"]


def test_forget_removes_one_entry_and_saves(path):
    ledger = Ledger.load(path)
    ledger.record(entry())
    ledger.record(entry("aimesh-00000b", 501, 16103))
    ledger.forget("aimesh-00000a")
    assert [e.hostname for e in Ledger.load(path).entries()] == ["aimesh-00000b"]
    assert ledger.get("aimesh-00000a") is None
    assert ledger.get("aimesh-00000b").device_id == 501


def test_save_creates_an_empty_ledger(path):
    Ledger.load(path).save()
    assert json.loads(path.read_text()) == {"version": 1, "devices": {}}


def test_save_never_creates_the_state_directory(tmp_path):
    with pytest.raises(LedgerError, match="cannot write"):
        Ledger.load(tmp_path / "missing" / "onboarded.json").save()
    assert not (tmp_path / "missing").exists()


def test_a_failed_rename_leaves_no_temp_file(path, monkeypatch):
    ledger = Ledger.load(path)

    def broken(src, dst):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(ledger_mod.os, "replace", broken)
    with pytest.raises(LedgerError, match="No space left"):
        ledger.record(entry())
    assert list(path.parent.iterdir()) == []


@pytest.mark.parametrize(
    "content",
    [
        "not json",
        "[]",
        '{"version": 2, "devices": {}}',
        '{"version": 1}',
        '{"version": 1, "devices": [], "extra": 1}',
        '{"version": 1, "devices": {"h": {"device_id": "7", "port": 1, '
        '"origin": "o", "added": "a"}}}',
        '{"version": 1, "devices": {"h": {"device_id": true, "port": 1, '
        '"origin": "o", "added": "a"}}}',
        '{"version": 1, "devices": {"h": {"device_id": 7, "port": 1, "origin": "o"}}}',
        '{"version": 1, "devices": {"": {"device_id": 7, "port": 1, '
        '"origin": "o", "added": "a"}}}',
    ],
)
def test_an_unusable_file_fails_closed_untouched(path, content):
    path.write_text(content)
    with pytest.raises(LedgerError, match=r"onboarded\.json"):
        Ledger.load(path)
    assert path.read_text() == content


def test_an_unreadable_file_is_a_ledger_error(path):
    path.write_text("{}")
    path.chmod(0)
    try:
        if os.access(path, os.R_OK):
            pytest.skip("running as root: permissions do not apply")
        with pytest.raises(LedgerError, match="cannot read"):
            Ledger.load(path)
    finally:
        path.chmod(0o600)
