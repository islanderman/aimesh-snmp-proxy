import json
import logging
import os
import stat

import pytest

from aimesh_snmp_proxy.collector import statefile
from aimesh_snmp_proxy.collector.statefile import StateFileError


def test_round_trip_writes_owner_only_file_without_leftovers(tmp_path):
    path = tmp_path / "state" / "x.json"
    statefile.write_json(path, {"b": 1, "a": [1, 2]})
    assert statefile.read_json(path) == {"a": [1, 2], "b": 1}
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(path.parent).st_mode) == 0o700
    assert sorted(p.name for p in path.parent.iterdir()) == ["x.json"]


def test_missing_file_reads_as_none(tmp_path):
    assert statefile.read_json(tmp_path / "absent.json") is None


@pytest.mark.parametrize("content", [b"{not json", b"\xff\xfe", b"x" * (2 << 20)])
def test_corrupt_file_is_moved_aside_and_reads_as_none(tmp_path, caplog, content):
    path = tmp_path / "x.json"
    path.write_bytes(content)
    with caplog.at_level(logging.ERROR):
        assert statefile.read_json(path) is None
    assert not path.exists()
    assert (tmp_path / "x.json.corrupt").read_bytes() == content
    assert "x.json" in caplog.text


def test_overwrite_replaces_content(tmp_path):
    path = tmp_path / "x.json"
    statefile.write_json(path, {"v": 1})
    statefile.write_json(path, {"v": 2})
    assert json.loads(path.read_text()) == {"v": 2}


def test_unwritable_location_raises_state_file_error(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("")
    with pytest.raises(StateFileError, match="cannot write"):
        statefile.write_json(blocker / "x.json", {})
