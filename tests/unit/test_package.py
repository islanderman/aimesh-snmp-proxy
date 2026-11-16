import tomllib
from pathlib import Path

import aimesh_snmp_proxy

PYPROJECT = Path(__file__).resolve().parents[2] / "pyproject.toml"


def test_version_matches_installed_metadata():
    project = tomllib.loads(PYPROJECT.read_text())["project"]
    assert aimesh_snmp_proxy.__version__ == project["version"]
