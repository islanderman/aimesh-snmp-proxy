"""scripts/generate-config.sh: find the CLI and hand every argument to ``init``."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "generate-config.sh"
INSTALLED = Path("/opt/aimesh-snmp-proxy/venv/bin/aimesh-snmp-proxy")
SHELLCHECK = shutil.which("shellcheck")
BASH = shutil.which("bash")
needs_no_install = pytest.mark.skipif(
    INSTALLED.exists(), reason="an installed CLI would win the lookup"
)


def stub(folder: Path, name: str) -> Path:
    """An executable that records its arguments, one per line, in ARGS."""
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / name
    path.write_text('#!/bin/sh\nprintf "%s\\n" "$0" "$@" >"$ARGS"\n')
    path.chmod(0o755)
    return path


def run(script: Path, tmp_path: Path, path: str, **env: str):
    args = tmp_path / "args.txt"
    clean = {"PATH": path, "ARGS": str(args), "HOME": str(tmp_path), **env}
    result = subprocess.run(
        [BASH, str(script), "--host", "192.168.50.1", "--dry-run"],
        env=clean,
        capture_output=True,
        text=True,
        check=False,
    )
    called = args.read_text().splitlines() if args.exists() else []
    return result, called


def test_the_named_cli_gets_init_and_every_argument(tmp_path):
    cli = stub(tmp_path / "bin", "my-cli")
    result, called = run(SCRIPT, tmp_path, "/usr/bin:/bin", AIMESH_SNMP_PROXY=str(cli))
    assert result.returncode == 0, result.stderr
    assert called == [str(cli), "init", "--host", "192.168.50.1", "--dry-run"]


@needs_no_install
def test_the_cli_on_path_is_found(tmp_path):
    cli = stub(tmp_path / "bin", "aimesh-snmp-proxy")
    result, called = run(SCRIPT, tmp_path, f"{cli.parent}:/usr/bin:/bin")
    assert result.returncode == 0, result.stderr
    assert called[1:] == ["init", "--host", "192.168.50.1", "--dry-run"]


@needs_no_install
def test_a_checkout_runs_through_uv(tmp_path):
    repo = tmp_path / "repo"
    (repo / "scripts").mkdir(parents=True)
    (repo / "pyproject.toml").write_text("[project]\n")
    script = repo / "scripts" / SCRIPT.name
    shutil.copy(SCRIPT, script)
    uv = stub(tmp_path / "bin", "uv")
    result, called = run(script, tmp_path, f"{uv.parent}:/usr/bin:/bin")
    assert result.returncode == 0, result.stderr
    assert called[1:] == [
        *("run", "--frozen", "--quiet", "--project", str(repo.resolve())),
        *("aimesh-snmp-proxy", "init", "--host", "192.168.50.1", "--dry-run"),
    ]


@needs_no_install
def test_no_cli_anywhere_exits_127(tmp_path):
    script = tmp_path / "lone" / SCRIPT.name
    script.parent.mkdir()
    shutil.copy(SCRIPT, script)
    result, called = run(script, tmp_path, "/usr/bin:/bin")
    assert result.returncode == 127
    assert "deploy/install.sh" in result.stderr
    assert called == []


def test_the_script_is_executable():
    assert os.access(SCRIPT, os.X_OK)


@pytest.mark.skipif(SHELLCHECK is None, reason="shellcheck not installed")
def test_the_script_is_shellcheck_clean():
    result = subprocess.run(
        [SHELLCHECK, str(SCRIPT)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stdout
