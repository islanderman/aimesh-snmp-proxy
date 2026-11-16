"""Shared helpers for the deploy tests: repo paths and a systemd unit-file parser."""

from __future__ import annotations

import base64
import hashlib
import os
import re
import shutil
import subprocess
import sys
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
DEPLOY = REPO / "deploy"

_SECTION = re.compile(r"\[([A-Za-z]+)\]$")
_DIRECTIVE = re.compile(r"([A-Za-z0-9]+)=(.*)$")

Unit = dict[str, list[tuple[str, str]]]


def parse_unit(text: str) -> Unit:
    """Parse unit-file text the way systemd reads it, rejecting what it would misread.

    Raises ValueError on a malformed line, a trailing comment, or a directive
    outside a section.
    """
    unit: Unit = {}
    section: str | None = None
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip() or line.lstrip()[0] in "#;":
            continue
        if line != line.strip():
            raise ValueError(f"line {number}: leading or trailing whitespace")
        header = _SECTION.match(line)
        if header:
            section = header.group(1)
            unit.setdefault(section, [])
            continue
        directive = _DIRECTIVE.match(line)
        if directive is None or section is None:
            raise ValueError(f"line {number}: not a section or Key=Value: {line!r}")
        key, value = directive.groups()
        if " #" in value or " ;" in value:
            raise ValueError(f"line {number}: systemd has no trailing comments")
        unit[section].append((key, value))
    return unit


def comment_runs(text: str) -> list[tuple[int, int]]:
    """``(first line, length)`` of every run of consecutive ``#`` comment lines."""
    runs: list[tuple[int, int]] = []
    start = length = 0
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        is_comment = stripped.startswith("#") and not stripped.startswith("#!")
        if is_comment:
            if not length:
                start = number
            length += 1
        elif length:
            runs.append((start, length))
            length = 0
    if length:
        runs.append((start, length))
    return runs


@pytest.fixture(scope="session")
def repo() -> Path:
    return REPO


@pytest.fixture(scope="session")
def deploy_dir() -> Path:
    return DEPLOY


@pytest.fixture(scope="session")
def unit_parser() -> Callable[[str], Unit]:
    return parse_unit


@pytest.fixture(scope="session")
def comment_run_finder() -> Callable[[str], list[tuple[int, int]]]:
    return comment_runs


# --- a fake host for install.sh: command stubs, a fake bundle, a fake interpreter ---

STUB_SCRIPTS = {
    "id": """#!/bin/sh
if [ "$1" = "-u" ]; then echo "${FAKE_UID:-0}"; exit 0; fi
exec /usr/bin/id "$@"
""",
    "chown": """#!/bin/sh
echo "chown $*" >> "$STUB_LOG"
""",
    "systemctl": """#!/bin/sh
echo "systemctl $*" >> "$STUB_LOG"
case "$1" in
  --version)
    echo "systemd ${FAKE_SYSTEMD:-252} (${FAKE_SYSTEMD:-252}.1-fake)"
    echo "+PAM +AUDIT"
    ;;
  is-active)
    state="${FAKE_STATE:-inactive}"
    case " ${FAKE_ACTIVE_UNITS:-} " in *" $2 "*) state=active ;; esac
    case " ${FAKE_LOADED_UNITS:-} " in
      *" $2 "*) state="${FAKE_LOADED_STATE:-active}" ;;
    esac
    echo "$state"
    [ "$state" = active ] && exit 0
    exit 3
    ;;
  list-units)
    for unit in ${FAKE_LOADED_UNITS:-}; do
      echo "  $unit loaded ${FAKE_LOADED_STATE:-active} running ASUS router SNMP proxy"
    done
    ;;
esac
exit 0
""",
    "getent": """#!/bin/sh
echo "getent $*" >> "$STUB_LOG"
if [ "$1 $2" = "passwd aimesh-snmp-proxy" ] && [ "${FAKE_USER_EXISTS:-0}" = 1 ]; then
  echo "aimesh-snmp-proxy:x:998:998::/nonexistent:/usr/sbin/nologin"
  exit 0
fi
exit 2
""",
    "systemd-analyze": """#!/bin/sh
echo "systemd-analyze $*" >> "$STUB_LOG"
if [ "$1" = verify ] && [ "${FAKE_VERIFY_FAIL:-0}" = 1 ]; then
  echo "unit has a problem" >&2
  exit 1
fi
[ "$1" = verify ] || echo "Overall exposure level for the unit: 1.5 OK"
exit 0
""",
    "useradd": """#!/bin/sh
echo "useradd $*" >> "$STUB_LOG"
""",
    "userdel": """#!/bin/sh
echo "userdel $*" >> "$STUB_LOG"
""",
}

# Answers the probes install.sh makes, fakes `-m venv` and `-m pip`, and hands
# everything else (the allow-list script on stdin) to the real interpreter.
FAKE_PYTHON = """#!/bin/sh
echo "python $*" >> "$STUB_LOG"
case "$*" in
  *sys.version_info*) echo "${FAKE_PYVER:-3.12.1}"; exit 0 ;;
  *"import venv, ensurepip"*) [ "${FAKE_NO_VENV:-0}" = 1 ] && exit 1; exit 0 ;;
  *"realpath(sys.executable)"*) echo "/usr/bin/python3.12"; exit 0 ;;
  *"-m venv"*)
    for last; do :; done
    mkdir -p "$last/bin"
    cp "$0" "$last/bin/python"
    chmod 755 "$last/bin/python"
    echo "built by the fake venv" > "$last/MARKER"
    exit 0 ;;
  *"-m pip install"*) [ "${FAKE_PIP_FAIL:-0}" = 1 ] && exit 1; exit 0 ;;
  *"-m pip check"*) exit 0 ;;
  *"import aimesh_snmp_proxy"*) exit 0 ;;
esac
exec "$FAKE_REAL_PYTHON" "$@"
"""

FAKE_UV = """#!/bin/sh
echo "uv $*" >> "$STUB_LOG"
if [ "$1" = venv ]; then
  for last; do :; done
  mkdir -p "$last/bin"
  cp "$FAKE_PYTHON_PATH" "$last/bin/python"
  chmod 755 "$last/bin/python"
fi
exit 0
"""


def _b64_digest(data: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def make_wheel(
    directory: Path,
    name: str,
    version: str,
    files: dict[str, str],
    requires: tuple[str, ...] = (),
) -> Path:
    """Write a tiny valid pure-Python wheel, with fixed timestamps; return its path."""
    dist = f"{name}-{version}"
    meta = ["Metadata-Version: 2.1", f"Name: {name}", f"Version: {version}"]
    meta += [f"Requires-Dist: {req}" for req in requires]
    members = {
        **files,
        f"{dist}.dist-info/METADATA": "\n".join(meta) + "\n",
        f"{dist}.dist-info/WHEEL": "Wheel-Version: 1.0\nGenerator: tests\n"
        "Root-Is-Purelib: true\nTag: py3-none-any\n",
    }
    record = [
        f"{path},sha256={_b64_digest(body.encode())},{len(body.encode())}"
        for path, body in members.items()
    ]
    record.append(f"{dist}.dist-info/RECORD,,")
    members[f"{dist}.dist-info/RECORD"] = "\n".join(record) + "\n"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{dist}-py3-none-any.whl"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for member, body in members.items():
            info = zipfile.ZipInfo(member, date_time=(2020, 1, 1, 0, 0, 0))
            info.external_attr = 0o644 << 16
            zf.writestr(info, body)
    return path


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@dataclass(frozen=True)
class Bundle:
    root: Path
    index: Path  # stands in for PyPI: holds the third-party wheel


@pytest.fixture(scope="session")
def bundle(tmp_path_factory: pytest.TempPathFactory) -> Bundle:
    """An unpacked bundle: real install.sh and unit, fake wheels, a hashed lock."""
    root = tmp_path_factory.mktemp("bundle")
    index = tmp_path_factory.mktemp("index")
    (root / "deploy").mkdir()
    shutil.copy2(DEPLOY / "install.sh", root / "deploy" / "install.sh")
    shutil.copy2(DEPLOY / "aimesh-snmp-proxy.service", root / "deploy")
    shutil.copy2(DEPLOY / "aimesh-snmp-proxy@.service", root / "deploy")
    shutil.copy2(REPO / "config.example.toml", root)
    (root / "deploy" / "install.sh").chmod(0o755)
    ar_sha = "0123456789abcdef0123456789abcdef01234567"
    own = make_wheel(
        root / "wheels",
        "aimesh_snmp_proxy",
        "0.1.0",
        {"aimesh_snmp_proxy/__init__.py": '__version__ = "0.1.0"\n'},
        requires=(
            f"asusrouter @ git+https://example.invalid/asusrouter@{ar_sha}",
            "fakedep==1.0",
        ),
    )
    router = make_wheel(
        root / "wheels",
        "asusrouter",
        "2.0.0.dev0",
        {"asusrouter/__init__.py": "\n"},
    )
    dep = make_wheel(index, "fakedep", "1.0", {"fakedep/__init__.py": "\n"})
    lock = [
        "# fake lock for tests",
        f"fakedep==1.0 \\\n    --hash=sha256:{sha256_file(dep)}",
        f"./wheels/{own.name} \\\n    --hash=sha256:{sha256_file(own)}",
        f"./wheels/{router.name} \\\n    --hash=sha256:{sha256_file(router)}",
    ]
    (root / "requirements.txt").write_text("\n".join(lock) + "\n")
    write_sums(root)
    return Bundle(root, index)


def write_sums(root: Path) -> None:
    """(Re)write SHA256SUMS for every file under root, the way build-bundle.sh does."""
    files = sorted(p for p in root.rglob("*") if p.is_file() and p.name != "SHA256SUMS")
    lines = [f"{sha256_file(p)}  {p.relative_to(root).as_posix()}" for p in files]
    (root / "SHA256SUMS").write_text("\n".join(lines) + "\n")


def _path_without(command: str) -> str:
    """The caller's PATH minus every directory that holds ``command``."""
    keep = [
        part
        for part in os.environ.get("PATH", "").split(os.pathsep)
        if part and not (Path(part) / command).exists()
    ]
    return os.pathsep.join(keep)


@dataclass
class FakeHost:
    """A DESTDIR tree plus command stubs; ``run`` executes the bundle's install.sh."""

    root: Path
    stubs: Path
    log: Path
    bundle: Bundle
    bundle_dir: Path

    @property
    def etc(self) -> Path:
        return self.root / "etc" / "aimesh-snmp-proxy"

    @property
    def opt(self) -> Path:
        return self.root / "opt" / "aimesh-snmp-proxy"

    @property
    def unit(self) -> Path:
        return self.root / "etc" / "systemd" / "system" / "aimesh-snmp-proxy.service"

    @property
    def units(self) -> Path:
        return self.root / "etc" / "systemd" / "system"

    @property
    def template(self) -> Path:
        return self.units / "aimesh-snmp-proxy@.service"

    def instance_etc(self, name: str) -> Path:
        return self.etc / name

    def dropin(self, name: str) -> Path:
        return self.units / f"aimesh-snmp-proxy@{name}.service.d" / "10-ip-allow.conf"

    def instance_state(self, name: str) -> Path:
        return self.root / "var" / "lib" / f"aimesh-snmp-proxy-{name}"

    @property
    def fake_python(self) -> Path:
        return self.stubs / "fakepython"

    def calls(self, program: str | None = None) -> list[str]:
        lines = self.log.read_text().splitlines() if self.log.exists() else []
        return [ln for ln in lines if program is None or ln.startswith(program + " ")]

    def stub_uv(self) -> None:
        (self.stubs / "uv").write_text(FAKE_UV)
        (self.stubs / "uv").chmod(0o755)

    def env(self, **extra: str) -> dict[str, str]:
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("PYTHON", "PIP_", "UV_", "VIRTUAL_ENV", "DESTDIR"))
        }
        has_uv = (self.stubs / "uv").exists()
        base_path = os.environ.get("PATH", "") if has_uv else _path_without("uv")
        env.update(
            PATH=f"{self.stubs}{os.pathsep}{base_path}",
            HOME=str(self.root / "home"),
            DESTDIR=str(self.root),
            STUB_LOG=str(self.log),
            FAKE_REAL_PYTHON=sys.executable,
            FAKE_PYTHON_PATH=str(self.fake_python),
            PIP_CONFIG_FILE=os.devnull,
            PIP_NO_INDEX="1",
            PIP_FIND_LINKS=str(self.bundle.index),
            PIP_DISABLE_PIP_VERSION_CHECK="1",
            UV_NO_INDEX="1",
            UV_FIND_LINKS=str(self.bundle.index),
            UV_NO_CONFIG="1",
        )
        env.update(extra)
        return env

    def run(
        self,
        *args: str,
        bash: str | None = None,
        uid: int = 0,
        systemd: int = 252,
        state: str = "inactive",
        python: str | None = None,
        search: bool = False,
        stdin: str | None = None,
        **extra_env: str,
    ) -> subprocess.CompletedProcess[str]:
        cmd = [bash or BASH, str(self.bundle_dir / "deploy" / "install.sh"), *args]
        wants_python = "--python" not in args and "--uninstall" not in args
        if wants_python and not search:
            cmd += ["--python", python or str(self.fake_python)]
        env = self.env(
            FAKE_UID=str(uid), FAKE_SYSTEMD=str(systemd), FAKE_STATE=state, **extra_env
        )
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env,
            input=stdin,
            stdin=None if stdin is not None else subprocess.DEVNULL,
            timeout=300,
            check=False,
        )


BASH = shutil.which("bash") or "/bin/bash"
BASHES = sorted({b for b in (BASH, "/bin/bash") if Path(b).exists()})


@pytest.fixture
def host(tmp_path: Path, bundle: Bundle) -> FakeHost:
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    for name, body in STUB_SCRIPTS.items():
        (stubs / name).write_text(body)
        (stubs / name).chmod(0o755)
    (stubs / "fakepython").write_text(FAKE_PYTHON)
    (stubs / "fakepython").chmod(0o755)
    root = tmp_path / "root"
    root.mkdir()
    bundle_dir = tmp_path / "bundle"
    shutil.copytree(bundle.root, bundle_dir, symlinks=True)
    return FakeHost(root, stubs, tmp_path / "calls.log", bundle, bundle_dir)


@pytest.fixture(scope="session")
def rewrite_sums() -> Callable[[Path], None]:
    return write_sums
