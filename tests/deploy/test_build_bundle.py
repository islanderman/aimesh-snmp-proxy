"""build-bundle.sh with a fake uv, a throwaway git repo and a local git dependency."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

BASH = shutil.which("bash") or "/bin/bash"
GIT = shutil.which("git")
TAR = shutil.which("tar")
HEX64 = "a" * 64
EPOCH = 1_760_000_000

# Stands in for uv: `build` writes a wheel named after the pyproject in SOURCE_DIR,
# `export` copies the lock the test chose; neither needs a network.
FAKE_UV = f"""#!{sys.executable}
import os, re, shutil, sys, zipfile
from pathlib import Path

args = sys.argv[1:]
with open(os.environ["STUB_LOG"], "a") as log:
    log.write("uv " + " ".join(args) + "\\n")
    if args[0] == "build":
        epoch = os.environ.get("SOURCE_DATE_EPOCH", "")
        log.write("SOURCE_DATE_EPOCH=" + epoch + "\\n")
if args[0] == "export":
    shutil.copy(os.environ["FAKE_UV_EXPORT"], args[args.index("-o") + 1])
    print("the lock, echoed to stdout")
elif args[0] == "build":
    epoch = int(os.environ["SOURCE_DATE_EPOCH"])
    out, src = Path(args[args.index("--out-dir") + 1]), Path(args[-1])
    text = (src / "pyproject.toml").read_text()
    name = re.search(r'^name = "([^"]+)"', text, re.M).group(1).replace("-", "_")
    version = re.search(r'^version = "([^"]+)"', text, re.M).group(1)
    out.mkdir(parents=True, exist_ok=True)
    (out / ".gitignore").write_text("*")
    path = out / f"{{name}}-{{version}}-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as zf:
        info = zipfile.ZipInfo(f"{{name}}/__init__.py", date_time=(2020, 1, 1, 0, 0, 0))
        zf.writestr(info, f"# built from {{src.name}} at {{epoch}}\\n")
else:
    sys.exit("fake uv: unexpected " + " ".join(args))
"""


def git(repo: Path, *args: str) -> str:
    env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    env.update(
        GIT_AUTHOR_NAME="T",
        GIT_AUTHOR_EMAIL="t@example.invalid",
        GIT_COMMITTER_NAME="T",
        GIT_COMMITTER_EMAIL="t@example.invalid",
        GIT_AUTHOR_DATE=f"{EPOCH} +0000",
        GIT_COMMITTER_DATE=f"{EPOCH} +0000",
    )
    result = subprocess.run(
        [GIT, "-C", str(repo), *args],
        capture_output=True,
        text=True,
        env=env,
        check=True,
    )
    return result.stdout.strip()


def commit_all(repo: Path, message: str = "x") -> str:
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "--no-gpg-sign", "-m", message)
    return git(repo, "rev-parse", "HEAD")


@pytest.fixture
def world(tmp_path: Path, repo: Path):
    tmp_path = tmp_path / "world"
    tmp_path.mkdir()
    """A throwaway project repo, a local 'asusrouter' repo, a fake uv, and a runner."""
    dep = tmp_path / "asusrouter-src"
    (dep / "asusrouter").mkdir(parents=True)
    (dep / "pyproject.toml").write_text(
        '[project]\nname = "asusrouter"\nversion = "2.0.0.dev0"\n'
    )
    (dep / "asusrouter" / "__init__.py").write_text("\n")
    git(tmp_path, "init", "-q", str(dep))
    git(dep, "config", "uploadpack.allowAnySHA1InWant", "true")
    dep_sha = commit_all(dep)

    proj = tmp_path / "proj"
    (proj / "deploy").mkdir(parents=True)
    (proj / "src" / "aimesh_snmp_proxy").mkdir(parents=True)
    (proj / "pyproject.toml").write_text(
        '[project]\nname = "aimesh-snmp-proxy"\nversion = "0.1.0"\n'
    )
    (proj / "uv.lock").write_text("# fake\n")
    (proj / "src" / "aimesh_snmp_proxy" / "__init__.py").write_text("\n")
    (proj / "README.md").write_text("committed readme\n")
    shutil.copy2(repo / "config.example.toml", proj)
    for item in (repo / "deploy").iterdir():
        shutil.copy2(item, proj / "deploy")
    git(tmp_path, "init", "-q", str(proj))
    head = commit_all(proj)

    lock = tmp_path / "lock.txt"
    lock.write_text(
        f"fakedep==1.0 \\\n    --hash=sha256:{HEX64}\n"
        "cffi==2.1.1 ; platform_python_implementation != 'PyPy' \\\n"
        f"    --hash=sha256:{'b' * 64} \\\n    --hash=sha256:{'c' * 64}\n"
        f"asusrouter @ git+{dep.as_uri()}@{dep_sha}\n"
    )
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    (stubs / "uv").write_text(FAKE_UV)
    (stubs / "uv").chmod(0o755)
    tmp_dir = tmp_path / "tmp"
    tmp_dir.mkdir()

    class World:
        pass

    w = World()
    w.proj, w.dep, w.dep_sha, w.head, w.lock = proj, dep, dep_sha, head, lock
    w.log, w.tmp, w.out = tmp_path / "uv.log", tmp_dir, tmp_path / "out"

    def run(
        *args: str, path: str | None = None, bash: str = BASH
    ) -> subprocess.CompletedProcess[str]:
        env = {k: v for k, v in os.environ.items() if not k.startswith(("UV_", "GIT_"))}
        env.update(
            PATH=path
            if path is not None
            else f"{stubs}{os.pathsep}{os.environ['PATH']}",
            STUB_LOG=str(w.log),
            FAKE_UV_EXPORT=str(w.lock),
            TMPDIR=str(tmp_dir),
            HOME=str(tmp_path / "home"),
            GIT_CONFIG_GLOBAL=os.devnull,
            GIT_CONFIG_NOSYSTEM="1",
        )
        cmd = [bash, str(proj / "deploy" / "build-bundle.sh"), *args]
        return subprocess.run(cmd, capture_output=True, text=True, env=env, check=False)

    w.run = run
    w.archive = w.out / "aimesh-snmp-proxy-0.1.0.tar.gz"
    return w


pytestmark = pytest.mark.skipif(
    GIT is None or TAR is None, reason="git and tar are required"
)


def logical_entries(text: str) -> list[str]:
    """Requirements entries with continuation lines joined and spaces squeezed."""
    joined = re.sub(r"\\\n\s*", " ", text)
    lines = [ln for ln in joined.splitlines() if ln.strip() and not ln.startswith("#")]
    return [re.sub(r"\s+", " ", ln).strip() for ln in lines]


def unpack(archive: Path, dest: Path) -> Path:
    dest.mkdir()
    subprocess.run([TAR, "-xzf", str(archive), "-C", str(dest)], check=True)
    (top,) = dest.iterdir()
    return top


def test_builds_a_complete_root_owned_bundle(world):
    result = world.run("--out-dir", str(world.out))
    assert result.returncode == 0, result.stderr
    assert "the lock, echoed" not in result.stdout
    sums = (world.out / (world.archive.name + ".sha256")).read_text()
    digest = hashlib.sha256(world.archive.read_bytes()).hexdigest()
    assert sums == f"{digest}  {world.archive.name}\n"
    with tarfile.open(world.archive) as tf:
        members = {m.name: m for m in tf.getmembers()}
    top = "aimesh-snmp-proxy-0.1.0"
    assert set(members) == {
        top,
        f"{top}/SHA256SUMS",
        f"{top}/README.md",
        f"{top}/config.example.toml",
        f"{top}/requirements.txt",
        f"{top}/deploy",
        f"{top}/deploy/install.sh",
        f"{top}/deploy/build-bundle.sh",
        f"{top}/deploy/aimesh-snmp-proxy.service",
        f"{top}/deploy/aimesh-snmp-proxy@.service",
        f"{top}/wheels",
        f"{top}/wheels/aimesh_snmp_proxy-0.1.0-py3-none-any.whl",
        f"{top}/wheels/asusrouter-2.0.0.dev0-py3-none-any.whl",
    }
    for member in members.values():
        assert (member.uid, member.gid, member.uname, member.gname) == (
            0,
            0,
            "root",
            "root",
        )
        assert member.mtime == EPOCH
        want = 0o755 if member.isdir() or member.name.endswith(".sh") else 0o644
        assert stat.S_IMODE(member.mode) == want, member.name


def test_every_requirement_is_hash_pinned_and_the_git_dependency_is_a_wheel(world):
    assert world.run("--out-dir", str(world.out)).returncode == 0
    root = unpack(world.archive, world.out.parent / "x")
    text = (root / "requirements.txt").read_text()
    entries = logical_entries(text)
    assert all(re.search(r"--hash=sha256:[0-9a-f]{64}$", e) for e in entries)
    assert not re.search(r"git\+| @ |https?:", text)
    assert entries[0].startswith(f"fakedep==1.0 --hash=sha256:{HEX64}")
    assert (
        "cffi==2.1.1 ; platform_python_implementation != 'PyPy' --hash=" in entries[1]
    )
    local = {e.split()[0]: e for e in entries[2:]}
    assert set(local) == {
        "./wheels/aimesh_snmp_proxy-0.1.0-py3-none-any.whl",
        "./wheels/asusrouter-2.0.0.dev0-py3-none-any.whl",
    }
    for path, entry in local.items():
        digest = hashlib.sha256((root / path).read_bytes()).hexdigest()
        assert entry.endswith(f"--hash=sha256:{digest}")
    assert world.head in text


def test_wheels_are_built_from_the_pinned_commits_with_the_commit_time(world):
    assert world.run("--out-dir", str(world.out)).returncode == 0
    log = world.log.read_text().splitlines()
    builds = [ln for ln in log if ln.startswith("uv build")]
    assert len(builds) == 2
    assert all("--wheel" in b and "--out-dir" in b for b in builds)
    assert log.count(f"SOURCE_DATE_EPOCH={EPOCH}") == 2
    (export,) = [ln for ln in log if ln.startswith("uv export")]
    for flag in (
        "--frozen",
        "--no-dev",
        "--no-emit-project",
        "--format requirements-txt",
    ):
        assert flag in export


def test_checksums_cover_every_file_and_install_sh_accepts_the_bundle(world, host):
    assert world.run("--out-dir", str(world.out)).returncode == 0
    root = unpack(world.archive, world.out.parent / "x")
    lines = (root / "SHA256SUMS").read_text().splitlines()
    files = sorted(
        p.relative_to(root).as_posix()
        for p in root.rglob("*")
        if p.is_file() and p.name != "SHA256SUMS"
    )
    assert [ln.split("  ", 1)[1] for ln in lines] == files
    for line in lines:
        digest, name = line.split("  ", 1)
        assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest
    host.bundle_dir = root
    result = host.run("--dry-run", uid=1000)
    assert result.returncode == 0, result.stderr
    assert "bundle files match SHA256SUMS" in result.stdout
    assert "install aimesh-snmp-proxy 0.1.0" in result.stdout


def test_two_builds_of_one_commit_are_byte_identical(world):
    assert world.run("--out-dir", str(world.out)).returncode == 0
    first = world.archive.read_bytes()
    assert world.run("--out-dir", str(world.out)).returncode == 0
    assert world.archive.read_bytes() == first


@pytest.mark.skipif(
    not Path("/bin/bash").exists() or Path("/bin/bash").samefile(BASH),
    reason="no second bash to compare",
)
def test_the_system_bash_builds_the_same_bytes(world):
    assert world.run("--out-dir", str(world.out)).returncode == 0
    first = world.archive.read_bytes()
    assert world.run("--out-dir", str(world.out), bash="/bin/bash").returncode == 0
    assert world.archive.read_bytes() == first


def test_bundles_the_commit_not_the_working_tree(world):
    (world.proj / "README.md").write_text("dirty readme\n")
    result = world.run("--out-dir", str(world.out))
    assert result.returncode == 0
    assert "uncommitted changes are NOT in the bundle" in result.stderr
    root = unpack(world.archive, world.out.parent / "x")
    assert (root / "README.md").read_text() == "committed readme\n"


def test_default_output_is_dist_in_the_repo(world):
    assert world.run().returncode == 0
    assert (world.proj / "dist" / "aimesh-snmp-proxy-0.1.0.tar.gz").exists()


def test_scratch_space_is_always_removed(world):
    assert world.run("--out-dir", str(world.out)).returncode == 0
    world.lock.write_text("evil==1.0\n")
    assert world.run("--out-dir", str(world.out)).returncode == 1
    assert list(world.tmp.iterdir()) == []


@pytest.mark.parametrize(
    ("lock", "message"),
    [
        ("evil==1.0\n", "without a pinned version and hash"),
        (
            f"evil>=1.0 \\\n    --hash=sha256:{HEX64}\n",
            "without a pinned version and hash",
        ),
        ("evil==1.0 \\\n    --hash=sha256:abc\n", "without a pinned version and hash"),
        (
            f"--index-url https://example.invalid/simple\nevil==1.0 \\\n"
            f"    --hash=sha256:{HEX64}\n",
            "without a pinned version and hash",
        ),
        ("evil @ https://example.invalid/evil.whl\n", "only git+URL"),
        (f"evil @ git+https://u:t@example.invalid/evil@{'d' * 40}\n", "credentials"),
        (
            f"evil @ git+https://example.invalid/evil@{'d' * 40} ; os_name == 'nt'\n",
            "only git+URL",
        ),
        ("evil @ git+https://example.invalid/evil@main\n", "only git+URL"),
    ],
)
def test_unsafe_locks_are_refused_and_nothing_is_written(world, lock, message):
    world.lock.write_text(lock)
    result = world.run("--out-dir", str(world.out))
    assert result.returncode == 1
    assert message in result.stderr
    assert not world.out.exists()


def test_a_commit_the_remote_lacks_is_refused(world):
    world.lock.write_text(f"asusrouter @ git+{world.dep.as_uri()}@{'e' * 40}\n")
    result = world.run("--out-dir", str(world.out))
    assert result.returncode == 1
    assert "cannot fetch asusrouter" in result.stderr
    assert not world.out.exists()


def test_missing_uv_is_reported(world):
    keep = [
        p for p in os.environ["PATH"].split(os.pathsep) if not (Path(p) / "uv").exists()
    ]
    result = world.run("--out-dir", str(world.out), path=os.pathsep.join(keep))
    assert result.returncode == 1
    assert "uv is required" in result.stderr


def test_usage(world):
    assert world.run("--help").returncode == 0
    bad = world.run("--nope")
    assert bad.returncode == 1
    assert "unknown option" in bad.stderr


@pytest.mark.skipif(
    os.environ.get("AIMESH_DEPLOY_E2E") != "1",
    reason="set AIMESH_DEPLOY_E2E=1: needs uv, git, PyPI and GitHub",
)
def test_real_bundle_builds_and_installs_from_pypi(host, repo, tmp_path):
    out = tmp_path / "dist"
    env = {k: v for k, v in os.environ.items() if k not in ("UV_INDEX_URL",)}
    build = subprocess.run(
        [BASH, str(repo / "deploy" / "build-bundle.sh"), "--out-dir", str(out)],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert build.returncode == 0, build.stderr
    (archive,) = out.glob("*.tar.gz")
    host.bundle_dir = unpack(archive, tmp_path / "unpacked")
    result = host.run(python=sys.executable, PIP_NO_INDEX="0", PIP_FIND_LINKS="")
    assert result.returncode == 0, result.stdout + result.stderr
    python = host.opt / "venv" / "bin" / "python"
    version = subprocess.run(
        [str(python), "-I", "-m", "aimesh_snmp_proxy", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert version.returncode == 0, version.stderr
    assert version.stdout.startswith("aimesh-snmp-proxy ")
