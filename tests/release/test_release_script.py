"""Tests for scripts/release.sh, run against throwaway repos with a stub gh."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest
from packaging.version import Version

pytestmark = pytest.mark.skipif(
    shutil.which("jq") is None, reason="the gh stub needs jq"
)

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "release.sh"
GIT = shutil.which("git") or "git"
BASH = shutil.which("bash") or "bash"
EMAIL = "jerry@chenyang.us"
SLUG = "github.com/islanderman/aimesh-snmp-proxy"
ORIGIN_URL = "git@github.com:islanderman/aimesh-snmp-proxy.git"

PYPROJECT = """\
[project]
name = "aimesh-snmp-proxy"
version = "0.2.4"
description = "demo"

[tool.example]
version = "9.9.9"
"""

LOCK = """\
version = 1
revision = 3
requires-python = ">=3.11"

[[package]]
name = "aiohttp"
version = "3.14.5"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "aimesh-snmp-proxy"
version = "0.2.4"
source = { editable = "." }
dependencies = [
    { name = "aiohttp" },
]

[package.metadata]
requires-dist = [{ name = "aiohttp", specifier = "==3.14.5" }]

[[package]]
name = "zeroconf"
version = "0.2.4"
source = { registry = "https://pypi.org/simple" }
"""

CHANGELOG = """\
# Changelog

All notable changes to this project are listed here.

## [Unreleased]

### Added

- First public release.
- A second entry
  that wraps onto a second line.

## [0.2.4] - 2026-11-01

### Fixed

- An old fix.

[Unreleased]: https://github.com/islanderman/aimesh-snmp-proxy/compare/v0.2.4...HEAD
[0.2.4]: https://github.com/islanderman/aimesh-snmp-proxy/releases/tag/v0.2.4
"""

# The gh stub logs each call, saves the PR body, and answers `gh api` from STUB_CHECKS:
# it reads checks-<state>.json, and a state with no file makes the call fail.
GH_STUB = """\
#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$STUB_DIR/gh-calls.txt"
case $1 in
  pr)
    while [ $# -gt 0 ]; do
      [ "$1" = --body-file ] && cp "$2" "$STUB_DIR/gh-body.md"
      shift
    done
    echo "https://github.com/islanderman/aimesh-snmp-proxy/pull/7"
    ;;
  api)
    filter=
    while [ $# -gt 0 ]; do
      [ "$1" = --jq ] && filter=$2
      shift
    done
    json=$STUB_DIR/checks-${STUB_CHECKS:-green}.json
    [ -f "$json" ] || exit 1
    jq -r "$filter" "$json"
    ;;
esac
"""

CHECK_RUNS = {
    "green": [{"conclusion": "success"}, {"conclusion": "skipped"}],
    "red": [{"conclusion": "success"}, {"conclusion": "failure"}],
    "pending": [{"conclusion": "success"}, {"conclusion": None}],
    "none": [],
}


@dataclass
class Sandbox:
    work: Path
    origin: Path
    stub_dir: Path
    env: dict[str, str]

    def git(self, *args: str, cwd: Path | None = None) -> str:
        done = subprocess.run(
            [GIT, *args],
            cwd=cwd or self.work,
            env=self.env,
            capture_output=True,
            text=True,
            check=True,
        )
        return done.stdout.strip()

    def release(
        self, *args: str, cwd: Path | None = None, **env: str
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [BASH, str(SCRIPT), *args],
            cwd=cwd or self.work,
            env={**self.env, **env},
            capture_output=True,
            text=True,
            check=False,
        )

    def gh_calls(self) -> list[str]:
        log = self.stub_dir / "gh-calls.txt"
        return log.read_text().splitlines() if log.exists() else []

    def write(self, name: str, text: str) -> None:
        (self.work / name).write_text(text)

    def commit_all(self, message: str) -> None:
        self.git("add", "-A")
        self.git("commit", "--no-gpg-sign", "-q", "-m", message)

    def merge_release(self, version: str) -> str:
        """Fast-forward origin/main to the release branch, as a rebase merge would."""
        self.git("push", "-q", "origin", f"release/v{version}:main")
        self.git("fetch", "-q", "origin")
        return self.git("rev-parse", "origin/main")


@pytest.fixture
def sandbox(tmp_path: Path) -> Sandbox:
    home = tmp_path / "home"
    stub_dir = tmp_path / "stub"
    work = tmp_path / "work"
    origin = tmp_path / "origin.git"
    for path in (home, stub_dir, work):
        path.mkdir()
    gh = stub_dir / "gh"
    gh.write_text(GH_STUB)
    gh.chmod(0o755)
    for state_name, runs in CHECK_RUNS.items():
        body = {"total_count": len(runs), "check_runs": runs}
        (stub_dir / f"checks-{state_name}.json").write_text(json.dumps(body))
    env = {
        "PATH": f"{stub_dir}{os.pathsep}{os.environ['PATH']}",
        "HOME": str(home),
        "STUB_DIR": str(stub_dir),
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GH_REPO": SLUG,
        "RELEASE_DATE": "2026-11-20",
        "LC_ALL": "C",
    }
    box = Sandbox(work, origin, stub_dir, env)
    subprocess.run(
        [GIT, "init", "-q", "--bare", "-b", "main", str(origin)], check=True, env=env
    )
    box.git("init", "-q", "-b", "main")
    box.git("config", "user.name", "Jerry Yang")
    box.git("config", "user.email", EMAIL)
    box.git("remote", "add", "origin", ORIGIN_URL)
    box.git("config", f"url.{origin}.insteadOf", ORIGIN_URL)
    (work / "scripts").mkdir()
    shutil.copy2(SCRIPT, work / "scripts" / "release.sh")
    box.write("pyproject.toml", PYPROJECT)
    box.write("uv.lock", LOCK)
    box.write("CHANGELOG.md", CHANGELOG)
    box.commit_all("chore: seed")
    box.git("push", "-q", "-u", "origin", "main")
    return box


def prepare(box: Sandbox, version: str = "0.3.0") -> None:
    done = box.release(version)
    assert done.returncode == 0, done.stderr


def state(box: Sandbox) -> tuple[str, ...]:
    """Everything a dry run must leave alone: local refs, the tree, the remote refs."""
    return (
        box.git("for-each-ref"),
        box.git("status", "--porcelain"),
        box.git("rev-parse", "HEAD"),
        box.git("for-each-ref", cwd=box.origin),
    )


def set_version(box: Sandbox, version: str) -> None:
    """Commit this current version to pyproject.toml and uv.lock on main."""
    box.write("pyproject.toml", PYPROJECT.replace("0.2.4", version))
    box.write(
        "uv.lock",
        LOCK.replace(
            'name = "aimesh-snmp-proxy"\nversion = "0.2.4"',
            f'name = "aimesh-snmp-proxy"\nversion = "{version}"',
        ),
    )
    box.commit_all(f"chore: set version {version}")
    box.git("push", "-q", "origin", "main")


# --- opening the release PR ---------------------------------------------------


def test_prepare_bumps_the_version_in_pyproject_and_lock(sandbox: Sandbox) -> None:
    prepare(sandbox)
    pyproject = (sandbox.work / "pyproject.toml").read_text()
    assert pyproject == PYPROJECT.replace('version = "0.2.4"', 'version = "0.3.0"')
    lock = (sandbox.work / "uv.lock").read_text()
    assert lock == LOCK.replace(
        'name = "aimesh-snmp-proxy"\nversion = "0.2.4"',
        'name = "aimesh-snmp-proxy"\nversion = "0.3.0"',
    )


def test_prepare_dates_the_changelog_and_opens_a_fresh_unreleased(
    sandbox: Sandbox,
) -> None:
    prepare(sandbox)
    text = (sandbox.work / "CHANGELOG.md").read_text()
    assert "## [Unreleased]\n\n## [0.3.0] - 2026-11-20\n\n### Added\n" in text
    assert "- A second entry\n  that wraps onto a second line.\n" in text
    assert "## [0.2.4] - 2026-11-01" in text


def test_prepare_moves_the_compare_links(sandbox: Sandbox) -> None:
    prepare(sandbox)
    text = (sandbox.work / "CHANGELOG.md").read_text()
    base = "https://github.com/islanderman/aimesh-snmp-proxy"
    assert f"[Unreleased]: {base}/compare/v0.3.0...HEAD\n" in text
    assert f"[0.3.0]: {base}/compare/v0.2.4...v0.3.0\n" in text
    assert f"[0.2.4]: {base}/releases/tag/v0.2.4\n" in text


def test_prepare_leaves_a_changelog_without_compare_links_alone(
    sandbox: Sandbox,
) -> None:
    head, _, _ = CHANGELOG.partition("[Unreleased]: ")
    sandbox.write("CHANGELOG.md", head)
    sandbox.commit_all("docs: drop links")
    sandbox.git("push", "-q", "origin", "main")
    prepare(sandbox)
    text = (sandbox.work / "CHANGELOG.md").read_text()
    assert "## [0.3.0] - 2026-11-20" in text
    assert "compare/" not in text


def test_prepare_commits_one_commit_as_the_maintainer_on_a_release_branch(
    sandbox: Sandbox,
) -> None:
    prepare(sandbox)
    assert sandbox.git("branch", "--show-current") == "release/v0.3.0"
    assert sandbox.git("rev-list", "--count", "origin/main..HEAD") == "1"
    fields = sandbox.git("log", "-1", "--format=%an|%ae|%cn|%ce|%s")
    assert fields == f"Jerry Yang|{EMAIL}|Jerry Yang|{EMAIL}|chore(release): v0.3.0"
    changed = sandbox.git("show", "--name-only", "--format=", "HEAD").split()
    assert sorted(changed) == ["CHANGELOG.md", "pyproject.toml", "uv.lock"]


def test_prepare_pushes_the_branch_and_opens_the_pr(sandbox: Sandbox) -> None:
    done = sandbox.release("0.3.0")
    assert done.returncode == 0, done.stderr
    assert "https://github.com/islanderman/aimesh-snmp-proxy/pull/7" in done.stdout
    pushed = sandbox.git("rev-parse", "release/v0.3.0", cwd=sandbox.origin)
    assert pushed == sandbox.git("rev-parse", "HEAD")
    (call,) = sandbox.gh_calls()
    assert call.startswith(f"pr create --repo {SLUG} --base main --head release/v0.3.0")
    assert "--title chore(release): v0.3.0" in call


def test_prepare_puts_the_release_notes_in_the_pr_body(sandbox: Sandbox) -> None:
    prepare(sandbox)
    body = (sandbox.stub_dir / "gh-body.md").read_text()
    assert "- First public release." in body
    assert "scripts/release.sh --tag 0.3.0" in body
    assert "0.2.4" not in body


@pytest.mark.parametrize("bad", ["1.2", "v1.2.3", "1.2.3-rc1", "01.2.3", "a.b.c"])
def test_prepare_rejects_a_malformed_version(sandbox: Sandbox, bad: str) -> None:
    done = sandbox.release(bad)
    assert done.returncode != 0
    assert f"'{bad}' is not a version like 1.2.3" in done.stderr
    assert sandbox.git("branch", "--list", "release/*") == ""


@pytest.mark.parametrize("old", ["0.2.4", "0.2.3", "0.1.9"])
def test_prepare_rejects_a_version_that_is_not_newer(
    sandbox: Sandbox, old: str
) -> None:
    done = sandbox.release(old)
    assert done.returncode != 0
    assert f"{old} is not newer than the current version 0.2.4" in done.stderr


@pytest.mark.parametrize("new", ["0.3.0", "0.3.1", "0.4.0", "1.0.0"])
def test_prepare_releases_over_a_dev_version(sandbox: Sandbox, new: str) -> None:
    set_version(sandbox, "0.3.0.dev0")
    prepare(sandbox, new)
    pyproject = (sandbox.work / "pyproject.toml").read_text()
    assert pyproject == PYPROJECT.replace('version = "0.2.4"', f'version = "{new}"')
    lock = (sandbox.work / "uv.lock").read_text()
    assert f'name = "aimesh-snmp-proxy"\nversion = "{new}"\n' in lock
    assert "dev" not in lock


@pytest.mark.parametrize("old", ["0.2.9", "0.2.4", "0.1.0"])
def test_prepare_rejects_a_release_older_than_a_dev_version(
    sandbox: Sandbox, old: str
) -> None:
    set_version(sandbox, "0.3.0.dev0")
    done = sandbox.release(old)
    assert done.returncode != 0
    assert f"{old} is not newer than the current version 0.3.0.dev0" in done.stderr
    assert sandbox.git("branch", "--list", "release/*") == ""


def test_prepare_rejects_the_release_that_a_later_dev_version_precedes(
    sandbox: Sandbox,
) -> None:
    set_version(sandbox, "0.3.1.dev2")
    done = sandbox.release("0.3.0")
    assert done.returncode != 0
    assert "0.3.0 is not newer than the current version 0.3.1.dev2" in done.stderr


@pytest.mark.parametrize("current", ["0.3.0rc1", "0.3.0.post1", "0.3.0.dev", "0.3"])
def test_prepare_rejects_a_current_version_it_cannot_compare(
    sandbox: Sandbox, current: str
) -> None:
    set_version(sandbox, current)
    done = sandbox.release("0.4.0")
    assert done.returncode != 0
    assert (
        f"the version '{current}' in pyproject.toml is not like 1.2.3 or 1.2.3.dev0"
        in done.stderr
    )


def newer_verdicts(pairs: list[tuple[str, str]]) -> list[bool]:
    """What release.sh's version_newer says for each (new, current) pair."""
    calls = "\n".join(
        f"version_newer {new} {current} && echo yes || echo no"
        for new, current in pairs
    )
    done = subprocess.run(
        [BASH, "-c", f"source {shlex.quote(str(SCRIPT))}\n{calls}"],
        capture_output=True,
        text=True,
        check=True,
    )
    return [line == "yes" for line in done.stdout.split()]


def test_the_version_order_matches_pep_440() -> None:
    currents = ["0.2.4", "0.3.0.dev0", "0.3.0.dev5", "0.3.1.dev2", "0.3.0", "0.10.0"]
    news = ["0.2.9", "0.3.0", "0.3.1", "0.4.0", "0.9.9", "0.10.0", "1.0.0"]
    pairs = [(new, current) for current in currents for new in news]
    verdicts = newer_verdicts(pairs)
    assert len(verdicts) == len(pairs)
    for (new, current), newer in zip(pairs, verdicts, strict=True):
        assert newer == (Version(new) > Version(current)), (new, current)


def test_a_dev_version_goes_through_the_whole_release(sandbox: Sandbox) -> None:
    set_version(sandbox, "0.3.0.dev0")
    plan = sandbox.release("0.3.0", "--dry-run")
    assert plan.returncode == 0, plan.stderr
    assert "0.3.0.dev0 -> 0.3.0" in plan.stdout
    prepare(sandbox)
    merged = sandbox.merge_release("0.3.0")
    done = sandbox.release("--tag", "0.3.0")
    assert done.returncode == 0, done.stderr
    assert sandbox.git("rev-parse", "v0.3.0^{commit}", cwd=sandbox.origin) == merged


def test_prepare_refuses_a_dirty_tree(sandbox: Sandbox) -> None:
    sandbox.write("notes.txt", "scratch")
    sandbox.git("add", "notes.txt")
    done = sandbox.release("0.3.0")
    assert done.returncode != 0
    assert "the working tree is not clean" in done.stderr
    assert sandbox.gh_calls() == []


def test_prepare_refuses_an_untracked_file(sandbox: Sandbox) -> None:
    sandbox.write("notes.txt", "scratch")
    done = sandbox.release("0.3.0")
    assert done.returncode != 0
    assert "the working tree is not clean" in done.stderr
    assert sandbox.git("branch", "--list", "release/*") == ""


def test_prepare_ignores_a_file_that_git_ignores(sandbox: Sandbox) -> None:
    (sandbox.work / ".git" / "info" / "exclude").write_text("scratch.txt\n")
    sandbox.write("scratch.txt", "x")
    prepare(sandbox)


def test_prepare_refuses_a_repository_without_an_identity_of_its_own(
    sandbox: Sandbox, tmp_path: Path
) -> None:
    other = tmp_path / "other.gitconfig"
    other.write_text("[user]\n\tname = Someone\n\temail = someone@example.com\n")
    sandbox.git("config", "--unset", "user.email")
    done = sandbox.release("0.3.0", GIT_CONFIG_GLOBAL=str(other))
    assert done.returncode != 0
    assert "this repository has no user.email of its own" in done.stderr
    assert sandbox.git("branch", "--list", "release/*") == ""


@pytest.mark.parametrize("role", ["AUTHOR", "COMMITTER"])
def test_prepare_refuses_an_identity_set_by_the_environment(
    sandbox: Sandbox, role: str
) -> None:
    done = sandbox.release("0.3.0", **{f"GIT_{role}_EMAIL": "someone@example.com"})
    assert done.returncode != 0
    assert f"git {role.lower()} email is 'someone@example.com'" in done.stderr
    assert f"but this repository's user.email is {EMAIL}" in done.stderr
    assert sandbox.git("branch", "--list", "release/*") == ""


def test_prepare_lets_another_maintainer_release_with_their_own_identity(
    sandbox: Sandbox,
) -> None:
    sandbox.git("config", "user.name", "Someone")
    sandbox.git("config", "user.email", "someone@example.com")
    prepare(sandbox)
    fields = sandbox.git("log", "-1", "--format=%an|%ae|%cn|%ce")
    assert fields == "Someone|someone@example.com|Someone|someone@example.com"


def test_prepare_rejects_a_malformed_release_date(sandbox: Sandbox) -> None:
    done = sandbox.release("0.3.0", RELEASE_DATE="tomorrow")
    assert done.returncode != 0
    assert "'tomorrow' is not a date like 2026-11-20" in done.stderr
    assert sandbox.git("branch", "--list", "release/*") == ""


def test_prepare_stops_before_any_change_when_the_lock_lacks_the_package(
    sandbox: Sandbox,
) -> None:
    sandbox.write(
        "uv.lock", LOCK.replace('name = "aimesh-snmp-proxy"', 'name = "other"')
    )
    sandbox.commit_all("chore: odd lock")
    sandbox.git("push", "-q", "origin", "main")
    before = state(sandbox)
    done = sandbox.release("0.3.0")
    assert done.returncode != 0
    assert "cannot update uv.lock" in done.stderr
    assert state(sandbox) == before
    assert sandbox.gh_calls() == []


def test_prepare_refuses_when_the_tag_exists_locally(sandbox: Sandbox) -> None:
    sandbox.git("tag", "-a", "v0.3.0", "-m", "x")
    done = sandbox.release("0.3.0")
    assert done.returncode != 0
    assert "tag v0.3.0 already exists" in done.stderr


def test_prepare_refuses_when_the_tag_exists_on_origin(sandbox: Sandbox) -> None:
    sandbox.git("tag", "-a", "v0.3.0", "-m", "x")
    sandbox.git("push", "-q", "origin", "v0.3.0")
    sandbox.git("tag", "-d", "v0.3.0")
    done = sandbox.release("0.3.0")
    assert done.returncode != 0
    assert "tag v0.3.0 already exists" in done.stderr


def test_prepare_refuses_when_the_release_branch_exists(sandbox: Sandbox) -> None:
    sandbox.git("branch", "release/v0.3.0")
    done = sandbox.release("0.3.0")
    assert done.returncode != 0
    assert "branch release/v0.3.0 already exists" in done.stderr


def test_prepare_refuses_an_empty_unreleased_section(sandbox: Sandbox) -> None:
    text = CHANGELOG.replace("### Added\n\n- First public release.\n", "")
    text = text.replace("- A second entry\n  that wraps onto a second line.\n", "")
    sandbox.write("CHANGELOG.md", text)
    sandbox.commit_all("docs: empty unreleased")
    sandbox.git("push", "-q", "origin", "main")
    done = sandbox.release("0.3.0")
    assert done.returncode != 0
    assert "the Unreleased section of CHANGELOG.md is empty" in done.stderr


def test_prepare_refuses_a_changelog_without_unreleased(sandbox: Sandbox) -> None:
    sandbox.write("CHANGELOG.md", CHANGELOG.replace("## [Unreleased]", "## [Next]"))
    sandbox.commit_all("docs: rename")
    sandbox.git("push", "-q", "origin", "main")
    done = sandbox.release("0.3.0")
    assert done.returncode != 0
    assert "CHANGELOG.md has no Unreleased section" in done.stderr


def test_prepare_branches_off_origin_main_not_the_local_branch(
    sandbox: Sandbox,
) -> None:
    sandbox.write("local-only.txt", "x")
    sandbox.commit_all("chore: local only")
    prepare(sandbox)
    assert sandbox.git("rev-list", "--count", "origin/main..HEAD") == "1"
    assert not (sandbox.work / "local-only.txt").exists()


def test_prepare_reads_only_the_project_table_version(sandbox: Sandbox) -> None:
    pyproject = PYPROJECT.replace(
        "[project]", '[build]\nversion = "7.7.7"\n\n[project]'
    )
    sandbox.write("pyproject.toml", pyproject)
    sandbox.commit_all("chore: build table first")
    sandbox.git("push", "-q", "origin", "main")
    prepare(sandbox)
    assert 'version = "7.7.7"' in (sandbox.work / "pyproject.toml").read_text()


# --- tagging the merged release ------------------------------------------------


def test_tag_creates_and_pushes_an_annotated_tag_on_the_release_commit(
    sandbox: Sandbox,
) -> None:
    prepare(sandbox)
    merged = sandbox.merge_release("0.3.0")
    done = sandbox.release("--tag", "0.3.0")
    assert done.returncode == 0, done.stderr
    assert (
        sandbox.git("cat-file", "-t", "refs/tags/v0.3.0", cwd=sandbox.origin) == "tag"
    )
    assert sandbox.git("rev-parse", "v0.3.0^{commit}", cwd=sandbox.origin) == merged
    fields = sandbox.git(
        "for-each-ref",
        "refs/tags/v0.3.0",
        "--format=%(taggeremail)|%(contents:subject)",
    )
    assert fields == f"<{EMAIL}>|Release v0.3.0"


def test_tag_checks_ci_on_the_release_commit(sandbox: Sandbox) -> None:
    prepare(sandbox)
    merged = sandbox.merge_release("0.3.0")
    sandbox.release("--tag", "0.3.0")
    call = sandbox.gh_calls()[-1]
    repo = "repos/islanderman/aimesh-snmp-proxy"
    assert call.startswith(
        f"api --hostname github.com {repo}/commits/{merged}/check-runs"
    )


@pytest.mark.parametrize("state", ["red", "pending", "none", "broken"])
def test_tag_refuses_when_ci_is_not_green(sandbox: Sandbox, state: str) -> None:
    prepare(sandbox)
    sandbox.merge_release("0.3.0")
    done = sandbox.release("--tag", "0.3.0", STUB_CHECKS=state)
    assert done.returncode != 0
    assert "CI is not green on" in done.stderr
    assert sandbox.git("tag", "--list", "v0.3.0", cwd=sandbox.origin) == ""


def test_tag_refuses_when_the_release_is_not_merged(sandbox: Sandbox) -> None:
    prepare(sandbox)
    done = sandbox.release("--tag", "0.3.0")
    assert done.returncode != 0
    assert "origin/main has no commit 'chore(release): v0.3.0'" in done.stderr
    assert sandbox.git("tag", "--list", "v0.3.0", cwd=sandbox.origin) == ""


def test_tag_refuses_when_the_tag_exists(sandbox: Sandbox) -> None:
    prepare(sandbox)
    sandbox.merge_release("0.3.0")
    assert sandbox.release("--tag", "0.3.0").returncode == 0
    done = sandbox.release("--tag", "0.3.0")
    assert done.returncode != 0
    assert "tag v0.3.0 already exists" in done.stderr


def test_tag_refuses_another_git_identity(sandbox: Sandbox) -> None:
    prepare(sandbox)
    sandbox.merge_release("0.3.0")
    done = sandbox.release("--tag", "0.3.0", GIT_COMMITTER_EMAIL="someone@example.com")
    assert done.returncode != 0
    assert "git committer email is 'someone@example.com'" in done.stderr
    assert sandbox.git("tag", "--list", "v0.3.0", cwd=sandbox.origin) == ""


def test_tag_accepts_a_squash_merge_subject(sandbox: Sandbox) -> None:
    prepare(sandbox)
    sandbox.git(
        "commit", "--no-gpg-sign", "-q", "--amend", "-m", "chore(release): v0.3.0 (#7)"
    )
    merged = sandbox.merge_release("0.3.0")
    done = sandbox.release("--tag", "0.3.0")
    assert done.returncode == 0, done.stderr
    assert sandbox.git("rev-parse", "v0.3.0^{commit}", cwd=sandbox.origin) == merged


def test_tag_still_picks_the_release_commit_after_main_moved_on(
    sandbox: Sandbox,
) -> None:
    prepare(sandbox)
    merged = sandbox.merge_release("0.3.0")
    sandbox.write("later.txt", "x")
    sandbox.commit_all("feat: a later change")
    sandbox.git("push", "-q", "origin", "HEAD:main")
    done = sandbox.release("--tag", "0.3.0")
    assert done.returncode == 0, done.stderr
    assert sandbox.git("rev-parse", "v0.3.0^{commit}", cwd=sandbox.origin) == merged


def test_tag_refuses_when_the_commit_carries_another_version(
    sandbox: Sandbox,
) -> None:
    prepare(sandbox)
    sandbox.merge_release("0.3.0")
    sandbox.git("checkout", "-q", "-b", "odd", "origin/main")
    sandbox.write("pyproject.toml", PYPROJECT.replace("0.2.4", "0.2.9"))
    sandbox.git("add", "-A")
    sandbox.git(
        "commit", "--no-gpg-sign", "-q", "--amend", "-m", "chore(release): v0.9.0"
    )
    sandbox.git("push", "-q", "-f", "origin", "odd:main")
    done = sandbox.release("--tag", "0.9.0")
    assert done.returncode != 0
    assert "says version 0.2.9, not 0.9.0" in done.stderr


# --- the checks the release workflow runs ------------------------------------


@pytest.fixture
def tagged(sandbox: Sandbox, tmp_path: Path) -> Path:
    """A fresh clone checked out at the pushed v0.3.0 tag, like the workflow sees it."""
    prepare(sandbox)
    sandbox.merge_release("0.3.0")
    assert sandbox.release("--tag", "0.3.0").returncode == 0
    clone = tmp_path / "ci"
    sandbox.git("clone", "-q", str(sandbox.origin), str(clone), cwd=tmp_path)
    sandbox.git("checkout", "-q", "v0.3.0", cwd=clone)
    return clone


def test_verify_passes_for_a_good_tag(sandbox: Sandbox, tagged: Path) -> None:
    done = sandbox.release("--verify", "v0.3.0", cwd=tagged)
    assert done.returncode == 0, done.stderr


def test_verify_rejects_a_tag_that_disagrees_with_pyproject(
    sandbox: Sandbox, tagged: Path
) -> None:
    sandbox.git("tag", "-a", "v0.4.0", "-m", "x", cwd=tagged)
    done = sandbox.release("--verify", "v0.4.0", cwd=tagged)
    assert done.returncode != 0
    assert "pyproject.toml says version 0.3.0, not 0.4.0" in done.stderr


def test_verify_rejects_a_lightweight_tag(sandbox: Sandbox, tagged: Path) -> None:
    sandbox.git("tag", "-d", "v0.3.0", cwd=tagged)
    sandbox.git("tag", "v0.3.0", cwd=tagged)
    done = sandbox.release("--verify", "v0.3.0", cwd=tagged)
    assert done.returncode != 0
    assert "v0.3.0 is not an annotated tag" in done.stderr


def test_verify_rejects_a_commit_that_is_not_on_main(
    sandbox: Sandbox, tagged: Path
) -> None:
    sandbox.git("checkout", "-q", "-b", "side", cwd=tagged)
    sandbox.git("config", "user.email", EMAIL, cwd=tagged)
    sandbox.git("config", "user.name", "Jerry Yang", cwd=tagged)
    (tagged / "side.txt").write_text("x")
    sandbox.git("add", "-A", cwd=tagged)
    sandbox.git("commit", "--no-gpg-sign", "-q", "-m", "chore: side", cwd=tagged)
    sandbox.git("tag", "-d", "v0.3.0", cwd=tagged)
    sandbox.git("tag", "-a", "v0.3.0", "-m", "x", cwd=tagged)
    done = sandbox.release("--verify", "v0.3.0", cwd=tagged)
    assert done.returncode != 0
    assert "is not on origin/main" in done.stderr


def test_verify_rejects_a_missing_changelog_section(
    sandbox: Sandbox, tagged: Path
) -> None:
    sandbox.git("config", "user.email", EMAIL, cwd=tagged)
    sandbox.git("config", "user.name", "Jerry Yang", cwd=tagged)
    text = (tagged / "CHANGELOG.md").read_text().replace("[0.3.0] - ", "[0.3.1] - ")
    (tagged / "CHANGELOG.md").write_text(text)
    sandbox.git("add", "-A", cwd=tagged)
    sandbox.git("commit", "--no-gpg-sign", "-q", "-m", "docs: rename", cwd=tagged)
    sandbox.git("push", "-q", "origin", "HEAD:main", cwd=tagged)
    sandbox.git("tag", "-d", "v0.3.0", cwd=tagged)
    sandbox.git("tag", "-a", "v0.3.0", "-m", "x", cwd=tagged)
    done = sandbox.release("--verify", "v0.3.0", cwd=tagged)
    assert done.returncode != 0
    assert "CHANGELOG.md has no notes for 0.3.0" in done.stderr


def test_verify_rejects_a_malformed_tag(sandbox: Sandbox, tagged: Path) -> None:
    done = sandbox.release("--verify", "0.3.0", cwd=tagged)
    assert done.returncode != 0
    assert "'0.3.0' is not a tag like v1.2.3" in done.stderr


# --- extracting the release notes ------------------------------------------------


def test_notes_prints_one_section_without_link_references(sandbox: Sandbox) -> None:
    done = sandbox.release("--notes", "0.2.4")
    assert done.returncode == 0, done.stderr
    assert done.stdout == "### Fixed\n\n- An old fix.\n"


def test_notes_keeps_wrapped_bullets(sandbox: Sandbox) -> None:
    prepare(sandbox)
    done = sandbox.release("--notes", "0.3.0")
    assert done.stdout == (
        "### Added\n\n- First public release.\n"
        "- A second entry\n  that wraps onto a second line.\n"
    )


@pytest.mark.parametrize(
    "heading", ["## 0.2.4 - 2026-11-01", "## [0.2.4]", "## v0.2.4", "## [v0.2.4] - x"]
)
def test_notes_accepts_common_heading_styles(sandbox: Sandbox, heading: str) -> None:
    text = CHANGELOG.replace("## [0.2.4] - 2026-11-01", heading)
    sandbox.write("CHANGELOG.md", text)
    done = sandbox.release("--notes", "0.2.4")
    assert done.returncode == 0, done.stderr
    assert done.stdout == "### Fixed\n\n- An old fix.\n"


def test_notes_does_not_match_a_longer_version(sandbox: Sandbox) -> None:
    sandbox.write("CHANGELOG.md", CHANGELOG.replace("[0.2.4] - ", "[0.2.41] - "))
    done = sandbox.release("--notes", "0.2.4")
    assert done.returncode != 0
    assert "CHANGELOG.md has no notes for 0.2.4" in done.stderr


def test_notes_fails_on_an_empty_section(sandbox: Sandbox) -> None:
    text = CHANGELOG.replace("### Fixed\n\n- An old fix.\n", "")
    sandbox.write("CHANGELOG.md", text)
    done = sandbox.release("--notes", "0.2.4")
    assert done.returncode != 0
    assert "CHANGELOG.md has no notes for 0.2.4" in done.stderr


# --- --dry-run ---------------------------------------------------------------------


@pytest.mark.parametrize("order", [("--dry-run", "0.3.0"), ("0.3.0", "--dry-run")])
def test_dry_run_prepare_changes_nothing_and_shows_the_plan(
    sandbox: Sandbox, order: tuple[str, ...]
) -> None:
    before = state(sandbox)
    done = sandbox.release(*order)
    assert done.returncode == 0, done.stderr
    assert state(sandbox) == before
    assert sandbox.gh_calls() == []
    assert "release/v0.3.0 from origin/main" in done.stdout
    assert "0.2.4 -> 0.3.0" in done.stdout
    assert "## [0.3.0] - 2026-11-20" in done.stdout
    assert f"as Jerry Yang <{EMAIL}>" in done.stdout
    assert "- First public release." in done.stdout


def test_dry_run_prepare_still_runs_every_check(sandbox: Sandbox) -> None:
    done = sandbox.release("0.3.0", "--dry-run", GIT_AUTHOR_EMAIL="someone@example.com")
    assert done.returncode != 0
    assert "git author email is 'someone@example.com'" in done.stderr


def test_dry_run_prepare_stops_on_a_file_it_cannot_update(sandbox: Sandbox) -> None:
    sandbox.write(
        "uv.lock", LOCK.replace('name = "aimesh-snmp-proxy"', 'name = "other"')
    )
    sandbox.commit_all("chore: odd lock")
    sandbox.git("push", "-q", "origin", "main")
    done = sandbox.release("0.3.0", "--dry-run")
    assert done.returncode != 0
    assert "cannot update uv.lock" in done.stderr


def test_dry_run_tag_changes_nothing_and_shows_the_plan(sandbox: Sandbox) -> None:
    prepare(sandbox)
    merged = sandbox.merge_release("0.3.0")
    before = state(sandbox)
    done = sandbox.release("--tag", "0.3.0", "--dry-run")
    assert done.returncode == 0, done.stderr
    assert state(sandbox) == before
    assert f"tag v0.3.0 (annotated, 'Release v0.3.0') at {merged[:12]}" in done.stdout
    assert sandbox.git("tag", "--list", "v0.3.0", cwd=sandbox.origin) == ""
    assert sandbox.gh_calls()[-1].startswith("api --hostname github.com")


def test_dry_run_tag_refuses_when_ci_is_not_green(sandbox: Sandbox) -> None:
    prepare(sandbox)
    sandbox.merge_release("0.3.0")
    done = sandbox.release("--tag", "0.3.0", "--dry-run", STUB_CHECKS="red")
    assert done.returncode != 0
    assert "CI is not green on" in done.stderr


@pytest.mark.parametrize("args", [["--verify", "v0.3.0"], ["--notes", "0.2.4"]])
def test_dry_run_does_not_apply_to_the_read_only_commands(
    sandbox: Sandbox, args: list[str]
) -> None:
    done = sandbox.release(*args, "--dry-run")
    assert done.returncode == 2
    assert "usage:" in done.stderr


# --- usage -------------------------------------------------------------------------


@pytest.mark.parametrize("args", [[], ["--tag"], ["--nope"], ["0.3.0", "0.4.0"]])
def test_usage_errors_exit_2(sandbox: Sandbox, args: list[str]) -> None:
    done = sandbox.release(*args)
    assert done.returncode == 2
    assert "usage:" in done.stderr


def test_help_exits_0(sandbox: Sandbox) -> None:
    done = sandbox.release("--help")
    assert done.returncode == 0
    assert "usage:" in done.stdout
