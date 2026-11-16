# Contributing

Thank you for helping. This guide shows how to set up, test, and submit a change. By taking part,
you agree to follow the
[Code of Conduct](https://github.com/islanderman/aimesh-snmp-proxy/blob/main/CODE_OF_CONDUCT.md).

## Ways to help

- **Report a bug or a device quirk.** Open an
  [issue](https://github.com/islanderman/aimesh-snmp-proxy/issues). Give the output of
  `aimesh-snmp-proxy --version`, the router model, and the firmware version. Add log lines with the
  addresses you want to keep private removed.
- **Improve the docs.** Every page in `docs/` has an edit link.
- **Send code.** Open an issue first for a large change, so we can agree on the approach.

Never post a password, a community, a token, a private key, or a certificate that you did not export
on purpose. Report a security problem as the
[security policy](https://github.com/islanderman/aimesh-snmp-proxy/security/policy) describes.

## Set up

You need `git`, [uv](https://docs.astral.sh/uv/), and [pre-commit](https://pre-commit.com/). uv
installs Python for you. The project supports Python 3.11, 3.12, 3.13, and 3.14. For the Markdown
checks, install `prettier` and `markdownlint-cli`.

```sh
git clone https://github.com/islanderman/aimesh-snmp-proxy.git
cd aimesh-snmp-proxy
make init
```

`make init` runs `uv sync --locked`, which builds `.venv` from `uv.lock`, and `pre-commit install`.

## Run the checks

Run all three before every commit:

```sh
make test
make check
pre-commit run -a
```

| Command             | What it does                                                                                               |
| ------------------- | ---------------------------------------------------------------------------------------------------------- |
| `make test`         | Runs `pytest` with coverage. It fails below 75 percent                                                     |
| `make test-deploy`  | Runs `deploy/install.sh` and the units through bash against stubbed system tools                           |
| `make test-matrix`  | Runs the tests on Python 3.11, 3.12, 3.13, and 3.14, each in its own venv                                  |
| `make lint`         | Runs `ruff format --check` and `ruff check`                                                                |
| `make shellcheck`   | Runs `shellcheck` on the shell scripts                                                                     |
| `make check`        | Runs `make lint`, `uv lock --check`, `shellcheck`, `markdownlint`, and `prettier --check`                  |
| `pre-commit run -a` | Runs every pre-commit hook on every file                                                                   |
| `make build`        | Builds the sdist and the wheel into `dist/`                                                                |
| `make bundle`       | Builds the release bundle into `dist/`. Needs network                                                      |
| `make audit`        | Checks the locked runtime packages, except `asusrouter`, against the PyPI advisory database. Needs network |

`make check` skips a tool that is not installed.

The hooks run `ruff`, `shellcheck`, `actionlint`, `gitleaks`, `markdownlint`, `prettier`, and basic
file checks. `ruff` also formats the Python code blocks in Markdown files. Some hooks fix files in
place: stage the fixes and commit again. Fix any other failure and run the command again.

## Write the test first

- Write a failing test, then make it pass. Every bug fix needs a regression test that fails without
  the fix.
- Tests never use a real router. They use synthetic data and fixtures. A fixture holds replies with
  placeholder values only.
- Keep coverage at 75 percent or higher. Do not lower it.

## Follow the conventions

- **Commits.** Use [Conventional Commits](https://www.conventionalcommits.org/). The format is
  `type(scope): subject`. Keep the message to one or two lines. Name the specific change in the
  subject. Examples: `fix(mapping): keep a wired row on its total` and
  `docs(install): add the dry-run step`. Types in use are `feat`, `fix`, `docs`, `test`,
  `refactor`, `perf`, `build`, `ci`, and `chore`.
- **Small commits.** Commit after each logical change.
- **Comments.** A code comment explains why, not what. Keep each comment to three lines or fewer.
- **Changelog.** Add one bullet under `## [Unreleased]` in `CHANGELOG.md` for a change that a user
  can see. Keep the bullet to three lines or fewer.
- **Placeholders.** In code, tests, fixtures, and docs, use the router `192.168.50.1`, the
  monitoring host `192.168.50.10`, the MAC addresses `00:00:5e:00:53:xx` (RFC 7042), and names under
  `example.com`. Never commit a real address, MAC, serial number, certificate, or token.
- **Style.** `ruff` formats and lints the Python code. `prettier` formats the Markdown. `markdownlint`
  checks it.

## Work on the docs

The docs use [MkDocs Material](https://squidfunk.github.io/mkdocs-material/). The `docs/requirements.txt`
file pins every package by version and hash. Build the site in a private environment:

```sh
uv venv .venv-docs
uv pip install --python .venv-docs/bin/python --require-hashes -r docs/requirements.txt
.venv-docs/bin/mkdocs serve
```

Open <http://127.0.0.1:8000>. Before you push, run `.venv-docs/bin/mkdocs build --strict`. A warning
fails the build, so a broken link or an orphan page never ships. A pull request builds the site. A
push to `main` builds and publishes it to GitHub Pages.

Material for MkDocs reaches end of life on 2027-05-05. It gets critical fixes and security updates
until then. The build prints a notice about it. Set `NO_MKDOCS_2_WARNING=1` to hide the notice. Plan
a move to a maintained theme before that date.

The pages `docs/contributing.md` and `docs/changelog.md` include the files `CONTRIBUTING.md` and
`CHANGELOG.md`. Edit the root files. Use full `https://` links in them, so they work on GitHub and on
the site.

A test checks the shell blocks in `README.md` and `docs/`: each parses with `bash -n`, each
`aimesh-snmp-proxy` command and each `install.sh` option exists, and each configuration key is
documented. Keep examples in step with the code.

## Submit a change

1. Fork the repository, or create a branch if you have write access. Name the branch
   `type/topic`, for example `fix/ports-json-read`. Branch from `main`.
2. Make small commits. Run the checks before each one.
3. Open a pull request against `main`. Say what changed and why. Link the issue.
4. Wait for CI to pass. A maintainer reviews the change.
5. A maintainer merges with a rebase merge. That keeps each commit and its author.

Never commit to `main`.

## Release a version

Only a maintainer releases. `scripts/release.sh` needs the GitHub CLI (`gh`), a clean working tree,
and a repository-local `git config user.email`. The release commit and the tag use that address as
author and committer. The script refuses a global or environment identity. It reads the changelog
and the version, so keep `## [Unreleased]` in `CHANGELOG.md` current as changes merge. The release
form and the `--tag` form accept `--dry-run`. The workflow also calls `--verify` and `--notes`, which
only read.

**1. Rehearse.** This prints the plan and the release notes. It changes nothing.

```sh
scripts/release.sh --dry-run X.Y.Z
```

**2. Open the release pull request.** The script creates the branch `release/vX.Y.Z` from
`origin/main`. It sets the version in `pyproject.toml` and `uv.lock`, dates the changelog section,
commits `chore(release): vX.Y.Z`, pushes the branch, and opens the pull request.

```sh
scripts/release.sh X.Y.Z
```

**3. Merge the pull request** with a rebase merge. Wait for CI to pass on `main`.

**4. Tag the merged commit.** The script checks CI, creates the annotated tag `vX.Y.Z`, and pushes
it.

```sh
scripts/release.sh --tag X.Y.Z
```

**5. Let the workflow publish.** The tag push runs the release workflow. It builds the wheel, the
sdist, and the offline bundle, writes `SHA256SUMS`, attests every file, and publishes the GitHub
release with the notes from `CHANGELOG.md`. No workflow commits or pushes.

Run `scripts/smoke-test.sh` before you tag. It builds the sdist, the wheel, and the offline bundle,
and checks the bundle checksums. It installs the bundle into a fresh environment and runs
`--version`, `--help`, and `check-config` on the bundled example config with throwaway secrets. CI
runs it as the `smoke` job. It needs `uv`, `git`, `tar`, and network access.

### If a release fails

- **A transient failure,** such as the network or a runner: open the Release run of the tag in the
  Actions tab and choose _Re-run failed jobs_.
- **A real fault:** never reuse a version. Delete the failed draft release and the tag, fix `main`
  by pull request, and release the next patch version. `release.sh --tag` tags the old release
  commit, so a fix on `main` would not reach a re-tagged version.
- **A rehearsal:** run the Release workflow by hand from `main`, from the Actions tab with _Run
  workflow_. It builds and uploads the files and publishes nothing.

## License

The project uses the [Apache License 2.0](https://github.com/islanderman/aimesh-snmp-proxy/blob/main/LICENSE).
Section 5 of the license applies to your contribution: unless you state otherwise, you submit it
under the same license.
