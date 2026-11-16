# Developer entry points. Every target runs through uv against the committed uv.lock.

# Resolve from the PyPI index pinned in pyproject.toml, not an index set in the shell.
unexport UV_INDEX_URL UV_DEFAULT_INDEX

PYTHON ?= 3.12
PYTHONS ?= 3.11 3.12 3.13 3.14
UV_RUN := uv run --frozen --python $(PYTHON)
MD_FILES := $(shell git ls-files '*.md' 2>/dev/null)
SH_FILES := $(or $(shell git ls-files '*.sh' 2>/dev/null),$(wildcard deploy/*.sh))
PIP_AUDIT := pip-audit==2.10.1

.PHONY: init test test-matrix test-deploy lint shellcheck check build bundle audit

init:
	uv sync --locked --python $(PYTHON)
	pre-commit install

test:
	$(UV_RUN) pytest --cov --cov-report=term-missing --cov-fail-under=75

# Run the suite on each supported Python in its own venv.
test-matrix:
	@for v in $(PYTHONS); do \
		UV_PROJECT_ENVIRONMENT=.venv-$$v uv run --frozen --python $$v pytest -q || exit 1; \
	done

# deploy/install.sh and the units, run through bash against stubbed system tools.
test-deploy:
	$(UV_RUN) pytest -q tests/deploy

lint:
	$(UV_RUN) ruff format --check .
	$(UV_RUN) ruff check .

shellcheck:
	shellcheck -x $(SH_FILES)

check: lint
	uv lock --check
	@if command -v shellcheck >/dev/null 2>&1; then shellcheck -x $(SH_FILES); \
		else echo "shellcheck not installed: skipped"; fi
	@if [ -n "$(MD_FILES)" ] && command -v markdownlint >/dev/null 2>&1; then \
		markdownlint $(MD_FILES); fi
	@if [ -n "$(MD_FILES)" ] && command -v prettier >/dev/null 2>&1; then \
		prettier --check $(MD_FILES); fi

# The sdist and wheel, into dist/.
build:
	uv build

# The release tarball deploy/install.sh takes; it packs the committed HEAD (network).
bundle:
	deploy/build-bundle.sh

# Online (PyPI advisories), so check stays offline. Audits every locked runtime
# package by hash; asusrouter is a git pin with no PyPI advisories to query.
audit:
	@tmp=$$(mktemp -d) && trap 'rm -rf "$$tmp"' EXIT && \
	uv export --frozen --no-dev --no-emit-project --no-emit-package asusrouter \
		--format requirements-txt --quiet -o "$$tmp/requirements.txt" && \
	uvx --from '$(PIP_AUDIT)' pip-audit -r "$$tmp/requirements.txt" \
		--require-hashes --disable-pip --cache-dir "$$tmp/cache" --progress-spinner off
