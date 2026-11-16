#!/usr/bin/env bash
# Smoke-test the release files: build the sdist, the wheel and the install bundle, install the
# bundle into a fresh venv, then run the CLI against its config.example.toml.
# Needs uv, git, tar and network access (PyPI, GitHub). Everything lands in one temp directory.
set -euo pipefail

# The index pinned in pyproject.toml decides, as in the Makefile.
unset UV_INDEX_URL UV_DEFAULT_INDEX

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
PYTHON=3.12
KEEP=0
WORK=

usage() {
  cat <<'EOF'
Usage: scripts/smoke-test.sh [--python VERSION] [--keep]

Build the sdist, the wheel and the install bundle from this checkout, check the bundle
checksums, install the bundle into a fresh venv, and run the CLI against the bundled
config.example.toml with throwaway secrets. Needs uv, git, tar and network access.

  --python VERSION  Python for the build and the venv (default: 3.12)
  --keep            keep the temp directory and print its path
EOF
}

say() { printf '%s\n' "$*"; }

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  case ${WORK##*/} in
    aimesh-smoke.*) [ "$KEEP" = 1 ] || { [ -d "$WORK" ] && rm -rf -- "$WORK"; } ;;
  esac
  return 0
}
trap cleanup EXIT

parse_args() {
  while [ $# -gt 0 ]; do
    case $1 in
      --python)
        [ $# -ge 2 ] || die "--python needs a value"
        PYTHON=$2
        shift 2
        ;;
      --keep)
        KEEP=1
        shift
        ;;
      -h | --help)
        usage
        exit 0
        ;;
      *) die "unknown option: $1 (try --help)" ;;
    esac
  done
}

quiet() { # quiet LABEL COMMAND...: show the output only when the command fails
  local label=$1 log=$WORK/last.log
  shift
  "$@" >"$log" 2>&1 || {
    cat "$log" >&2
    die "$label failed"
  }
  grep '^warning:' "$log" >&2 || true
}

sha256_check() { # sha256_check DIR FILE: verify the sums in FILE, which names files inside DIR
  local out
  if command -v sha256sum >/dev/null 2>&1; then
    out=$(cd "$1" && sha256sum -c "$2" 2>&1) || { printf '%s\n' "$out" >&2; return 1; }
  else
    out=$(cd "$1" && shasum -a 256 -c "$2" 2>&1) || { printf '%s\n' "$out" >&2; return 1; }
  fi
}

# Every *_file setting of the example config gets a throwaway file: a certificate for the
# ca_file settings, a random one-line secret for the rest. Nothing here is a real credential.
make_throwaway_files() { # make_throwaway_files PYTHON CONFIG DIR
  "$1" -I - "$2" "$3" <<'PY'
import datetime
import secrets
import sys
import tomllib
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

config, out = Path(sys.argv[1]), Path(sys.argv[2])


def file_settings(node):
    """Yield (setting, value) for each *_file key, in any table or array of tables."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key.endswith("_file") and isinstance(value, str):
                yield key, value
            else:
                yield from file_settings(value)
    elif isinstance(node, list):
        for item in node:
            yield from file_settings(item)


key = ec.generate_private_key(ec.SECP256R1())
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "router.example.com")])
now = datetime.datetime.now(datetime.timezone.utc)
cert = (
    x509.CertificateBuilder()
    .subject_name(name)
    .issuer_name(name)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - datetime.timedelta(days=1))
    .not_valid_after(now + datetime.timedelta(days=2))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(key, hashes.SHA256())
)
pem = cert.public_bytes(serialization.Encoding.PEM)

for setting, value in sorted(set(file_settings(tomllib.loads(config.read_text())))):
    if Path(value).is_absolute():
        sys.exit(f"{setting} names an absolute path: the example config must use relative names")
    target = out / value
    target.parent.mkdir(parents=True, exist_ok=True)
    if setting.endswith("ca_file"):
        target.write_bytes(pem)
        target.chmod(0o644)
    else:
        target.write_text(secrets.token_hex(16) + "\n")
        target.chmod(0o600)
PY
}

check_licenses() { # check_licenses PYTHON WHEEL SDIST: both files must carry the license text
  "$1" -I - "$2" "$3" <<'PY'
import sys
import tarfile
import zipfile

wheel, sdist = sys.argv[1:3]
with zipfile.ZipFile(wheel) as archive:
    names = archive.namelist()
if not any(name.rsplit("/", 1)[-1] == "LICENSE" for name in names):
    sys.exit("the wheel carries no LICENSE file")
with tarfile.open(sdist) as archive:
    names = archive.getnames()
if not any(name.rsplit("/", 1)[-1] == "LICENSE" for name in names):
    sys.exit("the sdist carries no LICENSE file")
PY
}

main() {
  local tool dist wheel sdist bundle version base count file bundle_dir venv cli etc creds status out
  local -a wheels
  parse_args "$@"
  for tool in uv git tar; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
  done
  git -C "$ROOT" rev-parse --verify --quiet HEAD >/dev/null || die "$ROOT has no commit to bundle"
  [ -f "$ROOT/LICENSE" ] || die "$ROOT has no LICENSE file"
  WORK=$(mktemp -d "${TMPDIR:-/tmp}/aimesh-smoke.XXXXXX")
  dist=$WORK/dist
  venv=$WORK/venv

  say "build: sdist and wheel"
  quiet "uv build" uv build --python "$PYTHON" --out-dir "$dist" "$ROOT"
  say "build: install bundle (commit $(git -C "$ROOT" rev-parse --short HEAD))"
  quiet "deploy/build-bundle.sh" "$ROOT/deploy/build-bundle.sh" --out-dir "$dist"

  shopt -s nullglob
  wheels=("$dist"/*.whl)
  [ ${#wheels[@]} -eq 1 ] || die "expected one wheel in dist, found ${#wheels[@]}"
  wheel=${wheels[0]}
  base=${wheel##*/}
  version=${base#*-}
  version=${version%%-*}
  sdist=$dist/aimesh_snmp_proxy-$version.tar.gz
  bundle=$dist/aimesh-snmp-proxy-$version.tar.gz
  count=0
  for file in "$dist"/*; do
    count=$((count + 1))
    case $file in
      "$wheel" | "$sdist" | "$bundle" | "$bundle.sha256") ;;
      *) die "dist holds an unexpected file: ${file##*/}" ;;
    esac
  done
  [ "$count" -eq 4 ] || die "dist holds $count files, expected the sdist, the wheel, the bundle and its .sha256"

  say "check: bundle checksums"
  sha256_check "$dist" "${bundle##*/}.sha256" || die "the bundle does not match its .sha256"
  mkdir "$WORK/unpacked"
  tar -xzf "$bundle" -C "$WORK/unpacked"
  bundle_dir=$WORK/unpacked/aimesh-snmp-proxy-$version
  [ -d "$bundle_dir" ] || die "the bundle does not unpack to aimesh-snmp-proxy-$version/"
  sha256_check "$bundle_dir" SHA256SUMS || die "the bundle files do not match its SHA256SUMS"

  say "install: bundle requirements, then the built wheel, into a fresh venv (python $PYTHON)"
  quiet "uv venv" uv venv --quiet --python "$PYTHON" "$venv"
  (
    cd "$bundle_dir"
    quiet "installing the bundle requirements" uv pip install --quiet --python "$venv/bin/python" \
      --require-hashes --no-deps --only-binary :all: -r requirements.txt
  )
  quiet "installing the wheel" uv pip install --quiet --python "$venv/bin/python" \
    --no-deps --reinstall-package aimesh-snmp-proxy "$wheel"
  quiet "uv pip check" uv pip check --python "$venv/bin/python"
  check_licenses "$venv/bin/python" "$wheel" "$sdist" || die "a release file is missing its license"

  say "run: --version, --help and check-config"
  cli=$venv/bin/aimesh-snmp-proxy
  out=$("$cli" --version) || die "--version failed"
  [ "$out" = "aimesh-snmp-proxy $version" ] ||
    die "--version printed '$out', expected 'aimesh-snmp-proxy $version'"
  "$cli" --help >/dev/null || die "--help failed"
  "$cli" check-config --help >/dev/null || die "check-config --help failed"

  etc=$WORK/etc
  creds=$WORK/creds
  mkdir -m 0700 "$etc" "$creds"
  cp "$bundle_dir/config.example.toml" "$etc/config.toml"
  make_throwaway_files "$venv/bin/python" "$etc/config.toml" "$creds" ||
    die "cannot make throwaway files for config.example.toml"
  out=$(env -i PATH=/usr/bin:/bin HOME="$WORK" CREDENTIALS_DIRECTORY="$creds" \
    "$cli" --config "$etc/config.toml" check-config 2>&1) || {
    printf '%s\n' "$out" >&2
    die "check-config rejects config.example.toml with throwaway secrets"
  }
  case $out in
    "config ok: "*) ;;
    *) die "check-config did not report 'config ok:'" ;;
  esac

  # A run without the secret files must fail: it proves the check above reads them.
  mkdir -m 0700 "$WORK/empty"
  status=0
  env -i PATH=/usr/bin:/bin HOME="$WORK" CREDENTIALS_DIRECTORY="$WORK/empty" \
    "$cli" --config "$etc/config.toml" check-config >/dev/null 2>&1 || status=$?
  [ "$status" -eq 78 ] || die "check-config without secret files exited $status, expected 78"

  say "ok: smoke test passed for $version"
  if [ "$KEEP" = 1 ]; then say "kept: $WORK"; fi
}

main "$@"
