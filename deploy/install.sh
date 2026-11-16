#!/usr/bin/env bash
# Install aimesh-snmp-proxy as a native systemd service on the LibreNMS host.
# Run as root from an unpacked bundle. It never starts or enables the service,
# never reads a secret file and never prints a secret.
set -euo pipefail
umask 077

NAME=aimesh-snmp-proxy
PREFIX=/opt/$NAME
ETC_DIR=/etc/$NAME
UNIT_DIR=/etc/systemd/system
STATE_DIR=/var/lib/$NAME
CREDENTIALS_MIN=247 # first systemd with LoadCredential= and ProtectProc=
ENCRYPTED_MIN=250   # first systemd with LoadCredentialEncrypted=
PLACEHOLDERS="asus_password snmp_community asus_router.pem"
NAME_RE='^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$' # an instance name: a unit name and a folder
STATE_LINE='state_dir = "/var/lib/aimesh-snmp-proxy"' # in the example, redirected per instance

DRY_RUN=0
UNINSTALL=0
PURGE=0
YES=0
PYTHON=
INSTANCE=
INSTANCE_GIVEN=0
ERRORS=0
LEGACY=0
USE_UV=0
IP_ALLOW=
PINS= # credential names of the node pins, one per line
PYTHON_BIN=
VERSION=
SYSTEMD_VERSION=

usage() {
  cat <<EOF
Usage: install.sh [--prefix DIR] [--python PATH] [--dry-run]
       install.sh --instance NAME [--prefix DIR] [--python PATH] [--dry-run]
       install.sh --uninstall [--purge [--yes]] [--prefix DIR] [--dry-run]
       install.sh --instance NAME --uninstall [--purge [--yes]] [--dry-run]

Install $NAME from this bundle as a systemd service. Needs root and Python >= 3.11.
It never starts or enables the service; running it again upgrades in place.

  --instance NAME  one more service, for another router: unit $NAME@NAME, config in
                   $ETC_DIR/NAME, state in $STATE_DIR-NAME. All services share one venv,
                   so every run that builds it refuses while any of them runs.
                   NAME: lower-case letters, digits and '-', 1-32 characters.
  --prefix DIR   application directory, holds venv/ (default $PREFIX)
  --python PATH  Python >= 3.11 for the venv (default: python3.12, 3.11, 3.13, 3.14, python3)
  --dry-run      run every check and print the plan; change nothing, no root needed
  --uninstall    stop the service, remove the unit and the venv; keep config and state.
                 With --instance: only that instance's drop-in; the venv stays.
  --purge        with --uninstall: also delete the config and state (all of $ETC_DIR
                 and $STATE_DIR, or with --instance only that instance's)
  --yes          do not ask before --purge deletes
Environment: DESTDIR installs below that directory instead of / (tests, packaging).
EOF
}

say() { printf '%s\n' "$*"; }
ok() { printf '  ok    %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
err() {
  printf 'error: %s\n' "$*" >&2
  ERRORS=$((ERRORS + 1))
}
die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}
usage_error() {
  printf 'error: %s\n\n' "$*" >&2
  usage >&2
  exit 2
}

# Every state change goes through here, so --dry-run can only print.
run() {
  if [ "$DRY_RUN" = 1 ]; then
    printf '  would run:'
    printf ' %q' "$@"
    printf '\n'
  else
    "$@"
  fi
}

parse_args() {
  while [ $# -gt 0 ]; do
    case $1 in
      --prefix | --python)
        [ $# -ge 2 ] || usage_error "$1 needs a value"
        if [ "$1" = --prefix ]; then PREFIX=$2; else PYTHON=$2; fi
        shift 2
        ;;
      --instance)
        [ $# -ge 2 ] || usage_error "--instance needs a value"
        INSTANCE=$2
        INSTANCE_GIVEN=1
        shift 2
        ;;
      --instance=*) INSTANCE=${1#*=} && INSTANCE_GIVEN=1 && shift ;;
      --prefix=*) PREFIX=${1#*=} && shift ;;
      --python=*) PYTHON=${1#*=} && shift ;;
      --uninstall) UNINSTALL=1 && shift ;;
      --purge) PURGE=1 && shift ;;
      --yes) YES=1 && shift ;;
      --dry-run) DRY_RUN=1 && shift ;;
      -h | --help) usage && exit 0 ;;
      *) usage_error "unknown option: $1" ;;
    esac
  done
  if [ "$PURGE" = 1 ] && [ "$UNINSTALL" = 0 ]; then usage_error "--purge needs --uninstall"; fi
  # The name lands in unit names, folder names and rm targets: plain characters only.
  if [ "$INSTANCE_GIVEN" = 1 ] && ! [[ $INSTANCE =~ $NAME_RE ]]; then
    usage_error "--instance must be 1-32 lower-case letters, digits or '-', not at either end, got: $INSTANCE"
  fi
  # The path lands in a unit file and in rm targets: plain characters only.
  [[ $PREFIX =~ ^(/[A-Za-z0-9_+-][A-Za-z0-9._+-]*){2,}$ ]] ||
    usage_error "--prefix must be an absolute path of 2+ plain components, got: $PREFIX"
}

set_paths() {
  local root=${DESTDIR:-}
  root=${root%/}
  case $root in "" | /*) ;; *) die "DESTDIR must be an absolute path" ;; esac
  ROOT=$root
  APP=$ROOT$PREFIX
  VENV=$APP/venv
  ETC=$ROOT$ETC_DIR
  TEMPLATE_UNIT=$ROOT$UNIT_DIR/$NAME@.service
  UNIT_FILE=$NAME.service
  SERVICE=$NAME.service
  UNIT=$ROOT$UNIT_DIR/$SERVICE
  DROPIN=
  NODE_CA_DROPIN=
  CONF=$ETC
  CONF_DIR=$ETC_DIR
  STATE_PRIVATE=$ROOT/var/lib/private/$NAME
  if [ -n "$INSTANCE" ]; then
    UNIT_FILE=$NAME@.service
    SERVICE=$NAME@$INSTANCE.service
    UNIT=$ROOT$UNIT_DIR/$SERVICE # no file of this name: only its drop-in folder, $UNIT.d
    DROPIN=$UNIT.d/10-ip-allow.conf
    NODE_CA_DROPIN=$UNIT.d/20-node-ca.conf
    CONF=$ETC/$INSTANCE
    CONF_DIR=$ETC_DIR/$INSTANCE
    STATE_DIR=$STATE_DIR-$INSTANCE
    STATE_PRIVATE=$ROOT/var/lib/private/$NAME-$INSTANCE
  fi
  STATE=$ROOT$STATE_DIR
  BUNDLE=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
}

# --- checks ------------------------------------------------------------------

check_root() {
  local uid
  uid=$(id -u)
  if [ "$uid" = 0 ]; then
    ok "running as root"
  elif [ "$DRY_RUN" = 1 ]; then
    warn "not root (uid $uid): $ETC_DIR is unreadable here; a real run needs sudo"
  else
    err "run as root (sudo); --dry-run works without it"
  fi
}

verify_checksums() {
  cd "$BUNDLE"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c SHA256SUMS
  else
    shasum -a 256 -c SHA256SUMS
  fi
}

check_bundle() {
  local file sums
  for file in requirements.txt config.example.toml "deploy/$UNIT_FILE"; do
    [ -f "$BUNDLE/$file" ] ||
      err "not a bundle: $BUNDLE/$file is missing (build one with deploy/build-bundle.sh)"
  done
  [ -d "$BUNDLE/wheels" ] || err "not a bundle: $BUNDLE/wheels is missing"
  [ "$ERRORS" = 0 ] || return 0
  if [ ! -f "$BUNDLE/SHA256SUMS" ]; then
    warn "no SHA256SUMS in the bundle: transfer integrity is not checked"
  elif sums=$(verify_checksums 2>&1); then
    ok "bundle files match SHA256SUMS"
  else
    err "bundle checksum mismatch, re-copy the bundle:"
    printf '%s\n' "$sums" | grep -v ': OK$' >&2 || true
  fi
  VERSION=$(sed -n 's|^\./wheels/aimesh_snmp_proxy-\([^-]*\)-.*|\1|p' "$BUNDLE/requirements.txt" | head -n 1)
  [ -n "$VERSION" ] || err "requirements.txt does not pin the aimesh_snmp_proxy wheel"
}

python_version() { "$1" -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])' 2>/dev/null; }

python_ok() { # python_ok VERSION: at least 3.11
  local major=${1%%.*} rest=${1#*.}
  local minor=${rest%%.*}
  [ "$major" -gt 3 ] || { [ "$major" -eq 3 ] && [ "$minor" -ge 11 ]; }
}

check_python() {
  local candidate version found=
  if [ -n "$PYTHON" ]; then set -- "$PYTHON"; else set -- python3.12 python3.11 python3.13 python3.14 python3; fi
  for candidate in "$@"; do
    command -v "$candidate" >/dev/null 2>&1 || continue
    version=$(python_version "$candidate") || continue
    if python_ok "$version"; then
      PYTHON_BIN=$(command -v "$candidate")
      found=$version
      break
    fi
    warn "$candidate is Python $version; 3.11 or newer is needed"
  done
  if [ -z "$found" ]; then
    err "no Python >= 3.11 found: install one and pass --python /path/to/python3.x"
    return 0
  fi
  ok "python $found ($PYTHON_BIN)"
  "$PYTHON_BIN" -I -c 'import venv, ensurepip' 2>/dev/null && return 0
  if command -v uv >/dev/null 2>&1; then
    USE_UV=1
    ok "python has no venv or ensurepip module: the venv comes from uv"
  else
    err "python lacks venv or ensurepip: apt install python3-venv (python${found%.*}-venv for this interpreter), or install uv"
  fi
}

# The unit sets ProtectHome=yes, so an interpreter under /home or /root is invisible to it.
check_interpreter_location() {
  local real
  [ -n "$PYTHON_BIN" ] && [ -z "$ROOT" ] || return 0
  real=$("$PYTHON_BIN" -I -c 'import os, sys; print(os.path.realpath(sys.executable))')
  case $real in
    /home/* | /root/* | /run/user/*)
      err "$real is under a directory the service cannot see: use a system-wide Python"
      ;;
  esac
}

check_systemd() {
  local out first word version
  if ! command -v systemctl >/dev/null 2>&1; then
    err "systemctl not found: this installer targets systemd hosts"
    return 0
  fi
  out=$(systemctl --version 2>/dev/null) || out=
  first=${out%%$'\n'*}
  read -r word version _ <<<"$first"
  if [ "$word" != systemd ] || ! [[ $version =~ ^[0-9]+$ ]]; then
    err "cannot read the systemd version from: $first"
    return 0
  fi
  SYSTEMD_VERSION=$version
  if [ "$version" -ge "$CREDENTIALS_MIN" ]; then
    ok "systemd $version: DynamicUser= and LoadCredential= available"
    if [ "$version" -ge "$ENCRYPTED_MIN" ]; then
      say "  note  LoadCredentialEncrypted= is available too (optional: README.md, Security)"
    fi
    return 0
  fi
  LEGACY=1
  if [ -n "$INSTANCE" ]; then
    err "instances need systemd $CREDENTIALS_MIN or newer (DynamicUser= and LoadCredential=); this host has $version"
    return 0
  fi
  warn "systemd $version has no LoadCredential= (needs $CREDENTIALS_MIN): using the static user $NAME, which owns $ETC_DIR (0700) and its 0600 files"
  if ! getent passwd "$NAME" >/dev/null 2>&1 && ! command -v useradd >/dev/null 2>&1; then
    err "legacy mode needs useradd to create the user $NAME"
  fi
}

# Every instance this host knows: a config folder, a drop-in, or a loaded unit.
instance_names() {
  local path name
  {
    for path in "$ETC"/*/ "$ROOT$UNIT_DIR/$NAME@"*.service.d; do
      [ -d "$path" ] || continue
      name=${path%/}
      name=${name##*/}
      name=${name#"$NAME@"}
      printf '%s\n' "${name%.service.d}"
    done
    if command -v systemctl >/dev/null 2>&1; then
      systemctl list-units --all --plain --no-legend --no-pager "$NAME@*.service" 2>/dev/null |
        awk -v p="$NAME@" '{ for (i = 1; i <= NF; i++) if (index($i, p) == 1) {
          sub(/\.service$/, "", $i); print substr($i, length(p) + 1); break } }'
    fi
  } | grep -E "$NAME_RE" | sort -u || true
}

service_units() { # the single unit, then one per instance
  local name
  printf '%s.service\n' "$NAME"
  while IFS= read -r name; do
    [ -z "$name" ] || printf '%s@%s.service\n' "$NAME" "$name"
  done <<<"$(instance_names)"
}

# The venv is shared, so a run that rebuilds it must find every service stopped.
check_service_idle() {
  local state unit
  command -v systemctl >/dev/null 2>&1 || return 0
  while IFS= read -r unit; do
    state=$(systemctl is-active "$unit" 2>/dev/null || true)
    case $state in
      active | activating | reloading)
        err "$unit is $state: stop it first (systemctl stop ${unit%.service}), then re-run"
        ;;
      *) ok "$unit is not running (${state:-not loaded})" ;;
    esac
  done <<<"$(service_units)"
}

# Line 1 is the unit's IP allow list: loopback, the router and, in per_node mode,
# the expected nodes. Later lines are notes about files the unit does not load, and
# "credential: NAME KEY" per node pin (node CA, override ca_file) it must load.
read_config() { # read_config CONFIG UNIT_TEMPLATE LEGACY ETC_FOLDER [STATE_DIR]
  "$PYTHON_BIN" -I - "$1" "$2" "$3" "$4" "${5:-}" <<'PY'
import ipaddress
import re
import sys
import tomllib


def expand(item):
    first, sep, last = item.strip().partition("-")
    start = ipaddress.IPv4Address(first.strip())
    if not sep:
        return [start]
    last = last.strip()
    if last.isdigit():
        if int(last) > 255:
            raise ValueError(item)
        end = ipaddress.IPv4Address(int(start) - int(start) % 256 + int(last))
    else:
        end = ipaddress.IPv4Address(last)
    if end < start or int(end) - int(start) >= 255:
        raise ValueError(item)
    return [ipaddress.IPv4Address(n) for n in range(int(start), int(end) + 1)]


try:
    with open(sys.argv[1], "rb") as fh:
        cfg = tomllib.load(fh)
except (OSError, tomllib.TOMLDecodeError) as exc:
    sys.exit(f"cannot read the config: {exc}")
asus = cfg.get("asus")
host = asus.get("host") if isinstance(asus, dict) else None
try:
    if not isinstance(host, str):
        raise ValueError(host)
    router = ipaddress.ip_address(host)
except ValueError:
    sys.exit("asus.host must be an IP address: systemd IPAddressAllow= takes no names")
pins = [("asus.node_ca_file", asus.get("node_ca_file"), "asus_node_ca.pem")]
overrides = cfg.get("override")
for index, item in enumerate(overrides if isinstance(overrides, list) else []):
    if isinstance(item, dict):
        pins.append((f"override[{index}].ca_file", item.get("ca_file"), "node-104.pem"))
# The name lands in a unit line: a plain file name only, never a path or a newline.
for key, name, example in pins:
    if isinstance(name, str) and not name.startswith("/"):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", name):
            sys.exit(
                f"{key} must name a file in {sys.argv[4]} such as {example}, "
                "or be an absolute path"
            )
addresses = [str(router)]
collector = cfg.get("collector")
if isinstance(collector, dict) and collector.get("mode") == "per_node":
    nodes = cfg.get("nodes")
    expected = nodes.get("expected", []) if isinstance(nodes, dict) else []
    if isinstance(expected, str):
        expected = [expected]
    try:
        for item in expected:
            addresses += [str(a) for a in expand(item)]
    except (ValueError, TypeError):
        sys.exit("nodes.expected must hold IPv4 addresses or ranges")
print(" ".join(["localhost", *dict.fromkeys(addresses)]))


def table(parent, key):
    value = parent.get(key) if isinstance(parent, dict) else None
    return value if isinstance(value, dict) else {}


loaded = set()
with open(sys.argv[2]) as fh:
    for line in fh:
        if line.startswith("LoadCredential="):
            loaded.add(line.split("=", 1)[1].split(":", 1)[0].strip())
etc, state = sys.argv[4], cfg.get("state_dir")
if sys.argv[5] and isinstance(state, str) and state != sys.argv[5]:
    print(f"note: state_dir is {state}, but the unit lets it write only {sys.argv[5]}")
snmp, v3 = table(cfg, "snmp"), table(table(cfg, "snmp"), "v3")
named = {
    "asus.password_file": table(cfg, "asus").get("password_file"),
    "asus.ca_file": table(cfg, "asus").get("ca_file"),
    "snmp.community_file": snmp.get("community_file"),
    "snmp.v3.auth_key_file": v3.get("auth_key_file"),
    "snmp.v3.priv_key_file": v3.get("priv_key_file"),
}
examples = {
    "asus.password_file": "asus_password",
    "snmp.community_file": "snmp_community",
    "snmp.v3.auth_key_file": "snmp_auth_key",
    "snmp.v3.priv_key_file": "snmp_priv_key",
}
for key, name in named.items():
    if sys.argv[3] == "1" or not isinstance(name, str) or name in loaded:
        continue
    if key in examples:  # its value may be the secret itself: never print it
        hint = f"the value must name a file such as {examples[key]}, not the secret itself"
        if name.startswith("/"):
            print(
                f"note: {key} is read by the service user from an absolute path, "
                f"not as a credential; {hint}"
            )
        else:
            print(
                f"note: {key} is not loaded by the unit: add "
                f"LoadCredential=FILE:{etc}/FILE for the file it "
                f"names (systemctl edit); {hint}"
            )
    elif name.startswith("/"):
        print(f"note: {key} = {name} is read by the service user, not as a credential")
    else:
        print(
            f"note: {key} = {name} is not loaded by the unit: add "
            f"LoadCredential={name}:{etc}/{name} (systemctl edit)"
        )
if sys.argv[3] == "1":  # the static user reads the pin files itself
    pins = []
for key, name, _ in pins:
    if not isinstance(name, str):
        continue
    if name.startswith("/"):
        print(f"note: {key} is read by the service user from {name}, not as a credential")
    elif name not in loaded:
        loaded.add(name)  # one credential per file, however many keys name it
        print(f"credential: {name} {key}")
PY
}

# Two services on one port would answer for each other's routers: one binds, one fails.
port_base_of() { # port_base_of CONFIG: snmp.port_base, or nothing when unreadable
  "$PYTHON_BIN" -I - "$1" <<'PY' 2>/dev/null || true
import sys
import tomllib

try:
    with open(sys.argv[1], "rb") as fh:
        snmp = tomllib.load(fh).get("snmp")
except (OSError, tomllib.TOMLDecodeError):
    sys.exit(0)
base = snmp.get("port_base", 16101) if isinstance(snmp, dict) else 16101
if isinstance(base, int) and not isinstance(base, bool):
    print(base)
PY
}

# The config this run reads is the bundle example until it exists: then only warn.
check_ports() { # check_ports CONFIG
  local mine other cfg msg
  mine=$(port_base_of "$1")
  [ -n "$mine" ] || return 0
  for cfg in "$ETC/config.toml" "$ETC"/*/config.toml; do
    if [ ! -r "$cfg" ] || [ "$cfg" = "$CONF/config.toml" ]; then continue; fi
    other=$(port_base_of "$cfg")
    [ "$other" = "$mine" ] || continue
    msg="snmp.port_base $mine is also the port base of ${cfg#"$ROOT"}: a port has one owner, so LibreNMS would poll the wrong router; give each service its own (16201, 16301, ...)"
    if [ "$1" = "$CONF/config.toml" ]; then
      err "$msg"
    else
      warn "$msg: set it in $CONF_DIR/config.toml, which this run seeds from the example"
    fi
  done
}

check_config() {
  local source=$CONF/config.toml out line own=
  [ -n "$PYTHON_BIN" ] || return 0
  if [ -r "$source" ]; then
    own=${INSTANCE:+$STATE_DIR} # an instance's own config must name its own state folder
  else
    source=$BUNDLE/config.example.toml
    say "  note  no readable $CONF_DIR/config.toml: using the bundle example"
    if [ -n "$INSTANCE" ] && ! grep -qxF "$STATE_LINE" "$source"; then
      err "$source has no '$STATE_LINE' line to point at this instance's state directory"
    fi
  fi
  if ! out=$(read_config "$source" "$BUNDLE/deploy/$UNIT_FILE" "$LEGACY" "$CONF_DIR" "$own" 2>&1); then
    err "$source: $out"
    return 0
  fi
  IP_ALLOW=${out%%$'\n'*}
  ok "the unit will allow only: $IP_ALLOW"
  PINS=
  while IFS=' ' read -r tag name key; do
    if [ "$tag" = "credential:" ]; then
      PINS+=$name$'\n'
      ok "$key loads as credential $name from $CONF_DIR/$name"
    fi
  done <<<"$out"
  while IFS= read -r line; do
    case $line in note:*) warn "${line#note: }" ;; esac
  done <<<"$out"
  check_ports "$source"
}

finish_checks() {
  if [ "$ERRORS" != 0 ]; then die "$ERRORS check(s) failed; nothing was changed"; fi
}

# --- install -------------------------------------------------------------------

owner() {
  if [ "$LEGACY" = 1 ]; then printf '%s:%s' "$NAME" "$NAME"; else printf 'root:root'; fi
}

# Copy through a temp file in the destination directory, then rename: no torn files.
install_file() { # install_file MODE SOURCE DEST
  local mode=$1 source=$2 dest=$3 tmp
  if [ "$DRY_RUN" = 1 ]; then
    say "  would write $dest ($mode)"
    return 0
  fi
  tmp=$(mktemp "$dest.XXXXXX")
  cp "$source" "$tmp"
  chmod "$mode" "$tmp"
  mv -f "$tmp" "$dest"
}

ensure_service_user() {
  [ "$LEGACY" = 1 ] || return 0
  if getent passwd "$NAME" >/dev/null 2>&1; then
    say "  kept system user $NAME"
  else
    run useradd --system --user-group --no-create-home --home-dir /nonexistent \
      --shell "$(command -v nologin || echo /usr/sbin/nologin)" "$NAME"
  fi
}

# The old venv waits at venv.prev until the new one imports cleanly, so a failed
# upgrade (no network, bad hash) leaves the previous install usable.
build_venv() {
  local prev=$VENV.prev
  say "venv: $VENV (pip runs in $BUNDLE: its requirements.txt names the wheels by relative path)"
  if [ -e "$prev" ]; then
    [ ! -e "$VENV" ] || die "$prev is left over from an interrupted run: check $VENV, then delete $prev"
    run mv "$prev" "$VENV"
  fi
  if [ -e "$VENV" ]; then run mv "$VENV" "$prev"; fi
  # An if-condition turns errexit off inside the subshell, so each step exits on failure.
  # pip keeps the mode umask gives each file, and the service user must read them.
  if ! (
    umask 022
    run mkdir -p "$APP" || exit 1
    cd "$BUNDLE" || exit 1
    if [ "$USE_UV" = 1 ]; then
      run uv venv --quiet --python "$PYTHON_BIN" "$VENV" || exit 1
      run uv pip install --quiet --python "$VENV/bin/python" \
        --require-hashes --no-deps --only-binary :all: -r requirements.txt || exit 1
      run uv pip check --python "$VENV/bin/python" || exit 1
    else
      run "$PYTHON_BIN" -I -m venv "$VENV" || exit 1
      run "$VENV/bin/python" -I -m pip install --quiet --no-cache-dir \
        --disable-pip-version-check --no-input --require-hashes --only-binary=:all: \
        --no-deps -r requirements.txt || exit 1
      run "$VENV/bin/python" -I -m pip check --disable-pip-version-check || exit 1
    fi
    run "$VENV/bin/python" -I -c 'import aimesh_snmp_proxy' || exit 1
  ); then
    remove_path "$VENV"
    if [ -e "$prev" ]; then mv "$prev" "$VENV" && say "restored the previous venv"; fi
    die "venv build failed: the previous install, if any, is unchanged"
  fi
  if [ "$DRY_RUN" = 1 ]; then
    say "  would delete $prev once the new venv imports cleanly"
  elif [ -e "$prev" ]; then
    remove_path "$prev"
  fi
  run chmod 0755 "$APP"
}

# An instance keeps its own state: the example's state_dir becomes its own folder.
seed_instance_config() { # seed_instance_config DEST
  local tmp
  if [ "$DRY_RUN" = 1 ]; then
    say "  would write $1 (0600), state_dir $STATE_DIR"
    return 0
  fi
  tmp=$(mktemp "$1.XXXXXX")
  awk -v line="$STATE_LINE" -v dir="$STATE_DIR" '
    $0 == line { print "state_dir = \"" dir "\""; next }
    { print }' "$BUNDLE/config.example.toml" >"$tmp"
  chmod 0600 "$tmp"
  mv -f "$tmp" "$1"
}

place_config() {
  local file
  say "config: $CONF"
  if [ -n "$INSTANCE" ]; then
    run mkdir -p "$ETC"
    run chmod 0700 "$ETC"
  fi
  run mkdir -p "$CONF"
  run chmod 0700 "$CONF"
  if [ -e "$CONF/config.toml" ]; then
    say "  kept config.toml (after an upgrade compare it with $BUNDLE/config.example.toml)"
    run chmod 0600 "$CONF/config.toml"
  elif [ -n "$INSTANCE" ]; then
    seed_instance_config "$CONF/config.toml"
  else
    install_file 0600 "$BUNDLE/config.example.toml" "$CONF/config.toml"
  fi
  for file in $PLACEHOLDERS; do
    if [ -e "$CONF/$file" ]; then
      say "  kept $file"
    elif [ "$DRY_RUN" = 1 ]; then
      say "  would create empty $CONF/$file (0600)"
      continue
    else
      : >"$CONF/$file"
      say "  created empty $file: fill it in"
    fi
    run chmod 0600 "$CONF/$file"
  done
  run chown -R "$(owner)" "$CONF"
  if [ -n "$INSTANCE" ]; then run chown "$(owner)" "$ETC"; fi
}

render_unit() { # render_unit TEMPLATE [EXTRA_LINES]: print the unit for this host
  # EXTRA goes by environment: awk -v takes no newline on every awk.
  EXTRA=${2:-} awk -v prefix="$PREFIX" -v allow="$IP_ALLOW" -v legacy="$LEGACY" -v svc="$NAME" \
    -v etc="$ETC_DIR" -v ver="$SYSTEMD_VERSION" '
    BEGIN { extra = ENVIRON["EXTRA"] }
    NR == 1 && legacy == 1 {
      print "# Legacy variant for systemd " ver " (before 247): static user, no LoadCredential=."
    }
    legacy == 1 && /^(DynamicUser|LoadCredential)=/ { next }
    legacy == 1 && /^# Optional from systemd 250/ { next }
    legacy == 1 && /^\[Service\]$/ { print; print "User=" svc; print "Group=" svc; next }
    /^LoadCredential=/ { loading = 1 }
    loading && !/^LoadCredential=/ { loading = 0; if (extra != "") print extra }
    {
      gsub(/@PREFIX@/, prefix)
      gsub(/@IP_ALLOW@/, allow)
      if (legacy == 1) gsub(/[$][{]CREDENTIALS_DIRECTORY[}]\//, etc "/")
      print
    }
    END { if (loading && extra != "") print extra }' "$1"
}

write_unit() { # write_unit SOURCE DEST [EXTRA_LINES]: the unit for this host, mode 0644
  local tmp
  mkdir -p "$(dirname "$2")"
  tmp=$(mktemp "$2.XXXXXX")
  render_unit "$1" "${3:-}" >"$tmp"
  if grep -q '@[A-Z_][A-Z_]*@' "$tmp"; then
    rm -f -- "$tmp"
    die "the unit template has a placeholder install.sh does not fill"
  fi
  chmod 0644 "$tmp"
  mv -f "$tmp" "$2"
}

place_template() {
  say "unit: $TEMPLATE_UNIT"
  if [ "$DRY_RUN" = 1 ]; then
    say "  would write $TEMPLATE_UNIT (0644)"
    return 0
  fi
  write_unit "$BUNDLE/deploy/$NAME@.service" "$TEMPLATE_UNIT"
}

# The template names no router: this drop-in lets the instance reach its own.
place_dropin() {
  local tmp
  say "drop-in: $DROPIN"
  if [ "$DRY_RUN" = 1 ]; then
    say "  would write $DROPIN (0644) with IPAddressAllow=$IP_ALLOW"
    return 0
  fi
  mkdir -p "$UNIT.d"
  chmod 0755 "$UNIT.d"
  tmp=$(mktemp "$DROPIN.XXXXXX")
  {
    printf '# Written by install.sh from %s/config.toml: run it again after a change.\n' "$CONF_DIR"
    printf '[Service]\nIPAddressAllow=\nIPAddressAllow=%s\n' "$IP_ALLOW"
  } >"$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$DROPIN"
}

pin_lines() { # the unit lines that load the node pins, one per line, or nothing
  local name
  while IFS= read -r name; do
    if [ -n "$name" ]; then printf 'LoadCredential=%s:%s/%s\n' "$name" "$CONF_DIR" "$name"; fi
  done <<<"$PINS"
}

# The template is shared, so an instance loads its own node pins from a drop-in.
place_node_ca_dropin() {
  local tmp lines line
  lines=$(pin_lines)
  if [ -z "$lines" ]; then
    if [ -e "$NODE_CA_DROPIN" ]; then
      say "drop-in: $NODE_CA_DROPIN, no node pins any more"
      remove_path "$NODE_CA_DROPIN"
    fi
    return 0
  fi
  say "drop-in: $NODE_CA_DROPIN"
  if [ "$DRY_RUN" = 1 ]; then
    say "  would write $NODE_CA_DROPIN (0644) with"
    while IFS= read -r line; do say "    $line"; done <<<"$lines"
    return 0
  fi
  mkdir -p "$UNIT.d"
  tmp=$(mktemp "$NODE_CA_DROPIN.XXXXXX")
  {
    printf '# Written by install.sh from %s/config.toml: run it again after a change.\n' "$CONF_DIR"
    printf '[Service]\n%s\n' "$lines"
  } >"$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$NODE_CA_DROPIN"
}

place_unit() {
  local line
  if [ -n "$INSTANCE" ]; then
    place_template
    place_dropin
    place_node_ca_dropin
    return 0
  fi
  say "unit: $UNIT"
  if [ "$DRY_RUN" = 1 ]; then
    say "  would write $UNIT (0644) with IPAddressAllow=$IP_ALLOW"
    while IFS= read -r line; do
      if [ -n "$line" ]; then say "  and $line"; fi
    done <<<"$(pin_lines)"
  else
    write_unit "$BUNDLE/deploy/$NAME.service" "$UNIT" "$(pin_lines)"
  fi
  # Instances run from the template: keep it as current as the venv they share.
  if [ -e "$TEMPLATE_UNIT" ] && [ -f "$BUNDLE/deploy/$NAME@.service" ]; then place_template; fi
}

# Advisory only: a warning here never fails the install.
check_unit() {
  local target=$UNIT
  command -v systemd-analyze >/dev/null 2>&1 || return 0
  if [ -n "$INSTANCE" ]; then target=$TEMPLATE_UNIT; fi
  say "unit check: systemd-analyze verify"
  run systemd-analyze verify "$target" || warn "systemd-analyze verify reported the problems above"
  if [ "$DRY_RUN" = 0 ]; then
    systemd-analyze security --no-pager "$SERVICE" 2>/dev/null | tail -n 1 || true
  fi
}

do_install() {
  if [ -n "$INSTANCE" ]; then
    say "plan: install $NAME $VERSION into $PREFIX; instance $INSTANCE, config in $CONF_DIR"
  else
    say "plan: install $NAME $VERSION into $PREFIX; config in $ETC_DIR"
  fi
  ensure_service_user
  build_venv
  place_config
  place_unit
  run systemctl daemon-reload
  check_unit
  if [ "$DRY_RUN" = 1 ]; then
    say "dry run complete: nothing was changed"
    return 0
  fi
  if [ -n "$INSTANCE" ]; then
    cat <<EOF

Installed $NAME $VERSION as instance $INSTANCE. The service is not enabled and not started. Next:
  1. sudo $PREFIX/venv/bin/$NAME init --detect --instance $INSTANCE
     (writes $CONF_DIR/config.toml, its secrets and the router pin, on a free port_base)
  2. run this script again with --instance $INSTANCE (the unit allows only config.toml's IPs)
  3. run check-config and selftest with --config $CONF_DIR/config.toml, then
     systemctl enable --now $NAME@$INSTANCE
  4. systemd-analyze security $SERVICE (README.md has the commands)
EOF
    return 0
  fi
  cat <<EOF

Installed $NAME $VERSION. The service is not enabled and not started. Next:
  1. sudo $PREFIX/venv/bin/$NAME init --detect
     (writes config.toml, its secrets and the router pin; check the fingerprint it shows)
  2. run this script again (the unit allows only config.toml's IPs)
  3. run check-config and selftest, then systemctl enable --now $NAME (README.md has the commands)
  4. systemd-analyze security $NAME (the unit is also checked above when systemd-analyze exists)
EOF
}

# --- uninstall -----------------------------------------------------------------

# Only paths this script creates may be deleted; any other argument is a bug.
# An instance run may not delete the single service's unit or config: $ETC, $UNIT, template.
remove_path() {
  case $1 in
    "$VENV" | "$VENV.prev" | "$UNIT.d" | "$CONF" | "$STATE" | "$STATE_PRIVATE") ;;
    "$UNIT" | "$TEMPLATE_UNIT") [ -z "$INSTANCE" ] || die "internal error: refusing to remove $1" ;;
    "$DROPIN" | "$NODE_CA_DROPIN") [ -n "$INSTANCE" ] || die "internal error: refusing to remove $1" ;;
    *) die "internal error: refusing to remove $1" ;;
  esac
  if [ -e "$1" ] || [ -L "$1" ]; then
    run rm -rf -- "$1"
  else
    say "  absent $1"
  fi
}

list_names() { # list_names DIR: file names only, never contents
  local entry
  for entry in "$1"/* "$1"/.[!.]*; do
    if [ -e "$entry" ]; then printf '%s ' "${entry##*/}"; fi
  done
}

confirm_purge() {
  local answer
  say "--purge deletes, permanently:"
  say "  $CONF (holds: $(list_names "$CONF"))"
  say "  $STATE (port pins, counters, login latch) and $STATE_PRIVATE"
  say "Without the port pins a re-install can give LibreNMS devices other SNMP ports."
  if [ "$YES" = 1 ] || [ "$DRY_RUN" = 1 ]; then return 0; fi
  [ -t 0 ] || die "refusing --purge without a terminal: add --yes to confirm"
  printf 'Type "purge" to continue: '
  read -r answer
  [ "$answer" = purge ] || die "aborted: nothing was deleted"
}

unit_running() { # unit_running UNIT
  case $(systemctl is-active "$1" 2>/dev/null || true) in
    active | activating | reloading) return 0 ;;
    *) return 1 ;;
  esac
}

# The single service owns the venv and the config root every instance lives in.
check_no_instance_left() {
  local name first=$NAME
  while IFS= read -r name; do
    [ -n "$name" ] || continue
    first="install.sh --instance $name --uninstall"
    if [ "$PURGE" = 1 ]; then first="$first --purge"; fi
    if [ -e "$ROOT$UNIT_DIR/$NAME@$name.service.d/10-ip-allow.conf" ] ||
      unit_running "$NAME@$name.service"; then
      err "instance $name still uses the venv and $ETC_DIR: run $first first"
    elif [ "$PURGE" = 1 ] && [ -d "$ETC/$name" ]; then
      err "--purge would delete the config of instance $name: run $first first"
    fi
  done <<<"$(instance_names)"
}

do_uninstall() {
  local have_systemctl=0
  command -v systemctl >/dev/null 2>&1 && have_systemctl=1
  if [ -n "$INSTANCE" ]; then
    say "plan: uninstall instance $INSTANCE of $NAME"
  else
    say "plan: uninstall $NAME (prefix $PREFIX)"
  fi
  if [ "$PURGE" = 1 ]; then confirm_purge; fi
  if [ "$have_systemctl" = 1 ]; then
    run systemctl stop "$SERVICE" || warn "systemctl stop failed (not loaded?)"
    run systemctl disable "$SERVICE" || warn "systemctl disable failed (not enabled?)"
  fi
  if [ -n "$INSTANCE" ]; then
    remove_path "$DROPIN"
    if [ -e "$NODE_CA_DROPIN" ]; then remove_path "$NODE_CA_DROPIN"; fi
    if [ "$PURGE" = 0 ]; then run rmdir "$UNIT.d" 2>/dev/null || true; fi
  else
    remove_path "$UNIT"
    if [ -e "$TEMPLATE_UNIT" ]; then remove_path "$TEMPLATE_UNIT"; fi
  fi
  if [ "$have_systemctl" = 1 ]; then
    run systemctl daemon-reload
    run systemctl reset-failed "$SERVICE" || true
  fi
  if [ -z "$INSTANCE" ]; then
    remove_path "$VENV"
    if [ "$DRY_RUN" = 0 ] && [ -d "$APP" ]; then
      rmdir "$APP" 2>/dev/null || say "  kept $APP (not empty)"
    fi
  fi
  if [ "$PURGE" = 1 ]; then
    remove_path "$UNIT.d"
    remove_path "$CONF"
    remove_path "$STATE"
    remove_path "$STATE_PRIVATE"
    if [ -z "$INSTANCE" ] && getent passwd "$NAME" >/dev/null 2>&1; then run userdel "$NAME"; fi
  else
    say "kept $CONF and $STATE (--purge deletes them)"
  fi
}

main() {
  parse_args "$@"
  set_paths
  if [ -n "$ROOT" ]; then say "STAGING: DESTDIR=$ROOT, nothing is installed on this host"; fi
  if [ "$DRY_RUN" = 1 ]; then say "DRY RUN: checks and plan only"; fi
  say "checks"
  check_root
  if [ "$UNINSTALL" = 1 ]; then
    if [ -z "$INSTANCE" ]; then check_no_instance_left; fi
    finish_checks
    do_uninstall
    return 0
  fi
  check_bundle
  check_python
  check_interpreter_location
  check_systemd
  check_service_idle
  check_config
  finish_checks
  do_install
}

main "$@"
