#!/usr/bin/env bash
# Build dist/aimesh-snmp-proxy-<version>.tar.gz: everything deploy/install.sh needs.
# Needs uv, git and network access (PyPI, GitHub). It bundles the committed HEAD, so
# uncommitted changes are left out. Run it on the dev machine, never on the host.
set -euo pipefail
umask 022
# The index pinned in pyproject.toml decides, as in the Makefile.
unset UV_INDEX_URL UV_DEFAULT_INDEX

NAME=aimesh-snmp-proxy
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
OUT_DIR=$ROOT/dist
WORK=

usage() {
  cat <<EOF
Usage: build-bundle.sh [--out-dir DIR]

Write $NAME-<version>.tar.gz and its .sha256 into DIR (default: dist/). The archive holds
our wheel, a wheel of every git-pinned dependency, a hash-pinned requirements.txt,
deploy/, config.example.toml, README.md and SHA256SUMS. Copy it to the host, verify the
.sha256, unpack it as root, and run deploy/install.sh.
EOF
}

say() { printf '%s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  case ${WORK##*/} in
    aimesh-bundle.*) [ -d "$WORK" ] && rm -rf -- "$WORK" ;;
  esac
  return 0
}
trap cleanup EXIT

sha256_of() { # sha256_of FILE: hex digest only
  local out
  if command -v sha256sum >/dev/null 2>&1; then out=$(sha256sum "$1"); else out=$(shasum -a 256 "$1"); fi
  printf '%s' "${out%% *}"
}

stamp_of() { # stamp_of EPOCH: UTC time for touch -t (BSD date, then GNU date)
  date -u -r "$1" +%Y%m%d%H%M.%S 2>/dev/null || date -u -d "@$1" +%Y%m%d%H%M.%S
}

parse_args() {
  while [ $# -gt 0 ]; do
    case $1 in
      --out-dir)
        [ $# -ge 2 ] || die "--out-dir needs a value"
        OUT_DIR=$2
        shift 2
        ;;
      -h | --help)
        usage
        exit 0
        ;;
      *) die "unknown option: $1 (try --help)" ;;
    esac
  done
}

check_tools() {
  local tool
  for tool in uv git tar gzip awk find touch; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
  done
  git -C "$ROOT" rev-parse --verify --quiet HEAD >/dev/null || die "$ROOT has no commit to bundle"
  if [ -n "$(git -C "$ROOT" status --porcelain --untracked-files=no)" ]; then
    warn "uncommitted changes are NOT in the bundle: it holds the commit $(git -C "$ROOT" rev-parse --short HEAD)"
  fi
}

# uv writes build progress to stdout; keep our own stdout for the summary.
build_wheel() { # build_wheel SOURCE_DIR OUT_DIR EPOCH: one pure-Python wheel
  local count=0 wheel
  SOURCE_DATE_EPOCH=$3 uv build --quiet --wheel --out-dir "$2" "$1" >&2 ||
    die "uv build failed for $1"
  for wheel in "$2"/*.whl; do
    [ -f "$wheel" ] && count=$((count + 1))
  done
  [ "$count" = 1 ] || die "expected one wheel from $1, found $count"
  for wheel in "$2"/*.whl; do
    case $wheel in
      *-py3-none-any.whl) ;;
      *) die "${wheel##*/} is not a pure-Python wheel: it would not match the host" ;;
    esac
    WHEEL=$wheel
  done
}

# A git requirement has no index hash: build its wheel from the pinned commit and
# let requirements.txt pin that wheel's SHA-256 instead.
build_git_dependency() { # build_git_dependency NAME URL SHA
  local dir=$WORK/git-$1 epoch
  mkdir -p "$dir"
  git -C "$dir" init --quiet
  GIT_TERMINAL_PROMPT=0 git -C "$dir" fetch --quiet --depth 1 "$2" "$3" ||
    die "cannot fetch $1 commit $3 from $2"
  git -C "$dir" checkout --quiet FETCH_HEAD
  [ "$(git -C "$dir" rev-parse HEAD)" = "$3" ] || die "$1: fetched a different commit than $3"
  epoch=$(git -C "$dir" log -1 --format=%ct HEAD)
  build_wheel "$dir" "$WORK/wheels-$1" "$epoch"
}

# Every entry must be NAME==VERSION (or a ./wheels path) with sha256 hashes, and
# nothing may point at an index, a URL or a VCS: pip --require-hashes enforces the rest.
check_hashed() { # check_hashed FILE
  local bad
  bad=$(awk '
    /^[[:space:]]*(#|$)/ { next }
    { line = line " " $0 }
    /\\[[:space:]]*$/ { sub(/\\[[:space:]]*$/, "", line); next }
    { check(line); line = "" }
    function check(l,    hashes, rest) {
      gsub(/[[:space:]]+/, " ", l)
      sub(/^ /, "", l)
      hashes = 0
      rest = l
      while (match(rest, /--hash=sha256:[0-9a-f]+/)) {
        if (RLENGTH == 14 + 64) hashes++
        rest = substr(rest, RSTART + RLENGTH)
      }
      if (l !~ /^([A-Za-z0-9][A-Za-z0-9._-]*==[^ ;@]+|\.\/wheels\/[A-Za-z0-9._+-]+\.whl)( ;[^@]*)?( --hash=sha256:[0-9a-f]+)+$/ \
          || l ~ /@|git\+|https?:|--index|--find-links|--extra-index|--trusted-host|-e / || hashes == 0)
        print l
    }' "$1")
  [ -z "$bad" ] || die "requirements.txt has entries without a pinned version and hash: $(printf '%s' "$bad" | cut -c1-120)"
}

split_lock() { # split_lock RAW KEPT URLS: URL entries go to URLS, the rest to KEPT
  awk -v urls="$3" '
    skip { skip = ($0 ~ /\\[[:space:]]*$/); next }
    /^[A-Za-z0-9][A-Za-z0-9._-]* @ / {
      print > urls
      skip = ($0 ~ /\\[[:space:]]*$/)
      next
    }
    { print }' "$1" >"$2"
  : >>"$3"
}

entry() { # entry WHEEL: the requirements.txt lines that pin one wheel by path and hash
  printf './wheels/%s \\\n    --hash=sha256:%s\n' "${1##*/}" "$(sha256_of "$1")"
}

main() {
  local epoch commit stamp raw kept urls line dep_name dep_rest dep_url dep_sha version stage base
  local -a wheels=()
  parse_args "$@"
  check_tools
  WORK=$(mktemp -d "${TMPDIR:-/tmp}/aimesh-bundle.XXXXXX")
  commit=$(git -C "$ROOT" rev-parse HEAD)
  epoch=$(git -C "$ROOT" log -1 --format=%ct HEAD)

  say "export: commit ${commit:0:12}"
  mkdir -p "$WORK/src"
  git -C "$ROOT" archive --format=tar HEAD | tar -x -C "$WORK/src"

  say "wheel: $NAME"
  build_wheel "$WORK/src" "$WORK/wheels-self" "$epoch"
  wheels+=("$WHEEL")
  base=${WHEEL##*/}
  version=${base#*-}
  version=${version%%-*}

  say "lock: uv export --frozen"
  raw=$WORK/requirements.raw
  kept=$WORK/requirements.kept
  urls=$WORK/requirements.urls
  # uv also echoes the lock to stdout when given -o.
  (cd "$WORK/src" && uv export --frozen --format requirements-txt --no-emit-project \
    --no-dev --no-annotate --no-header -o "$raw" >/dev/null) || die "uv export failed"
  split_lock "$raw" "$kept" "$urls"
  while IFS= read -r line; do
    dep_name=${line%% @ *}
    dep_rest=${line#* @ }
    if [[ $dep_rest =~ ^git\+(.+)@([0-9a-f]{40})$ ]]; then
      dep_url=${BASH_REMATCH[1]}
      dep_sha=${BASH_REMATCH[2]}
      case $dep_url in *://*@*) die "$dep_name: the lock holds a URL with credentials; remove them" ;; esac
    else
      die "cannot bundle '$dep_name @ ...': only git+URL@<40-hex commit> sources are supported"
    fi
    say "wheel: $dep_name from $dep_url at ${dep_sha:0:12} (git source: pinned by wheel hash)"
    build_git_dependency "$dep_name" "$dep_url" "$dep_sha"
    wheels+=("$WHEEL")
  done <"$urls"

  stage=$WORK/stage/$NAME-$version
  mkdir -p "$stage/wheels" "$stage/deploy"
  for WHEEL in "${wheels[@]}"; do cp "$WHEEL" "$stage/wheels/"; done
  {
    printf '# Hash-pinned install list for deploy/install.sh (pip --require-hashes, no deps).\n'
    printf '# Commit %s. Third-party entries come from uv.lock; the wheels below are built here.\n' "$commit"
    cat "$kept"
    for WHEEL in "${wheels[@]}"; do entry "$stage/wheels/${WHEEL##*/}"; done
  } >"$stage/requirements.txt"
  check_hashed "$stage/requirements.txt"

  cp "$WORK"/src/deploy/* "$stage/deploy/"
  cp "$WORK/src/config.example.toml" "$stage/"
  if [ -f "$WORK/src/README.md" ]; then cp "$WORK/src/README.md" "$stage/"; fi
  find "$stage" -type d -exec chmod 0755 {} +
  find "$stage" -type f -exec chmod 0644 {} +
  chmod 0755 "$stage"/deploy/*.sh
  (cd "$stage" && find . -type f | LC_ALL=C sort | sed 's|^\./||') >"$WORK/files.txt"
  : >"$WORK/SHA256SUMS"
  while IFS= read -r line; do
    printf '%s  %s\n' "$(sha256_of "$stage/$line")" "$line" >>"$WORK/SHA256SUMS"
  done <"$WORK/files.txt"
  mv "$WORK/SHA256SUMS" "$stage/SHA256SUMS"
  chmod 0644 "$stage/SHA256SUMS"

  stamp=$(stamp_of "$epoch")
  TZ=UTC find "$stage" -exec touch -h -t "$stamp" {} +
  make_archive "$WORK/stage" "$NAME-$version"
  say "bundle: $OUT_DIR/$NAME-$version.tar.gz"
  say "sha256: $(sha256_of "$OUT_DIR/$NAME-$version.tar.gz")"
  say "note: ${wheels[*]##*/}"
  say "note: these wheels come from no index; requirements.txt pins their SHA-256 by path"
}

make_archive() { # make_archive STAGE_PARENT DIRNAME: reproducible, root-owned
  local parent=$1 dir=$2 file=$2.tar.gz list
  local -a owner
  list=$WORK/files.list
  mkdir -p "$OUT_DIR"
  (cd "$parent" && find "$dir" | LC_ALL=C sort >"$list")
  # Owner and group root:0 by name and id; GNU tar takes NAME:ID, bsdtar sets each apart.
  if tar --version 2>/dev/null | grep -q 'GNU tar'; then
    owner=(--owner=root:0 --group=root:0)
  else
    owner=(--uid 0 --gid 0 --uname root --gname root)
  fi
  # Root-owned entries: unpacking as root must not hand the installer to another uid.
  (cd "$parent" && COPYFILE_DISABLE=1 tar -cf - --no-recursion "${owner[@]}" -T "$list") |
    gzip -n -9 >"$OUT_DIR/.$file.tmp"
  mv -f "$OUT_DIR/.$file.tmp" "$OUT_DIR/$file"
  (cd "$OUT_DIR" && printf '%s  %s\n' "$(sha256_of "$file")" "$file" >"$file.sha256")
}

main "$@"
