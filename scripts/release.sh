#!/usr/bin/env bash
# Cut a release in two steps, both run by the maintainer:
#   scripts/release.sh X.Y.Z        open the release PR (version bump and changelog)
#   scripts/release.sh --tag X.Y.Z  tag the merged release; the tag push runs the workflow

# The release workflow also calls --verify vX.Y.Z and --notes X.Y.Z. It never commits.
# --dry-run runs every check and prints the plan; it changes nothing.
set -euo pipefail

REMOTE=origin
MAIN=main
PACKAGE=aimesh-snmp-proxy
PYPROJECT=pyproject.toml
LOCKFILE=uv.lock
CHANGELOG=CHANGELOG.md
NUM='(0|[1-9][0-9]*)'
VERSION_RE="^$NUM\\.$NUM\\.$NUM\$"
CURRENT_RE="^$NUM\\.$NUM\\.$NUM(\\.dev[0-9]+)?\$"
TAG_RE="^v$NUM\\.$NUM\\.$NUM\$"
DATE_RE='^[0-9]{4}-[0-9]{2}-[0-9]{2}$'
DRY_RUN=0
WORK=

usage() {
  cat <<'EOF'
usage: scripts/release.sh [--dry-run] X.Y.Z        open the release PR
       scripts/release.sh [--dry-run] --tag X.Y.Z  tag the merged release and push the tag
       scripts/release.sh --verify vX.Y.Z          check a tag (the release workflow runs this)
       scripts/release.sh --notes X.Y.Z            print the changelog notes of one version

--dry-run runs every check, prints the plan, and changes nothing.
The release commit and the tag use this repository's own user.name and user.email.
The GitHub CLI reads its login, or GH_TOKEN and GH_HOST, as usual.
EOF
}

usage_error() {
  usage >&2
  exit 2
}

say() { printf '%s\n' "$*"; }

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  case ${WORK##*/} in
    release.*) [ -d "$WORK" ] && rm -rf -- "$WORK" ;;
  esac
  return 0
}
trap cleanup EXIT

check_version() { # check_version X.Y.Z
  [[ $1 =~ $VERSION_RE ]] || die "'$1' is not a version like 1.2.3"
}

ident_email() { # ident_email author|committer: the email git would record
  local ident var
  var=GIT_$(printf '%s' "$1" | tr '[:lower:]' '[:upper:]')_IDENT
  ident=$(git var "$var" 2>/dev/null) || return 0
  ident=${ident#*<}
  printf '%s' "${ident%%>*}"
}

# The release commit and the tag must carry this repository's own identity, not a global one.
# Git takes the author and the committer from config and environment alike, so check both.
check_identity() {
  local own role email
  own=$(git config --local user.email 2>/dev/null || true)
  [ -n "$own" ] ||
    die "this repository has no user.email of its own: run git config user.email you@example.com"
  for role in author committer; do
    email=$(ident_email "$role")
    [ "$email" = "$own" ] ||
      die "git $role email is '${email:-unset}', but this repository's user.email is $own"
  done
}

version_newer() { # version_newer NEW OLD: NEW is X.Y.Z, OLD is X.Y.Z or X.Y.Z.devN
  awk -v new="$1" -v old="$2" 'BEGIN {
    split(new, a, ".")
    split(old, b, ".")
    for (i = 1; i <= 3; i++) {
      if (a[i] + 0 > b[i] + 0) exit 0
      if (a[i] + 0 < b[i] + 0) exit 1
    }
    # The same numbers: a release is newer than its own .devN, and equal to itself.
    exit (b[4] != "" ? 0 : 1)
  }'
}

# --- file edits: each reads stdin and writes stdout, so the caller decides where it lands

project_version() { # the version in the [project] table
  awk '
    /^\[/ { in_project = ($0 ~ /^\[project\][[:space:]]*$/); next }
    in_project && /^version[[:space:]]*=/ && match($0, /"[^"]*"/) {
      print substr($0, RSTART + 1, RLENGTH - 2)
      exit
    }'
}

bump_pyproject() { # bump_pyproject VERSION
  awk -v new="$1" '
    /^\[/ { in_project = ($0 ~ /^\[project\][[:space:]]*$/) }
    in_project && !done && /^version[[:space:]]*=/ {
      print "version = \"" new "\""
      done = 1
      next
    }
    { print }
    END { if (!done) exit 3 }'
}

bump_lock() { # bump_lock PACKAGE VERSION: only that package entry changes
  awk -v pkg="$1" -v new="$2" '
    /^\[/ { mine = 0 }
    /^name = / { mine = ($0 == "name = \"" pkg "\"") }
    mine && !done && /^version = / {
      print "version = \"" new "\""
      done = 1
      next
    }
    { print }
    END { if (!done) exit 3 }'
}

unreleased_has_content() { # exit 0: has notes, 1: empty, 2: no Unreleased heading
  awk '
    /^## / {
      if (in_section) exit
      in_section = ($0 ~ /^## \[?Unreleased\]?[[:space:]]*$/)
      found = found || in_section
      next
    }
    in_section && $0 !~ /^[[:space:]]*$/ && $0 !~ /^#/ && $0 !~ /^\[.+\]:/ { content = 1 }
    END {
      if (!found) exit 2
      exit (content ? 0 : 1)
    }'
}

rotate_changelog() { # rotate_changelog VERSION DATE
  awk -v ver="$1" -v date="$2" '
    !done && /^## \[?Unreleased\]?[[:space:]]*$/ {
      print "## [Unreleased]"
      print ""
      print "## [" ver "] - " date
      done = 1
      next
    }
    { print }
    END { if (!done) exit 3 }'
}

# The first release has no compare link to move: those lines pass through unchanged.
update_links() { # update_links VERSION
  awk -v ver="$1" '
    /^\[Unreleased\]:[[:space:]]/ && match($0, /\/compare\/v[0-9][0-9.]*\.\.\.[^ \t]+$/) {
      base = substr($0, 1, RSTART - 1)
      sub(/^\[Unreleased\]:[[:space:]]*/, "", base)
      prev = substr($0, RSTART + 9)
      sub(/\.\.\..*$/, "", prev)
      print "[Unreleased]: " base "/compare/v" ver "...HEAD"
      print "[" ver "]: " base "/compare/" prev "...v" ver
      next
    }
    { print }'
}

roll_changelog() { # roll_changelog VERSION DATE: date the Unreleased section, move the links
  rotate_changelog "$1" "$2" | update_links "$1"
}

# Accepts "## [1.2.3] - date", "## 1.2.3 - date" and "## v1.2.3"; exits 4 on an empty section.
changelog_notes() { # changelog_notes VERSION
  awk -v ver="$1" '
    /^## / {
      if (found) exit
      head = $0
      sub(/^## \[?v?/, "", head)
      if (index(head, ver) == 1) {
        rest = substr(head, length(ver) + 1)
        lead = substr(rest, 1, 1)
        if (lead == "" || lead == "]" || lead == " ") found = 1
      }
      next
    }
    found && $0 !~ /^\[.+\]:[[:space:]]/ { line[++n] = $0 }
    END {
      first = 1
      while (first <= n && line[first] ~ /^[[:space:]]*$/) first++
      last = n
      while (last >= first && line[last] ~ /^[[:space:]]*$/) last--
      for (i = first; i <= last; i++) print line[i]
      if (last < first) exit 4
    }'
}

# Render FILE as it is on the remote main, through FILTER, into $WORK. Nothing else changes.
render() { # render FILE FILTER [ARGS...]
  local file=$1
  shift
  git show "$REMOTE/$MAIN:$file" | "$@" >"$WORK/$file" || die "cannot update $file with $1"
}

# --- repository facts

repo_slug() { # HOST/OWNER/REPO of the remote; GH_REPO wins
  local url host path
  if [ -n "${GH_REPO:-}" ]; then
    case $GH_REPO in
      */*/*) printf '%s\n' "$GH_REPO" ;;
      *) printf 'github.com/%s\n' "$GH_REPO" ;;
    esac
    return
  fi
  url=$(git config --get "remote.$REMOTE.url") || die "no remote named $REMOTE"
  case $url in
    *://*)
      url=${url#*://}
      case ${url%%/*} in *@*) url=${url#*@} ;; esac
      host=${url%%/*}
      host=${host%%:*}
      path=${url#*/}
      ;;
    *@*:*)
      host=${url#*@}
      host=${host%%:*}
      path=${url#*:}
      ;;
    *) die "cannot read the host and repository from the $REMOTE URL '$url'" ;;
  esac
  printf '%s/%s\n' "$host" "${path%.git}"
}

tag_exists() { # tag_exists TAG: locally or on the remote
  local listed
  git rev-parse --quiet --verify "refs/tags/$1" >/dev/null && return 0
  listed=$(git ls-remote --tags "$REMOTE" "refs/tags/$1") || die "cannot reach $REMOTE"
  [ -n "$listed" ]
}

branch_exists() { # branch_exists BRANCH: locally or on the remote
  local listed
  git rev-parse --quiet --verify "refs/heads/$1" >/dev/null && return 0
  listed=$(git ls-remote --heads "$REMOTE" "refs/heads/$1") || die "cannot reach $REMOTE"
  [ -n "$listed" ]
}

fetch_main() {
  git fetch --quiet "$REMOTE" "+refs/heads/$MAIN:refs/remotes/$REMOTE/$MAIN" ||
    die "cannot fetch $MAIN from $REMOTE"
}

# Fail closed: no check runs, a pending one, or an API error all count as not green.
ci_green() { # ci_green SHA
  local slug host repo counts
  slug=$(repo_slug)
  host=${slug%%/*}
  repo=${slug#*/}
  counts=$(gh api --hostname "$host" "repos/$repo/commits/$1/check-runs?per_page=100" --jq \
    '[.total_count, ([.check_runs[] | select(.conclusion != "success" and .conclusion != "skipped" and .conclusion != "neutral")] | length)] | @tsv') ||
    return 1
  [ "${counts%%$'\t'*}" -gt 0 ] && [ "${counts##*$'\t'}" -eq 0 ]
}

prettify() { # prettify ROOT FILE: run markdownlint and prettier when they are installed
  local root=$1 file=$2 lint=() fmt=()
  [ -f "$root/.markdownlint.json" ] && lint=(--config "$root/.markdownlint.json")
  [ -f "$root/.prettierrc" ] && fmt=(--config "$root/.prettierrc")
  if command -v markdownlint >/dev/null 2>&1; then
    markdownlint ${lint[@]+"${lint[@]}"} --fix "$file" >/dev/null 2>&1 || true
  fi
  if command -v prettier >/dev/null 2>&1; then
    prettier ${fmt[@]+"${fmt[@]}"} --parser markdown --write "$file" >/dev/null 2>&1 || true
  fi
}

# --- the four commands

prepare_release() { # prepare_release VERSION
  local ver=$1 branch=release/v$1 base current today ident body url file
  check_version "$ver"
  check_identity
  command -v gh >/dev/null 2>&1 || die "the GitHub CLI (gh) is required to open the pull request"
  [ -z "$(git status --porcelain)" ] ||
    die "the working tree is not clean: commit, stash or remove the changes first"
  fetch_main
  for file in "$PYPROJECT" "$LOCKFILE" "$CHANGELOG"; do
    git cat-file -e "$REMOTE/$MAIN:$file" 2>/dev/null || die "$file is missing on $REMOTE/$MAIN"
  done
  base=$(git rev-parse "$REMOTE/$MAIN")
  current=$(git show "$REMOTE/$MAIN:$PYPROJECT" | project_version)
  [[ $current =~ $CURRENT_RE ]] ||
    die "the version '$current' in $PYPROJECT is not like 1.2.3 or 1.2.3.dev0"
  version_newer "$ver" "$current" || die "$ver is not newer than the current version $current"
  tag_exists "v$ver" && die "tag v$ver already exists"
  branch_exists "$branch" && die "branch $branch already exists"
  if git show "$REMOTE/$MAIN:$CHANGELOG" | unreleased_has_content; then
    :
  else
    case $? in
      2) die "$CHANGELOG has no Unreleased section" ;;
      *) die "the Unreleased section of $CHANGELOG is empty" ;;
    esac
  fi
  today=${RELEASE_DATE:-$(date +%Y-%m-%d)}
  [[ $today =~ $DATE_RE ]] || die "'$today' is not a date like 2026-11-20"

  # Render every new file from the fresh main first: a bad file stops us before any change.
  WORK=$(mktemp -d "${TMPDIR:-/tmp}/release.XXXXXX")
  render "$PYPROJECT" bump_pyproject "$ver"
  render "$LOCKFILE" bump_lock "$PACKAGE" "$ver"
  render "$CHANGELOG" roll_changelog "$ver" "$today"

  ident=$(git var GIT_AUTHOR_IDENT)
  if [ "$DRY_RUN" = 1 ]; then
    say "dry run: nothing is changed. The release would:"
    say "  branch $branch from $REMOTE/$MAIN (${base:0:12})"
    say "  set the version $current -> $ver in $PYPROJECT and $LOCKFILE"
    say "  date the changelog: ## [$ver] - $today, under a fresh ## [Unreleased]"
    say "  commit 'chore(release): v$ver' as ${ident%> *}> and push the branch"
    say "  open a pull request against $MAIN with these release notes:"
    say ""
    changelog_notes "$ver" <"$WORK/$CHANGELOG"
    return 0
  fi

  git checkout --quiet -b "$branch" --no-track "$REMOTE/$MAIN"
  for file in "$PYPROJECT" "$LOCKFILE" "$CHANGELOG"; do
    cat "$WORK/$file" >"$file"
  done
  git add -- "$PYPROJECT" "$LOCKFILE" "$CHANGELOG"
  git commit --no-gpg-sign --quiet -m "chore(release): v$ver"
  git push --quiet --set-upstream "$REMOTE" "$branch"

  body=$WORK/pr-body.md
  {
    printf 'Release v%s: bumps the version and dates the changelog.\n\n' "$ver"
    printf '## Release notes\n\n'
    changelog_notes "$ver" <"$CHANGELOG"
    printf '\n## After the merge\n\n'
    printf 'Run %s. The tag push runs the release workflow.\n' "\`scripts/release.sh --tag $ver\`"
  } >"$body"
  prettify "$(pwd)" "$body"
  url=$(gh pr create --repo "$(repo_slug)" --base "$MAIN" --head "$branch" \
    --title "chore(release): v$ver" --body-file "$body") ||
    die "gh could not open the pull request; the branch $branch is pushed"
  say "$url"
  say "Merge it by rebase, wait for CI on $MAIN, then run: scripts/release.sh --tag $ver"
}

tag_release() { # tag_release VERSION
  local ver=$1 tag=v$1 sha found
  check_version "$ver"
  check_identity
  command -v gh >/dev/null 2>&1 || die "the GitHub CLI (gh) is required to read the CI status"
  tag_exists "$tag" && die "tag $tag already exists"
  fetch_main
  # A rebase merge keeps the subject; a squash merge appends " (#N)".
  sha=$(git log "$REMOTE/$MAIN" --format='%H%x09%s' |
    awk -F'\t' -v subject="chore(release): $tag" '
      !seen && ($2 == subject || index($2, subject " (#") == 1) { print $1; seen = 1 }')
  [ -n "$sha" ] ||
    die "$REMOTE/$MAIN has no commit 'chore(release): $tag'; merge the release PR first"
  found=$(git show "$sha:$PYPROJECT" | project_version)
  [ "$found" = "$ver" ] || die "$PYPROJECT at ${sha:0:12} says version $found, not $ver"
  git show "$sha:$CHANGELOG" | changelog_notes "$ver" >/dev/null ||
    die "$CHANGELOG has no notes for $ver"
  ci_green "$sha" || die "CI is not green on ${sha:0:12}; wait for the checks on $REMOTE/$MAIN"
  if [ "$DRY_RUN" = 1 ]; then
    say "dry run: nothing is changed. The release would:"
    say "  tag $tag (annotated, 'Release $tag') at ${sha:0:12} on $REMOTE/$MAIN"
    say "  push the tag, which runs the release workflow"
    return 0
  fi
  git tag --no-sign -a "$tag" -m "Release $tag" "$sha"
  git push --quiet "$REMOTE" "refs/tags/$tag"
  say "Pushed $tag at ${sha:0:12}. Watch the release workflow: gh run list --workflow release.yml"
}

verify_tag() { # verify_tag vX.Y.Z: what the release workflow checks before it builds
  local tag=$1 ver commit found
  [[ $tag =~ $TAG_RE ]] || die "'$tag' is not a tag like v1.2.3"
  ver=${tag#v}
  [ "$(git cat-file -t "refs/tags/$tag" 2>/dev/null)" = tag ] ||
    die "$tag is not an annotated tag"
  commit=$(git rev-parse "$tag^{commit}")
  [ "$commit" = "$(git rev-parse HEAD)" ] || die "HEAD is not the commit of $tag"
  found=$(project_version <"$PYPROJECT")
  [ "$found" = "$ver" ] || die "$PYPROJECT says version $found, not $ver"
  changelog_notes "$ver" <"$CHANGELOG" >/dev/null || die "$CHANGELOG has no notes for $ver"
  git merge-base --is-ancestor "$commit" "refs/remotes/$REMOTE/$MAIN" ||
    die "$tag ($commit) is not on $REMOTE/$MAIN"
  say "ok: $tag matches $PYPROJECT, $CHANGELOG and $REMOTE/$MAIN"
}

print_notes() { # print_notes X.Y.Z
  check_version "$1"
  changelog_notes "$1" <"$CHANGELOG" || die "$CHANGELOG has no notes for $1"
}

main() {
  local root arg
  local -a args=()
  for arg in "$@"; do
    if [ "$arg" = --dry-run ]; then DRY_RUN=1; else args+=("$arg"); fi
  done
  set -- ${args[@]+"${args[@]}"}
  case ${1:-} in
    -h | --help)
      usage
      exit 0
      ;;
    --verify | --notes) { [ $# -eq 2 ] && [ "$DRY_RUN" = 0 ]; } || usage_error ;;
    --tag) [ $# -eq 2 ] || usage_error ;;
    '' | -*) usage_error ;;
    *) [ $# -eq 1 ] || usage_error ;;
  esac
  root=$(git rev-parse --show-toplevel 2>/dev/null) || die "not inside a git repository"
  cd "$root"
  case $1 in
    --tag) tag_release "$2" ;;
    --verify) verify_tag "$2" ;;
    --notes) print_notes "$2" ;;
    *) prepare_release "$1" ;;
  esac
}

# A test sources this file to call single functions: only a direct run starts main.
if [ "${BASH_SOURCE[0]:-$0}" = "$0" ]; then main "$@"; fi
