#!/usr/bin/env bash
# Generate config.toml and its secret files for one ASUS router: a thin wrapper
# around `aimesh-snmp-proxy init`, which takes the same flags (--help lists them).
set -euo pipefail

INSTALLED=/opt/aimesh-snmp-proxy/venv/bin/aimesh-snmp-proxy # install.sh's default prefix

# The CLI to run: $AIMESH_SNMP_PROXY, the installed venv, PATH, then this checkout.
if [ -n "${AIMESH_SNMP_PROXY:-}" ]; then
  exec "$AIMESH_SNMP_PROXY" init "$@"
elif [ -x "$INSTALLED" ]; then
  exec "$INSTALLED" init "$@"
elif command -v aimesh-snmp-proxy >/dev/null 2>&1; then
  exec aimesh-snmp-proxy init "$@"
fi
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
if [ -f "$root/pyproject.toml" ] && command -v uv >/dev/null 2>&1; then
  exec uv run --frozen --quiet --project "$root" aimesh-snmp-proxy init "$@"
fi
printf 'error: %s\n' "aimesh-snmp-proxy not found: run deploy/install.sh first, or set AIMESH_SNMP_PROXY to the CLI" >&2
exit 127
