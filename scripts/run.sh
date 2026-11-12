#!/usr/bin/env bash
# Start the Speakeasy MCP server on stdio, installing it into ./.venv on first use.
#   scripts/run.sh           run the server (point your MCP client at this)
#   scripts/run.sh --setup   only install
# stdout belongs to the MCP protocol, so everything else goes to stderr.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="${SPEAKEASY_MCP_VENV:-$ROOT/.venv}"
(
  flock -w 600 9
  if ! "$VENV/bin/python" -I -c "import speakeasy, speakeasy_mcp, mcp" 2>/dev/null; then
    echo "[speakeasy-mcp] installing into $VENV" >&2
    python3 -m venv "$VENV"
    "$VENV/bin/pip" install -q --disable-pip-version-check -e "$ROOT" >&2
  fi
) 9>"${TMPDIR:-/tmp}/speakeasy-mcp-install.lock"
[[ "${1:-}" == "--setup" ]] && exit 0
exec "$VENV/bin/python" -I -m speakeasy_mcp "$@"
