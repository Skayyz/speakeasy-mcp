#!/usr/bin/env bash
# Entry point for Claude Code sessions opened on this repository.
#   scripts/claude-mcp.sh           start the server (registered in .mcp.json as "speakeasy")
#   scripts/claude-mcp.sh --setup   only install into ./.venv; always exits 0 (SessionStart hook)
# Inputs and outputs are confined to ./samples. stdout is the MCP protocol: log to stderr only.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export SPEAKEASY_MCP_ALLOWED_ROOTS="${SPEAKEASY_MCP_ALLOWED_ROOTS:-$ROOT/samples}"
export SPEAKEASY_MCP_DATA="${SPEAKEASY_MCP_DATA:-$ROOT/samples/.speakeasy-mcp}"
mkdir -p "$SPEAKEASY_MCP_DATA" || echo "[speakeasy-mcp] could not create $SPEAKEASY_MCP_DATA" >&2

if [[ "${1:-}" == "--setup" ]]; then
  bash "$ROOT/scripts/run.sh" --setup >&2 || echo "[speakeasy-mcp] install failed (exit $?)" >&2
  exit 0
fi
exec bash "$ROOT/scripts/run.sh" "$@"
