#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON:-$ROOT/.venv/bin/python}"

if [[ ! -x "$PYTHON_BIN" ]]; then
  echo "Python runtime not found at $PYTHON_BIN" >&2
  echo "Create .venv or set PYTHON=/path/to/python." >&2
  exit 1
fi

cd "$ROOT"

"$PYTHON_BIN" -m pytest -q
"$PYTHON_BIN" tools/parity/audit_parity.py --fetch-current-docs --format markdown --strict >/dev/null
"$PYTHON_BIN" -m limacharlie_mcp.configure --help >/dev/null
"$PYTHON_BIN" -m limacharlie_mcp.auth_doctor --help >/dev/null
"$PYTHON_BIN" -m limacharlie_mcp.vault_bootstrap --help >/dev/null
"$PYTHON_BIN" -m limacharlie_mcp.trajectory_benchmark --help >/dev/null

echo "readiness ok"
