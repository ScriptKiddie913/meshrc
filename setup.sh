#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if ! command -v node >/dev/null 2>&1; then
  echo "node is required (>=22.13). Install it and re-run ./setup.sh" >&2
  exit 1
fi

NODE_VER=$(node -e 'const [maj,min]=process.versions.node.split(".").map(Number); console.log(maj>22||(maj===22&&min>=13)?"ok":"old")')
if [ "$NODE_VER" != "ok" ]; then
  echo "node >=22.13.0 is required (found $(node -v)). This client uses the built-in" >&2
  echo "node:sqlite module so there's no native build step — just upgrade node:" >&2
  echo "  nvm install --lts && nvm use --lts" >&2
  exit 1
fi

if [ ! -d node_modules ]; then
  echo "Installing dependencies..."
  npm install --no-fund --no-audit
fi

node --no-warnings src/setup.js "$@"
