#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if [ ! -d node_modules ]; then
  echo "Dependencies missing — run ./setup.sh first." >&2
  exit 1
fi

exec node src/index.js "$@"
