#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "==> Tearing down existing environment..."
make test-environment-down || true

echo "==> Starting test environment..."
make local-test-environment-running

echo "==> Running smoketests..."
cd tests/smoketest
make "$@"
