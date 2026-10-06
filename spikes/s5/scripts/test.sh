#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Runs the S5 tests on SQLite and PostgreSQL and writes the log to results/.
#
# Usage: test.sh <postgres-port> [<postgres-major>]   (container from README.md, user/password s5)
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
port=${1:?postgres port}
major=${2:-18}
export RPMGR_S5_PG="postgres://s5:s5@127.0.0.1:$port/postgres?sslmode=disable"
export RPMGR_S5_REQUIRE_PG=1
race=()
if command -v gcc >/dev/null; then race=(-race); fi
mkdir -p "$here/results"
out="$here/results/test-sqlite-postgres$major.txt"
{
  echo "# go test ${race[*]} -count=1 -v ./...   ($(go version); PostgreSQL $major)"
  CGO_ENABLED=$([[ ${#race[@]} -gt 0 ]] && echo 1 || echo 0) go -C "$here" test "${race[@]}" -count=1 -v ./... 2>&1
} | tee "$out" | grep -E '^(=== RUN|--- FAIL|FAIL|ok|PASS|panic)' | grep -v '=== RUN' || true
grep -q '^FAIL' "$out" && exit 1 || exit 0
