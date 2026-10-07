#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The store checks of docs/12-testing-and-quality.md ("Database tests"):
#   - the database tests on SQLite and on every PostgreSQL given in RPMGR_TEST_PG_URLS (admin DSNs,
#     space-separated): the store's own tests, among them that the embedded migrations apply, that
#     regenerating them from the Ent schema yields nothing new and that the live schema equals the
#     Ent schema, and the tests of every package that uses the store through storetest;
#   - Atlas community lint of both migration directories (check-atlas-lint.sh). PostgreSQL lint
#     needs an empty development database in RPMGR_LINT_PG_DEV.
# With REQUIRE_PG=1 (CI) a missing PostgreSQL is an error, not a skip. Needs Docker for the lint.
#
# Usage: check-store.sh [<repository root>]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

root=${1:-$(repo_root)}
migrations=internal/store/migrations
cd "$root"
if [[ ! -d $migrations ]]; then
  echo "no migrations"
  exit 0
fi

mapfile -t pkgs < <(go list -f '{{.ImportPath}} {{join .TestImports " "}} {{join .XTestImports " "}}' ./... |
  awk '$1 ~ /\/internal\/store(\/|$)/ { print $1; next }
    { for (i = 2; i <= NF; i++) if ($i ~ /\/internal\/store\/storetest$/) { print $1; next } }')
echo "== database test packages: ${pkgs[*]}"
echo "== store tests, SQLite"
if ! go test -race -count=1 "${pkgs[@]}"; then
  fail "store tests failed on SQLite"
fi
read -r -a pgs <<<"${RPMGR_TEST_PG_URLS-}"
if ((${#pgs[@]} == 0)) && [[ ${REQUIRE_PG-} == 1 ]]; then
  fail "RPMGR_TEST_PG_URLS is empty but PostgreSQL is required"
fi
for pg in "${pgs[@]}"; do
  echo "== store tests, PostgreSQL $pg"
  if ! RPMGR_TEST_PG=$pg RPMGR_TEST_REQUIRE_PG=1 go test -race -count=1 "${pkgs[@]}"; then
    fail "store tests failed on PostgreSQL ($pg)"
  fi
done

lint=$(dirname "${BASH_SOURCE[0]}")/check-atlas-lint.sh
echo "== atlas migrate lint, SQLite"
if ! "$lint" "$migrations/sqlite" "sqlite://dev?mode=memory"; then
  fail "atlas migrate lint reported problems in the SQLite migrations"
fi
if [[ -n ${RPMGR_LINT_PG_DEV-} ]]; then
  echo "== atlas migrate lint, PostgreSQL"
  if ! "$lint" "$migrations/postgres" "$RPMGR_LINT_PG_DEV"; then
    fail "atlas migrate lint reported problems in the PostgreSQL migrations"
  fi
elif [[ ${REQUIRE_PG-} == 1 ]]; then
  fail "RPMGR_LINT_PG_DEV is empty but PostgreSQL is required"
else
  echo "skipped: PostgreSQL lint (RPMGR_LINT_PG_DEV not set)"
fi
finish
