#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The store checks of docs/12-testing-and-quality.md ("Database tests"):
#   - the database tests on SQLite, unless STORE_SKIP_SQLITE=1, and on every PostgreSQL given in
#     RPMGR_TEST_PG_URLS (admin DSNs, space-separated): the store's own tests, among them that the
#     embedded migrations apply, that regenerating them from the Ent schema yields nothing new and
#     that the live schema equals the Ent schema, and the tests of every package that uses the
#     store through storetest;
#   - Atlas community lint of both migration directories (check-atlas-lint.sh). PostgreSQL lint
#     needs an empty development database in RPMGR_LINT_PG_DEV.
# With REQUIRE_PG=1 (CI) a missing PostgreSQL is an error, not a skip. Needs Docker for the lint.
#
# Environment, all unset locally and in the nightly run: GO_TEST_CACHE=1 lets go test reuse cached
# results and GO_TEST_SHARD=i/n runs one share of the packages (check-go.sh explains both); shard 1
# also lints the migrations.
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

shard=${GO_TEST_SHARD-}
if ! shard_valid "$shard"; then
  fail "GO_TEST_SHARD must be <i>/<n> with 1 <= i <= n, not '$shard'"
  finish
fi
count=(-count=1)
if [[ ${GO_TEST_CACHE-} == 1 ]]; then
  count=()
fi

# Only packages with tests count, so the shards deal out real work.
all=$(go list -f '{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}} {{join .TestImports " "}} {{join .XTestImports " "}}{{end}}' ./... |
  awk '$1 ~ /\/internal\/store(\/|$)/ { print $1; next }
    { for (i = 2; i <= NF; i++) if ($i ~ /\/internal\/store\/storetest$/) { print $1; next } }')
if [[ -z $all ]]; then
  fail "no database test packages found"
  finish
fi
mapfile -t pkgs < <(sort <<<"$all" | shard_select "$shard")
echo "== database test packages (shard ${shard:-all}): ${pkgs[*]}"
# internal/controller alone runs for 8 to 10 minutes on PostgreSQL on a CI runner, at go test's
# default limit of 10 minutes per package, so a slow run timed out without a failing test (#905,
# #896). The limit is 20 minutes; a test that hangs still fails, only later.
timeout=20m
# CI's go job runs these packages on SQLite already, with the same flags (check-go.sh), so the store
# job sets STORE_SKIP_SQLITE and runs them on PostgreSQL only.
if ((${#pkgs[@]} == 0)); then
  echo "skipped: no database test packages in this shard"
elif [[ ${STORE_SKIP_SQLITE-} == 1 ]]; then
  echo "skipped: store tests on SQLite (STORE_SKIP_SQLITE=1, the go job runs them)"
else
  echo "== store tests, SQLite"
  if ! go test -race "${count[@]}" -timeout "$timeout" "${pkgs[@]}"; then
    fail "store tests failed on SQLite"
  fi
fi
read -r -a pgs <<<"${RPMGR_TEST_PG_URLS-}"
if ((${#pgs[@]} == 0)) && [[ ${REQUIRE_PG-} == 1 ]]; then
  fail "RPMGR_TEST_PG_URLS is empty but PostgreSQL is required"
fi
for pg in "${pgs[@]}"; do
  ((${#pkgs[@]} > 0)) || break
  echo "== store tests, PostgreSQL $pg"
  if ! RPMGR_TEST_PG=$pg RPMGR_TEST_REQUIRE_PG=1 go test -race "${count[@]}" -timeout "$timeout" "${pkgs[@]}"; then
    fail "store tests failed on PostgreSQL ($pg)"
  fi
done

if shard_first "$shard"; then
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
else
  echo "skipped: atlas migrate lint (shard 1 runs it)"
fi
finish
