#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Builds the Atlas CLI community edition (Apache-2.0) from the v1.3.0 source and records which of
# the commands rpmgr would need work there. Writes results/atlas-community-cli.txt.
#
# Usage: atlas-community.sh <atlas source dir> <postgres-port>
#   <atlas source dir>: the extracted https://codeload.github.com/ariga/atlas/tar.gz/refs/tags/v1.3.0
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
src=${1:?atlas source dir}
port=${2:?postgres port}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
out="$here/results/atlas-community-cli.txt"
mkdir -p "$here/results"

# The CLI's SQLite driver is mattn/go-sqlite3, which needs cgo. The CLI is a development tool and
# never ships in rpmgr.
CGO_ENABLED=1 go -C "$src/cmd/atlas" build -trimpath -o "$work/atlas" . 2>/dev/null || {
  echo "build failed"
  exit 1
}
for d in sqlite postgres; do cp -r "$here/migrations/$d" "$work/$d"; done
docker exec rpmgr-s5-pg18 psql -U s5 -qtAc "DROP DATABASE IF EXISTS s5cli" >/dev/null
docker exec rpmgr-s5-pg18 psql -U s5 -qtAc "DROP DATABASE IF EXISTS s5clidev" >/dev/null
docker exec rpmgr-s5-pg18 psql -U s5 -qtAc "CREATE DATABASE s5cli" >/dev/null
docker exec rpmgr-s5-pg18 psql -U s5 -qtAc "CREATE DATABASE s5clidev" >/dev/null
pg="postgres://s5:s5@127.0.0.1:$port"

run() {
  echo "\$ atlas $*"
  (cd "$here" && "$work/atlas" "$@") 2>&1 | sed 's/^/  /'
  echo "  → exit ${PIPESTATUS[0]}"
  echo
}

{
  echo "# Atlas CLI community edition, built from ariga/atlas v1.3.0 cmd/atlas ($(go version))"
  echo
  run version
  echo "## Generate a migration from the Ent schema (ent://)"
  run migrate diff probe --dir "file://$work/sqlite" --to "ent://ent/schema" --dev-url "sqlite://dev?mode=memory"
  echo "## Re-hash the directories generated through Ent's Go API (must leave atlas.sum unchanged)"
  run migrate hash --dir "file://$work/sqlite"
  run migrate hash --dir "file://$work/postgres"
  echo "atlas.sum unchanged (sqlite):   $(cmp -s "$work/sqlite/atlas.sum" "$here/migrations/sqlite/atlas.sum" && echo yes || echo NO)"
  echo "atlas.sum unchanged (postgres): $(cmp -s "$work/postgres/atlas.sum" "$here/migrations/postgres/atlas.sum" && echo yes || echo NO)"
  echo
  echo "## Validate and lint"
  run migrate validate --dir "file://$work/sqlite" --dev-url "sqlite://dev?mode=memory"
  run migrate lint --dir "file://$work/sqlite" --dev-url "sqlite://dev?mode=memory" --latest 2
  run migrate lint --dir "file://$work/postgres" --dev-url "$pg/s5clidev?sslmode=disable" --latest 2
  echo "## Lint must flag a destructive change (negative control, on a copy)"
  cp -r "$work/sqlite" "$work/sqlite-bad"
  printf 'DROP TABLE `health_checks`;\n' >"$work/sqlite-bad/20991231000000_drop.sql"
  (cd "$here" && "$work/atlas" migrate hash --dir "file://$work/sqlite-bad") >/dev/null 2>&1
  run migrate lint --dir "file://$work/sqlite-bad" --dev-url "sqlite://dev?mode=memory" --latest 1
  echo "## Apply"
  run migrate apply --dir "file://$work/sqlite" --url "sqlite://$work/cli.db"
  run migrate apply --dir "file://$work/postgres" --url "$pg/s5cli?sslmode=disable"
  run migrate status --dir "file://$work/postgres" --url "$pg/s5cli?sslmode=disable"
  echo "## Inspect the result"
  run schema inspect --url "sqlite://$work/cli.db" --format '{{ sql . }}'
} >"$out"
echo "wrote $out"
