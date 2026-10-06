#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Applies the migrations of both dialects to empty databases with the Go executor (no Atlas CLI),
# re-applies them (must be a no-op), and checks that the live schema equals the Ent schema.
#
# Usage: apply-check.sh <postgres-port>   (PostgreSQL user/password s5/s5, see README.md)
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
port=${1:?postgres port}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$here/results"
exec > >(tee "$here/results/apply-check.txt") 2>&1
echo "# apply-check.sh ($(go version); $(docker exec rpmgr-s5-pg18 postgres --version))"
go -C "$here" build -o "$work/s5" ./cmd/s5
s5() { "$work/s5" "$@" -dir "$here/migrations"; }

psql_admin() { docker exec rpmgr-s5-pg18 psql -U s5 -qtAc "$1"; }
psql_admin "DROP DATABASE IF EXISTS s5apply" && psql_admin "CREATE DATABASE s5apply"

sqlite="file:$work/app.db?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
pg="postgres://s5:s5@127.0.0.1:$port/s5apply?sslmode=disable"

for target in "sqlite $sqlite" "postgres $pg"; do
  set -- $target
  echo "== $1: apply from empty"
  s5 apply -dialect "$1" -db "$2"
  echo "== $1: apply again (no pending files)"
  s5 apply -dialect "$1" -db "$2"
  echo "== $1: live schema vs Ent schema"
  s5 check -dialect "$1" -db "$2" && echo "equal"
done
