#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Reproducibility: removes the newest migration of each dialect from a copy of the directory,
# regenerates it from the Ent schema with the pinned Atlas library, and compares it byte for byte
# with the committed file. Writes results/regen-check.txt.
#
# Usage: regen-check.sh <postgres-port>
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
port=${1:?postgres port}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$here/results"
exec > >(tee "$here/results/regen-check.txt") 2>&1
echo "# regen-check.sh ($(go version); ariga.io/atlas $(go -C "$here" list -m -f '{{.Version}}' ariga.io/atlas))"
go -C "$here" build -o "$work/s5" ./cmd/s5
docker exec rpmgr-s5-pg18 psql -U s5 -qtAc "DROP DATABASE IF EXISTS s5regen" >/dev/null
docker exec rpmgr-s5-pg18 psql -U s5 -qtAc "CREATE DATABASE s5regen" >/dev/null

status=0
for d in sqlite postgres; do
  mkdir -p "$work/m/$d"
  newest=$(ls "$here/migrations/$d"/*.sql | sort | tail -n 1)
  for f in "$here/migrations/$d"/*.sql; do
    [[ $f == "$newest" ]] || cp "$f" "$work/m/$d/"
  done
  "$work/s5" hash -dialect "$d" -dir "$work/m"
  dev=""
  [[ $d == postgres ]] && dev="postgres://s5:s5@127.0.0.1:$port/s5regen?sslmode=disable"
  "$work/s5" diff -dialect "$d" ${dev:+-dev "$dev"} -name regen -dir "$work/m"
  regen=$(ls "$work/m/$d"/*_regen.sql)
  if cmp -s "$regen" "$newest"; then
    echo "$d: regenerated $(basename "$newest") is byte-identical"
  else
    echo "$d: regenerated file differs from $(basename "$newest"):"
    diff "$newest" "$regen" || true
    status=1
  fi
done
exit $status
