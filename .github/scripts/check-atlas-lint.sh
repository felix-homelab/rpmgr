#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Lints every migration file of one directory with the Atlas community CLI (Apache-2.0; image
# pinned by digest): destructive changes, data-dependent changes and other Atlas analyzers
# (docs/06-data-model.md, "Migrations"). The development database must be empty. Needs Docker.
#
# Usage: check-atlas-lint.sh <migration directory> <dev URL, e.g. sqlite://dev?mode=memory>
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

dir=${1:?migration directory required}
dev=${2:?development database URL required}
atlas='mirror.gcr.io/arigaio/atlas:1.3.3-community@sha256:9c9958f5b8d26d404ab2e28098c8629526eb4bec647f790278611e58a0b19839'

abs=$(cd "$dir" && pwd)
n=$(find "$abs" -maxdepth 1 -name '*.sql' | wc -l)
if ((n == 0)); then
  echo "no migrations in $dir"
  exit 0
fi
if ! docker run --rm --network host -u "$(id -u):$(id -g)" -v "$abs:/migrations:ro" "$atlas" \
  migrate lint --dir "file:///migrations" --dev-url "$dev" --latest "$n"; then
  fail "atlas migrate lint reported problems in $dir"
fi
finish
