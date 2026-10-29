#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Upgrades a lone gateway and an all-in-one under load with the socket hand-off, from the previous
# build (HANDOFF_FROM) to this tree's, in containers (docs/12-testing-and-quality.md, "Continuous
# integration"; slice 17.8, D159). Needs Docker. HANDOFF_FROM is a git revision, default HEAD: the
# code under test hands over to itself, as in a pull request. `release` is the last release tag
# (`git describe --tags --abbrev=0 --match 'v*'`, needs the tags: fetch-depth 0), as in the
# nightly run.
#
# Usage: check-handoff.sh [<repository root>]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

root=${1:-$(repo_root)}
cd "$root"
if [[ ! -f test/handoff/handoff_test.go ]]; then
  echo "no test/handoff"
  exit 0
fi
if ! command -v docker >/dev/null; then
  fail "docker is needed for the hand-off test"
fi
from=${HANDOFF_FROM:-HEAD}
if [[ $from == release ]]; then
  from=$(git describe --tags --abbrev=0 --match 'v*' 2>/dev/null) || fail "no release tag in this checkout (use fetch-depth 0)"
  if ! git cat-file -e "$from:internal/handoff" 2>/dev/null; then
    fail "the last release $from has no socket hand-off to start from"
  fi
  echo "the previous build is the last release, $from"
fi
if ! git rev-parse --verify --quiet "$from^{commit}" >/dev/null; then
  fail "the previous build $from is not in this checkout (set HANDOFF_FROM to a revision it has)"
fi
export HANDOFF_FROM=$from
if ! go test -tags handoff -count=1 -timeout 20m ./test/handoff/...; then
  fail "the hand-off test failed"
fi
finish
