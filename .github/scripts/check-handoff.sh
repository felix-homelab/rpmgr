#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Upgrades a lone gateway and an all-in-one under load with the socket hand-off, from the previous
# build (HANDOFF_FROM, default HEAD~1: the commit before the one under test) to this tree's, in
# containers (docs/12-testing-and-quality.md, "Continuous integration"; slice 17.8). Needs Docker
# and a checkout with the previous commit (fetch-depth 2).
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
if ! git rev-parse --verify --quiet "${HANDOFF_FROM:-HEAD~1}^{commit}" >/dev/null; then
  fail "the previous build ${HANDOFF_FROM:-HEAD~1} is not in this checkout (use fetch-depth 2, or set HANDOFF_FROM)"
fi
if ! go test -tags handoff -count=1 -timeout 20m ./test/handoff/...; then
  fail "the hand-off test failed"
fi
finish
