#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Runs every Go fuzz target briefly (docs/12-testing-and-quality.md, "Test strategy": a short smoke
# run per PR, long runs nightly). The go command fuzzes one target per invocation, so each target
# runs on its own. A crash leaves its input in testdata/fuzz/, which becomes a regression test.
#
# Usage: check-fuzz.sh [<fuzz time per target, default 10s>] [<repository root>]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

fuzztime=${1:-10s}
root=${2:-$(repo_root)}
cd "$root"

targets=0
while IFS= read -r file; do
  dir=$(dirname "$file")
  while IFS= read -r name; do
    targets=$((targets + 1))
    echo "fuzz $dir $name ($fuzztime)"
    if ! go test -run='^$' -fuzz="^${name}\$" -fuzztime="$fuzztime" "./$dir"; then
      fail "fuzz target $name in $dir failed"
    fi
  done < <(sed -nE 's/^func (Fuzz[A-Za-z0-9_]*)\(f \*testing\.F\).*/\1/p' "$file")
done < <(git ls-files '*_test.go' | grep -v '/testdata/' || true)
echo "$targets fuzz target(s)"
finish
