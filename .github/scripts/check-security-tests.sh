#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Checks that every named security regression test in docs/12-testing-and-quality.md ("Security
# testing") is accounted for in security-tests.txt, and that the code agrees (D61):
#   - every test named in the document is registered once, and every registered test is named there;
#   - a test marked "done" exists as a Go test function;
#   - a test marked "pending" does not exist yet, so the PR that adds it must mark it done;
#   - with REQUIRE_COMPLETE=1 (the end of the phase) no test may still be pending.
#
# Usage: check-security-tests.sh [<repository root>]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

root=${1:-$(repo_root)}
registry=$root/.github/scripts/security-tests.txt
doc=$root/docs/12-testing-and-quality.md

mapfile -t named < <(grep -oE '^\| `Test[A-Za-z0-9_]+`' "$doc" | sed 's/^| `//; s/`$//' | sort)
declare -A seen=()
pending=0
while IFS=$'\t' read -r test status slice issue _; do
  [[ -z $test || $test == \#* ]] && continue
  if [[ -n ${seen[$test]-} ]]; then
    fail "$test is registered twice"
    continue
  fi
  seen[$test]=1
  if ! printf '%s\n' "${named[@]}" | grep -qx "$test"; then
    fail "$test is registered but not named in docs/12; remove it or name it there"
  fi
  exists=no
  if git -C "$root" grep -qE "^func ${test}\(" -- '*_test.go' ':!**/testdata/**'; then
    exists=yes
  fi
  case $status in
    done)
      [[ $exists == yes ]] || fail "$test is marked done but no test function $test exists"
      ;;
    pending)
      [[ $slice =~ ^[0-9]+\.[0-9]+[a-z]?$ && $issue =~ ^#[0-9]+$ ]] ||
        fail "$test is pending without a slice and an issue"
      [[ $exists == no ]] || fail "$test exists now; mark it done in security-tests.txt"
      pending=$((pending + 1))
      ;;
    p2 | p3) ;;
    *) fail "$test has an unknown status '$status' (pending, done, p2, p3)" ;;
  esac
done <"$registry"
for test in "${named[@]}"; do
  [[ -n ${seen[$test]-} ]] || fail "$test is named in docs/12 but not registered in security-tests.txt"
done
echo "${#named[@]} named security tests; $pending pending"
if [[ ${REQUIRE_COMPLETE-} == 1 ]] && ((pending > 0)); then
  fail "$pending security tests are still pending at the end of the phase"
fi
finish
