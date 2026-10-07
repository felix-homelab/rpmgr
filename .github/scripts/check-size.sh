#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Counts the changed lines of production code in a pull request and applies the size limits of
# CONTRIBUTING.md, "Size of changes" (D53): below 400 is fine, 400–800 gives a warning (the PR
# must say why it cannot be split), more than 800 fails unless the PR is labelled `mechanical`.
#
# Production code is source code (.go, .proto, .ts, .tsx, .js, .jsx, .css, .sh, .sql) outside
# tests, test data, generated files, migrations, CI configuration and documents. Lockfiles and
# fixtures are not source code by these rules.
#
# Usage: check-size.sh <base-sha> <head-sha> "<space-separated labels>"
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

base=${1:?base commit required}
head=${2:?head commit required}
labels=" ${3-} "
warn_at=400
fail_above=800

if ! numstat=$(git diff --numstat --no-renames "$base...$head"); then
  fail "cannot compare $base...$head"
  finish
fi
counted=0
files=0
while IFS=$'\t' read -r added deleted path; do
  [[ $added == - ]] && continue # binary
  [[ $path =~ \.(go|proto|ts|tsx|js|jsx|mjs|cjs|css|sh|sql)$ ]] || continue
  [[ $path =~ (_test\.go|\.(test|spec)\.(ts|tsx|js|jsx))$ ]] && continue
  [[ $path =~ (^|/)(testdata|migrations|node_modules|vendor|e2e)/ || $path =~ ^(gen|\.github)/ ]] && continue
  if git cat-file -e "$head:$path" 2>/dev/null &&
    git show "$head:$path" | head -n 10 | grep -qE 'Code generated .* DO NOT EDIT\.'; then
    continue
  fi
  counted=$((counted + added + deleted))
  files=$((files + 1))
done <<<"$numstat"

summary="Production code changed: $counted lines in $files files (limits: warning from $warn_at, failure above $fail_above)."
echo "$summary"
if [[ -n ${GITHUB_STEP_SUMMARY-} ]]; then
  echo "$summary" >>"$GITHUB_STEP_SUMMARY"
fi
if ((counted > fail_above)); then
  if [[ $labels == *" mechanical "* ]]; then
    echo "above $fail_above lines, allowed: the PR is labelled 'mechanical'"
  else
    fail "$counted lines of production code; more than $fail_above must be split, unless the change is" \
      "mechanical (label 'mechanical'), see CONTRIBUTING.md, 'Size of changes'"
  fi
elif ((counted >= warn_at)); then
  msg="$counted lines of production code: the PR description must say why it cannot be split (CONTRIBUTING.md, 'Size of changes')"
  if [[ ${GITHUB_ACTIONS-} == true ]]; then
    echo "::warning::$msg"
  else
    echo "warning: $msg"
  fi
fi
finish
