#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Checks the head and base branch of a pull request against CONTRIBUTING.md, "Branches".
# Dependency-bot branches are exempt. tmp/ branches are never merged, so a PR from one fails.
#
# Usage: check-branch-name.sh <head-branch> [<base-branch>]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

head=${1-}
base=${2-main}
word='[a-z0-9]+([.-][a-z0-9]+)*'

case $base in
  main) ;;
  release/*)
    if [[ ! $base =~ ^release/[0-9]+\.[0-9]+$ ]]; then
      fail "the base branch '$base' is not a release/<major>.<minor> branch"
    fi
    ;;
  *) fail "pull requests target main or a release/<major>.<minor> branch, not '$base'" ;;
esac

if [[ $head == dependabot/* ]]; then
  finish
  exit 0
fi
if ((${#head} > 60)); then
  fail "the branch name '$head' has ${#head} characters; the limit is 60"
fi
if [[ $head =~ ^(feature|bugfix)/[0-9]+-${word}$ ]]; then
  :
elif [[ $head =~ ^(improvement|merge)/${word}$ ]]; then
  :
elif [[ $head =~ ^tmp/ ]]; then
  fail "tmp/ branches hold experiments and spikes and are never merged; write the result down" \
    "and open the PR from a feature/ or improvement/ branch"
elif [[ $head =~ ^release/ ]]; then
  fail "release/ branches are merge targets; merge a release branch into main from a" \
    "merge/<desc> branch"
else
  fail "the branch name '$head' does not match feature/<issue>-<desc>, bugfix/<issue>-<desc>," \
    "improvement/<desc> or merge/<desc> (lowercase letters, digits, '-' and '.')"
fi
finish
