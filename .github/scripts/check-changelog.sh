#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Checks that a pull request changes CHANGELOG.md or carries the no-changelog label
# (RELEASING.md, "Changelog").
#
# Usage: check-changelog.sh <base-sha> <head-sha> "<space-separated labels>"
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

base=${1:?base commit required}
head=${2:?head commit required}
labels=" ${3-} "

if [[ $labels == *" no-changelog "* ]]; then
  finish
  exit 0
fi
if ! git diff --name-only "$base...$head" -- | grep -qx 'CHANGELOG.md'; then
  fail "the PR changes no CHANGELOG.md entry; add one under '## [Unreleased]', or label the PR" \
    "no-changelog if it has no user-visible change"
fi
finish
