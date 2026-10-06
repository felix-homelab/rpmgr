#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Checks that every non-merge commit in <base>..<head> carries a Developer Certificate of Origin
# sign-off by its author: a "Signed-off-by: Name <email>" trailer whose e-mail equals the author's
# (CONTRIBUTING.md, "License, sign-off and third-party code"). Commits authored by the dependency
# bot are exempt.
#
# Usage: check-dco.sh <base-sha> <head-sha>
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

base=${1:?base commit required}
head=${2:?head commit required}
bot_email='49699333+dependabot[bot]@users.noreply.github.com'

commits=$(git rev-list --no-merges "$base..$head")
for c in $commits; do
  author_email=$(git log -1 --format='%ae' "$c")
  if [[ $author_email == "$bot_email" ]]; then
    continue
  fi
  signoffs=$(git log -1 --format='%(trailers:key=Signed-off-by,valueonly)' "$c")
  if ! grep -qiF "<${author_email}>" <<<"$signoffs"; then
    fail "commit ${c:0:12} ($(git log -1 --format='%s' "$c")) has no 'Signed-off-by:' trailer" \
      "for its author <${author_email}>; amend it with 'git commit --amend -s' or sign off all" \
      "commits with 'git rebase --signoff $base'"
  fi
done
finish
