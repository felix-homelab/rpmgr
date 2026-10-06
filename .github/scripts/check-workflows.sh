#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Lints the GitHub Actions workflows with actionlint (including shellcheck on run: steps), and
# checks that every action is pinned to a full commit SHA (docs/12-testing-and-quality.md,
# "Security testing"). Needs Docker.
#
# Usage: check-workflows.sh [<repository root>]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

root=${1:-$(repo_root)}
image='rhysd/actionlint:1.7.12@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667'

if ! docker run --rm -u "$(id -u):$(id -g)" -v "$root:/repo:ro" -w /repo "$image" -color; then
  fail "actionlint reported problems (see above)"
fi

# uses: owner/repo@<40 hex characters>, or a local action (./...), or docker://...@sha256:...
while IFS= read -r line; do
  ref=${line#*uses:}
  ref=${ref%%#*}
  ref=$(echo "$ref" | tr -d " \"'")
  case $ref in
    ./*) ;;
    docker://*@sha256:*) ;;
    *@*)
      if [[ ! ${ref##*@} =~ ^[0-9a-f]{40}$ ]]; then
        fail "${line%%:*}: '$ref' is not pinned to a full commit SHA"
      fi
      ;;
    *) fail "${line%%:*}: '$ref' has no version pin" ;;
  esac
done < <(cd "$root" && grep -rnE '^[[:space:]-]*uses:' .github/workflows || true)
finish
