#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Checks every relative link and heading anchor in the repository's tracked Markdown files with
# lychee, offline (docs/12-testing-and-quality.md, "Continuous integration"). External URLs are not
# fetched, so the check is deterministic; untracked files (e.g. local worktrees) are not checked.
# Needs Docker.
#
# Usage: check-links.sh [<repository root>]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

root=${1:-$(repo_root)}
image='lycheeverse/lychee:0.24.2@sha256:e2d19e57cf6ab037026f20b8e449a1f30d9d7f81eef4194763aab2eab20bd28d'

mapfile -t files < <(git -C "$root" ls-files '*.md')
if ((${#files[@]} == 0)); then
  echo "no Markdown files"
  exit 0
fi
if ! docker run --rm -u "$(id -u):$(id -g)" -v "$root:/input:ro" -w /input "$image" \
  --offline --include-fragments --no-progress --format compact "${files[@]}"; then
  fail "broken links or anchors in Markdown files (see the lychee report above)"
fi
finish
