#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The reproducibility check of the release build (docs/12-testing-and-quality.md, "Continuous
# integration"). With two directories, it compares two builds of build-release.sh: the same
# artifacts, equal byte for byte. Without them, it builds the committed HEAD twice, each from its
# own copy of the tree at another path with its own Go build cache and npm cache, and compares
# the two; uncommitted changes are not built. CI builds on two runners instead and compares here.
#
# Usage: check-reproducible.sh <build a> <build b>
#        check-reproducible.sh [<repository root>]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

compare() {
  local a=$1 b=$2 f
  if ! cmp -s "$a/SHA256SUMS" "$b/SHA256SUMS"; then
    fail "the two builds differ:"$'\n'"$(diff "$a/SHA256SUMS" "$b/SHA256SUMS" || true)"
  fi
  for f in "$a"/* "$b"/*; do
    [[ -f $a/${f##*/} && -f $b/${f##*/} ]] || fail "${f##*/} is in one build only"
  done
  finish
  echo "the two builds are equal:"
  cat "$a/SHA256SUMS"
}

if (($# == 2)); then
  compare "$1" "$2"
  exit 0
fi

root=${1:-$(repo_root)}
commit=$(git -C "$root" rev-parse HEAD)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/rpmgr-reproducible.XXXXXX")
for side in a b; do
  src=$tmp/src-$side/$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')/rpmgr
  mkdir -p "$src"
  git -C "$root" archive HEAD | tar -x -C "$src"
  echo "== build $side in $src"
  GOCACHE=$tmp/gocache-$side npm_config_cache=$tmp/npm-$side \
    "$src/.github/scripts/build-release.sh" 0.0.0-reproducible "$commit" "$tmp/out-$side" "$src" >"$tmp/build-$side.log" 2>&1 ||
    { tail -n 30 "$tmp/build-$side.log"; fail "build $side failed (log in $tmp/build-$side.log)"; finish; }
done
compare "$tmp/out-a" "$tmp/out-b"
echo "(builds and logs in $tmp)"
