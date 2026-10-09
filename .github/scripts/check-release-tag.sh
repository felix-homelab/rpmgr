#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Checks a release tag before anything is built from it (RELEASING.md, "Tags" and "Changelog"):
# the tag matches the release pattern, and CHANGELOG.md has a dated section for its version. On
# success it prints that section's text, the release notes.
#
# Usage: check-release-tag.sh <tag> [<repository root>]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

tag=${1?tag required}
root=${2:-$(repo_root)}

# The release pattern of RELEASING.md, "Tags".
if ! [[ $tag =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(alpha|beta|rc)\.[1-9][0-9]*)?$ ]]; then
  fail "'$tag' is not a release tag (RELEASING.md, \"Tags\")"
  finish
fi
version=${tag#v}
heading=$(grep -nE "^## \[${version//./\\.}\] - [0-9]{4}-[0-9]{2}-[0-9]{2}\$" "$root/CHANGELOG.md" || true)
if [[ -z $heading ]]; then
  fail "CHANGELOG.md has no section '## [$version] - YYYY-MM-DD' (RELEASING.md, \"Release process\")"
  finish
fi
# The section runs to the next "## " heading or to the link definitions at the end, without the
# blank lines around it.
notes=$(tail -n +"$((${heading%%:*} + 1))" "$root/CHANGELOG.md" | awk '/^## |^\[[^]]+\]: /{ exit } { print }' |
  sed -e '/./,$!d')
if [[ -z $notes ]]; then
  fail "the section of $version in CHANGELOG.md is empty"
  finish
fi
echo "$notes"
