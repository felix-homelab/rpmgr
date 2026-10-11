#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Prints the tags of the image of a release, one per line (RELEASING.md, "Release process"): the
# version, and for a stable release also X.Y, X and latest, each only while no published stable
# release above it shares it: X.Y for the highest release of its minor, X for the highest of its
# major, latest for the highest of all. A pre-release gets its version only.
#
# Usage: image-tags.sh <version> [<published stable version>...]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

semver='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.]+)?$'
version=${1:?version required}
shift
[[ $version =~ $semver ]] || { fail "'$version' is not a version without a leading v"; finish; }
echo "$version"
[[ -n ${BASH_REMATCH[4]} ]] && exit 0
major=${BASH_REMATCH[1]} minor=${BASH_REMATCH[2]}

# highest prints the highest of the stable versions given, the release's own among them.
highest() { printf '%s\n' "$version" "$@" | sort -t . -k 1,1n -k 2,2n -k 3,3n | tail -n 1; }
stable=() same_major=() same_minor=()
for v in "$@"; do
  [[ $v =~ $semver && -z ${BASH_REMATCH[4]} ]] || continue
  stable+=("$v")
  [[ ${BASH_REMATCH[1]} == "$major" ]] && same_major+=("$v")
  [[ ${BASH_REMATCH[1]} == "$major" && ${BASH_REMATCH[2]} == "$minor" ]] && same_minor+=("$v")
done
[[ $(highest ${same_minor[@]+"${same_minor[@]}"}) == "$version" ]] && echo "$major.$minor"
[[ $(highest ${same_major[@]+"${same_major[@]}"}) == "$version" ]] && echo "$major"
[[ $(highest ${stable[@]+"${stable[@]}"}) == "$version" ]] && echo latest
exit 0
