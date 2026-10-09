#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Builds the multi-arch image of a release from its artifacts with the Dockerfile and pushes it
# with the given tags (RELEASING.md, "Release process"), then prints the digest of its index. The
# image has one manifest per released architecture and no attestation manifests; provenance and
# signatures are added by digest. Needs Docker with a buildx builder that builds for several
# platforms (the docker-container driver) and a login to the registry.
#
# Usage: release-images.sh <artifact directory> <version> <commit> <image> <tag>...
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

dir=${1:?artifact directory required} version=${2:?version required} commit=${3:?commit required}
image=${4:?image required}
shift 4
(($# > 0)) || { fail "no tag given"; finish; }
root=$(repo_root)

platforms=()
for arch in "${RELEASE_ARCHES[@]}"; do
  if [[ $arch == arm ]]; then
    platforms+=(linux/arm/v7)
  else
    platforms+=("linux/$arch")
  fi
done
tags=()
for tag in "$@"; do
  tags+=(-t "$image:$tag")
done
meta=$(mktemp)
docker buildx build --platform "$(IFS=,; echo "${platforms[*]}")" --build-arg VERSION="$version" \
  --build-arg REVISION="$commit" --provenance=false --sbom=false -f "$root/Dockerfile" "${tags[@]}" \
  --metadata-file "$meta" --push "$dir" >&2
digest=$(grep -o '"containerimage.digest": *"sha256:[0-9a-f]*"' "$meta" | grep -o 'sha256:[0-9a-f]*')
rm -- "$meta"
[[ -n $digest ]] || { fail "buildx reported no image digest"; finish; }
echo "$digest"
