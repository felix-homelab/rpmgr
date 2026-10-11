#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests the OCI image that the Dockerfile builds (test/images, build tag images;
# docs/10-operations.md, "Install"): on every released platform the binary runs as the
# nonroot user and every role starts; on this host's platform an all-in-one runs and serves on the
# ports 80 and 443 that Docker publishes. With a directory of release artifacts and their version,
# the images are built from them, as the image workflow does before it publishes; without, from
# binaries the test builds. Needs Docker with buildx and the go command. The other platforms run
# under QEMU user-mode emulation (tonistiigi/binfmt, as the workflows register it); without it they
# are only built, unless REQUIRE_EMULATION=1, as in CI.
#
# Usage: check-images.sh [<artifact directory> <version>] [<repository root>]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

dir= version= root=
case $# in
  0 | 1) root=${1-} ;;
  *) dir=$(cd "$1" && pwd) version=$2 root=${3-} ;;
esac
root=$(cd "${root:-$(repo_root)}" && pwd)
if ! (cd "$root" && RPMGR_RELEASE_ARCHES="${RELEASE_ARCHES[*]}" RPMGR_IMAGE_ARTIFACTS=$dir RPMGR_IMAGE_VERSION=$version \
  go test -count=1 -tags images -timeout 30m ./test/images/); then
  fail "the image tests failed (see above)"
fi
finish
