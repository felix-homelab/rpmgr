#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Writes the SBOM of a release (docs/04-security.md, "Release signing"): an SPDX JSON document
# that syft makes from the source tree, listing the Go modules that go.mod requires and the npm
# packages of the web UI's lockfile that reach the browser (syft leaves out development
# dependencies), without test fixtures, installed packages and build output. Needs Docker.
#
# Usage: release-sbom.sh <version> <output file> [<repository root>]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

version=${1:?version required} out=${2:?output file required}
root=${3:-$(repo_root)}
image='mirror.gcr.io/anchore/syft:v1.54.1@sha256:3eb5379ba7b409c3f4069b686110527af0c47df993fa5c10d13e7cf34f49b1aa'

if [[ -e $out ]]; then
  fail "$out exists already"
  finish
fi
if ! docker run --rm -u "$(id -u):$(id -g)" --tmpfs /tmp:mode=1777 -e XDG_CACHE_HOME=/tmp -e SYFT_CHECK_FOR_APP_UPDATE=false \
  -v "$root:/src:ro" "$image" scan dir:/src \
  --source-name rpmgr --source-version "$version" --exclude './.git/**' --exclude './.github/**' \
  --exclude './test/**' --exclude './web/go.mod' --exclude './web/node_modules/**' \
  --exclude './internal/webui/ui/**' -o spdx-json >"$out"; then
  rm -- "$out"
  fail "syft could not make the SBOM"
fi
finish
