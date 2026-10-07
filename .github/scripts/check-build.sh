#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Builds and vets every package, tests included, for every platform rpmgr is built for, with
# CGO_ENABLED=0 (docs/12-testing-and-quality.md, "Continuous integration"): linux/amd64, arm64,
# armv7 and riscv64 are released; windows/amd64 and darwin/{amd64,arm64} are compiled only, for
# the Phase 2 connectors. Linux-only code therefore needs a stub for the other systems.
#
# Usage: check-build.sh [<repository root>]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

root=${1:-$(repo_root)}
cd "$root"
if [[ ! -f go.mod ]]; then
  echo "no go.mod"
  exit 0
fi

for platform in linux/amd64 linux/arm64 linux/arm linux/riscv64 windows/amd64 darwin/amd64 darwin/arm64; do
  goos=${platform%/*} goarch=${platform#*/}
  echo "build $platform"
  if ! env CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" GOARM=7 go build -trimpath ./...; then
    fail "go build failed for $platform"
    continue
  fi
  if ! env CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" GOARM=7 go vet ./...; then
    fail "go vet failed for $platform"
  fi
done
finish
