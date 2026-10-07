#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Runs every Go test for one Linux architecture (docs/12-testing-and-quality.md, "Continuous
# integration"): natively on a machine of that architecture, or under QEMU user-mode emulation
# when the kernel has a binfmt handler for it. The race detector runs where Go supports it
# (amd64, arm64); it needs cgo for its runtime only.
#
# Usage: check-test-arch.sh <amd64|arm64|arm|riscv64> [<repository root>]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

arch=${1:?architecture required: amd64, arm64, arm or riscv64}
root=${2:-$(repo_root)}
cd "$root"
case $arch in
  amd64 | arm64) flags=(-race) cgo=1 ;;
  arm | riscv64) flags=() cgo=0 ;;
  *)
    fail "unknown architecture '$arch'"
    finish
    ;;
esac
echo "go test linux/$arch ${flags[*]}"
if ! env GOOS=linux GOARCH="$arch" GOARM=7 CGO_ENABLED="$cgo" go test "${flags[@]}" -count=1 ./...; then
  fail "tests failed on linux/$arch"
fi
finish
