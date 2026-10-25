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
# Under QEMU a package's tests take several times as long: internal/apisvc took 529 and 582 s of
# go test's default 10 minutes per package on riscv64 before it grew, so emulated runs get 30.
# A 32-bit test process has 4 GiB of address space, which parallel tests that hash passwords
# (64 MiB each with the default profile) filled before the collector ran; a soft memory limit
# makes it collect early enough.
limits=()
case $arch in
  amd64 | arm64) flags=(-race -timeout 20m) cgo=1 ;;
  arm) flags=(-timeout 30m) cgo=0 limits=(GOMEMLIMIT=2GiB) ;;
  riscv64) flags=(-timeout 30m) cgo=0 ;;
  *)
    fail "unknown architecture '$arch'"
    finish
    ;;
esac
echo "go test linux/$arch ${flags[*]}"
# Tests listen on ports from internal/testutil/freeport, below the kernel's ephemeral range; a
# runner whose range reaches lower would take them for outgoing connections.
echo "ephemeral ports: $(cat /proc/sys/net/ipv4/ip_local_port_range 2>/dev/null || echo unknown)"
if ! env GOOS=linux GOARCH="$arch" GOARM=7 CGO_ENABLED="$cgo" "${limits[@]}" go test "${flags[@]}" -count=1 ./...; then
  fail "tests failed on linux/$arch"
fi
finish
