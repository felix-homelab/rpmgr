#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Runs golangci-lint with the repository's .golangci.yml (docs/12-testing-and-quality.md,
# "Security testing"): the standard linters, gosec, and the forbidigo and depguard bans. Needs
# Docker; the module cache of the host's go command is reused when there is one.
#
# Usage: check-golangci.sh [<repository root>]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

root=${1:-$(repo_root)}
image='mirror.gcr.io/golangci/golangci-lint:v2.14.0@sha256:ad862ba6b3798cbe0fd9fd7408d498fd74fbd2623a92406b2fd3898faf0bf98f'

if [[ ! -f $root/go.mod ]]; then
  echo "no go.mod"
  exit 0
fi
modcache=$(go env GOMODCACHE 2>/dev/null || true)
mounts=(-v "$root:/src")
env=(-e GOCACHE=/tmp/gocache -e GOLANGCI_LINT_CACHE=/tmp/lintcache -e GOFLAGS=-mod=readonly -e HOME=/tmp)
if [[ -n $modcache && -d $modcache ]]; then
  mounts+=(-v "$modcache:/gomodcache")
  env+=(-e GOMODCACHE=/gomodcache)
else
  env+=(-e GOMODCACHE=/tmp/gomodcache) # downloaded inside the container
fi
if ! docker run --rm -u "$(id -u):$(id -g)" "${mounts[@]}" -w /src "${env[@]}" \
  "$image" golangci-lint run ./...; then
  fail "golangci-lint reported problems (see above)"
fi
finish
