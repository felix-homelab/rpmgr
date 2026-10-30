#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The object store client against a real S3-compatible store (docs/12-testing-and-quality.md,
# "Continuous integration"): conditional create races, Object Lock refusals, listing, a proxy.
# Runs the container of test/objstore. Without Docker the check is skipped, unless
# REQUIRE_DOCKER=1.
#
# Usage: check-objstore.sh [<repository root>]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

root=${1:-$(repo_root)}
cd "$root"
if ! docker version >/dev/null 2>&1; then
  if [[ ${REQUIRE_DOCKER:-} == 1 ]]; then
    fail "Docker is needed for the object store checks"
  fi
  echo "skipped: no Docker"
  exit 0
fi
if ! go test -tags objstoreit -count=1 -timeout 10m -v ./internal/objstore; then
  fail "the object store client did not work against the store"
fi
finish
