#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Real clients against the gateway's port 443 router (docs/12-testing-and-quality.md, "Continuous
# integration"): Go, curl, headless Chromium and Firefox reach http routes, a TLS-passthrough
# route and the controller's UI name, and get no page for an unknown name. Nightly; needs Docker
# and, for Firefox, network access to install playwright-core. Without Docker the check is
# skipped, unless REQUIRE_DOCKER=1. Adapted from spike/s3: spikes/s3/scripts/run-real-clients.sh.
#
# Usage: check-real-clients.sh [<repository root>]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# The client images, by digest; the Playwright image is in lib.sh.
export CURL_IMAGE='mirror.gcr.io/curlimages/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777'

root=${1:-$(repo_root)}
cd "$root"
if ! docker version >/dev/null 2>&1; then
  if [[ ${REQUIRE_DOCKER:-} == 1 ]]; then
    fail "Docker is needed for the real-client checks"
  fi
  echo "skipped: no Docker"
  exit 0
fi
if ! go test -tags realclients -count=1 -timeout 20m -run TestRealClients -v ./internal/gateway; then
  fail "real clients did not reach what they should"
fi
finish
