#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The per-PR subset of the container end-to-end tests (docs/12-testing-and-quality.md, "Where the
# cells run"): Docker Compose with a controller, two gateways, two connectors, a service and a
# client, running the rpmgrtest build. Needs Docker with Compose; without it the check is skipped,
# unless REQUIRE_DOCKER=1.
#
# Usage: check-e2e.sh [<repository root>]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

root=${1:-$(repo_root)}
cd "$root"
if [[ ! -d test/e2e ]]; then
  echo "no test/e2e"
  exit 0
fi
if ! docker compose version >/dev/null 2>&1; then
  if [[ ${REQUIRE_DOCKER:-} == 1 ]]; then
    fail "Docker with Compose is needed for the end-to-end tests"
  fi
  echo "skipped: no Docker with Compose"
  exit 0
fi
if ! (cd test/e2e && go test -tags e2e -count=1 -timeout 25m .); then
  fail "end-to-end tests failed"
fi
finish
