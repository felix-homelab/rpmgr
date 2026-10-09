#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Browser tests of the web UI (docs/12-testing-and-quality.md, "Test layers"): builds web/ into
# internal/webui, runs an all-in-one with it in the test process (test/webe2e), and runs the
# Playwright flows of web/e2e against it in the Playwright image, with axe and a CSP check on every
# page. Needs Docker, Node and npm, and Go; without Docker the check is skipped, unless
# REQUIRE_DOCKER=1.
#
# Usage: check-web-e2e.sh [<repository root>]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

root=${1:-$(repo_root)}
want=$(node -p 'require(process.argv[1]).devDependencies["@playwright/test"]' "$root/web/package.json")
if [[ $want != "$PLAYWRIGHT_VERSION" ]]; then
  fail "web/package.json has @playwright/test $want, the Playwright image $PLAYWRIGHT_VERSION (.github/scripts/lib.sh)"
  finish
fi
if ! docker version >/dev/null 2>&1; then
  if [[ ${REQUIRE_DOCKER:-} == 1 ]]; then
    fail "Docker is needed for the browser tests"
  fi
  echo "skipped: no Docker"
  exit 0
fi
if [[ ! -d $root/web/node_modules ]]; then
  npm --prefix "$root/web" ci --ignore-scripts --no-fund --no-audit
fi
npm --prefix "$root/web" run build >/dev/null || { fail "the web build failed"; finish; }
if ! go -C "$root" test -tags webe2e -count=1 -timeout 10m -v ./test/webe2e/; then
  fail "browser tests failed"
fi
finish
