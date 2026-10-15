#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Takes the screenshots of the user guide (docs/guide/images/README.md): builds web/ into
# internal/webui, then runs test/webe2e's TestScreens, which seeds an all-in-one with made-up data
# and writes one PNG per page of the web UI into docs/guide/images/web, in the Playwright image of
# lib.sh. Needs Docker, Node and npm, and Go. A tool, not a check: CI never runs it.
#
# Usage: screenshots.sh [all | <name>,<name>,...]
#   all (the default) writes every screenshot; names write only those, e.g. routes,overview.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

root=$(repo_root)
names=${1:-all}
if [[ ! $names =~ ^[a-z0-9,-]+$ ]]; then
  fail "screenshot names are lowercase letters, digits and dashes, separated by commas: '$names'"
  finish
fi
if ! docker version >/dev/null 2>&1; then
  fail "Docker is needed for the screenshots"
  finish
fi
want=$(node -p 'require(process.argv[1]).devDependencies["@playwright/test"]' "$root/web/package.json")
if [[ $want != "$PLAYWRIGHT_VERSION" ]]; then
  fail "web/package.json has @playwright/test $want, the Playwright image $PLAYWRIGHT_VERSION (.github/scripts/lib.sh)"
  finish
fi
if [[ ! -d $root/web/node_modules ]]; then
  npm --prefix "$root/web" ci --ignore-scripts --no-fund --no-audit
fi
npm --prefix "$root/web" run build >/dev/null || {
  fail "the web build failed"
  finish
}
if ! SCREENS=$names go -C "$root" test -tags webe2e -count=1 -timeout 15m -run '^TestScreens$' -v ./test/webe2e/; then
  fail "the screenshots failed"
fi
finish
