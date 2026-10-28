#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Runs inside the Playwright image: installs playwright-core from the lockfile next to it, which
# pins it by hash at the version of the image's browsers, into a temporary directory and runs
# firefox.mjs.
#
# Usage: firefox.sh <port> <host>...
set -euo pipefail
pinned=$(node -p 'require("/scripts/package.json").dependencies["playwright-core"]')
if [[ $pinned != "${PLAYWRIGHT_VERSION:?}" ]]; then
  echo "test/realclients/package.json pins playwright-core $pinned, the Playwright image $PLAYWRIGHT_VERSION (.github/scripts/lib.sh)" >&2
  exit 1
fi
work=$(mktemp -d)
cp /scripts/package.json /scripts/package-lock.json "$work/"
npm ci --prefix "$work" --silent --no-audit --no-fund >/dev/null
cp /scripts/firefox.mjs "$work/"
node "$work/firefox.mjs" "$@"
