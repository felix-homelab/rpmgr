#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Runs inside the Playwright image: installs playwright-core at the version of the image's
# browsers into a temporary directory and runs firefox.mjs.
#
# Usage: firefox.sh <port> <host>...
set -euo pipefail
work=$(mktemp -d)
npm --prefix "$work" install --silent --no-audit --no-fund "playwright-core@${PLAYWRIGHT_VERSION:?}" >/dev/null
cp /scripts/firefox.mjs "$work/"
node "$work/firefox.mjs" "$@"
