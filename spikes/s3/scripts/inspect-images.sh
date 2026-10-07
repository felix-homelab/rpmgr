#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Prints the versions of the client tools inside the pinned images used by the real-client runs.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/images.sh"

echo "== curl ($CURL_IMAGE)"
docker run --rm "$CURL_IMAGE" -V
echo "== playwright ($PLAYWRIGHT_IMAGE)"
docker run --rm --entrypoint /bin/bash "$PLAYWRIGHT_IMAGE" -c '
  ls -d /ms-playwright/*/
  for c in /ms-playwright/chromium-*/chrome-linux*/chrome; do [ -x "$c" ] && "$c" --version; done
  for f in /ms-playwright/firefox-*/firefox/firefox; do [ -x "$f" ] && "$f" --version; done
  node --version
  ls /usr/lib/node_modules 2>/dev/null || true'
