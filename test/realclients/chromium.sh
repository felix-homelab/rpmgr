#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Runs inside the Playwright image: headless Chromium (chrome-headless-shell, which prints the page
# it loaded) against every name the gateway's port 443 serves. Certificate errors are ignored
# because the routing is measured, not the browser's trust store; an unknown name still gets no
# page, as the gateway closes it after the handshake. Adapted from spike/s3:
# spikes/s3/scripts/in-container/chromium.sh.
#
# Usage: chromium.sh <port> <host>...
set -euo pipefail
port=$1
shift
shell=$(ls -d /ms-playwright/chromium_headless_shell-*/chrome-headless-shell-linux64/chrome-headless-shell | head -n1)
echo "chrome-headless-shell $shell"
for h in "$@"; do
  profile=$(mktemp -d)
  echo "== https://$h:$port/"
  rc=0
  timeout 20 "$shell" --no-sandbox --disable-gpu --no-first-run --disable-dev-shm-usage \
    --host-resolver-rules="MAP *.example.test 127.0.0.1" --ignore-certificate-errors \
    --user-data-dir="$profile" --dump-dom "https://$h:$port/" >"$profile/out.html" 2>"$profile/err.txt" || rc=$?
  grep -oE '(http-route|passthrough-backend|controller) [^<]*' "$profile/out.html" ||
    echo "(no page; exit $rc$(grep -m1 -oE 'net::ERR_[A-Z_]+' "$profile/err.txt" | sed 's/^/; /'))"
done # the profiles go with the container
