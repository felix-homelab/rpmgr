#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Runs inside the Playwright image: Chromium against every browser-facing route of s3gw, directly
# and through the relay, then HTTP/3 forced on the UDP port. Two binaries with the same network
# stack: Chrome for Testing (new headless mode; it loads the page but does not exit after
# --dump-dom in this container, so the gateway's records are the evidence) and
# chrome-headless-shell (prints the page). Certificate errors are ignored only because the routing,
# not the browser's trust store, is measured; HTTP/3 uses the SPKI allow-list, the documented way
# to make Chromium accept a test certificate over QUIC.
#
# Usage: chromium.sh <port> <relay-port>
set -euo pipefail
port=$1
relay=$2
cft=$(ls -d /ms-playwright/chromium-*/chrome-linux*/chrome | head -n1)
shell=$(ls -d /ms-playwright/chromium_headless_shell-*/chrome-headless-shell-linux64/chrome-headless-shell | head -n1)
"$cft" --version
"$shell" --version 2>/dev/null || echo "chrome-headless-shell: $shell"
spki=$(cat /certs/h3-spki.txt)
common=(--no-sandbox --disable-gpu --no-first-run --disable-dev-shm-usage
  --host-resolver-rules="MAP *.example.test 127.0.0.1")

visit() { # visit <binary> <timeout> <url> [extra flags...]
  local bin=$1 secs=$2 url=$3
  shift 3
  local profile rc=0
  profile=$(mktemp -d)
  echo "== $(basename "$bin") $url $*"
  local mode=()
  [[ $bin == "$cft" ]] && mode=(--headless=new)
  timeout "$secs" "$bin" "${mode[@]}" "${common[@]}" --user-data-dir="$profile" "$@" --dump-dom "$url" \
    >"$profile/out.html" 2>"$profile/err.txt" || rc=$?
  grep -oE '(http-route|passthrough-backend|controller|h3) [^<]*' "$profile/out.html" ||
    echo "(no page printed; exit $rc$(grep -m1 -oE 'net::ERR_[A-Z_]+' "$profile/err.txt" | sed 's/^/; /'))"
  rm -rf "$profile"
}

for bin in "$cft" "$shell"; do
  secs=20
  [[ $bin == "$cft" ]] && secs=8
  for p in "$port" "$relay"; do
    for h in app.example.test api.example.test pass.example.test panel.example.test unknown.example.test; do
      visit "$bin" "$secs" "https://$h:$p/" --ignore-certificate-errors
    done
  done
  visit "$bin" "$secs" "https://app.example.test:$port/" --enable-quic --origin-to-force-quic-on="app.example.test:$port" \
    --ignore-certificate-errors-spki-list="$spki"
done
