#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Spike S3 real-client run. For each client (Go, curl, Chromium, Firefox) it starts a fresh s3gw
# on 127.0.0.1, sends the client to every route on TCP — directly and through the segmenting relay
# (1448-byte segments) — and, where the client can, HTTP/3 on the same UDP port; then it stops the
# gateway, which writes its routing events and handler notes to results/real-clients/<client>/.
# Certificates and the connector's test key stay in a temporary directory.
#
# Usage: run-real-clients.sh [go|curl|chromium|firefox ...]   (default: all)
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$here/scripts/images.sh"
export PATH=$HOME/.local/go1.27.1/bin:$PATH
port=${PORT:-18443}
relay=${RELAY:-18444}
td=rpmgr-s3test01
work=$(mktemp -d)
gw_pid=""
cleanup() {
  [[ -n $gw_pid ]] && kill "$gw_pid" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

CGO_ENABLED=0 go -C "$here" build -trimpath -o "$work/s3gw" ./cmd/s3gw
CGO_ENABLED=0 go -C "$here" build -trimpath -o "$work/s3probe" ./cmd/s3probe

start_gw() { # start_gw <client>
  local res="$here/results/real-clients/$1"
  mkdir -p "$res"
  rm -f "$res"/*.jsonl "$res"/*.txt "$res"/*.json "$res"/*.log
  "$work/s3gw" -addr "127.0.0.1:$port" -relay "127.0.0.1:$relay" -certs "$work/certs" \
    -results "$res" >"$res/s3gw.log" 2>&1 &
  gw_pid=$!
  for _ in $(seq 50); do
    [[ -s $work/certs/names.txt ]] && return 0
    sleep 0.1
  done
  echo "s3gw did not start" >&2
  return 1
}
stop_gw() {
  kill -TERM "$gw_pid"
  wait "$gw_pid" || true
  gw_pid=""
  rm -rf "$work/certs"
}

run_go() {
  start_gw go
  "$work/s3probe" -addr "127.0.0.1:$port" -relay "127.0.0.1:$relay" -certs "$work/certs" \
    | tee "$here/results/real-clients/go/client.txt"
  stop_gw
}

run_curl() {
  start_gw curl
  local out="$here/results/real-clients/curl/client.txt"
  docker run --rm -u "$(id -u):$(id -g)" "$CURL_IMAGE" -V | head -n1 >"$out"
  for p in "$port" "$relay"; do
    for h in app.example.test api.example.test pass.example.test panel.example.test unknown.example.test; do
      echo "== https://$h:$p/" >>"$out"
      docker run --rm --network host -u "$(id -u):$(id -g)" -v "$work/certs:/certs:ro" "$CURL_IMAGE" \
        -sS -v --max-time 10 --cacert /certs/public-ca.pem --resolve "$h:$p:127.0.0.1" "https://$h:$p/" 2>&1 |
        grep -E 'SSL connection|ALPN: server|^(http-route|passthrough|controller)|curl: \(' >>"$out" || true
    done
    echo "== https://controller.$td:$p/ (client certificate)" >>"$out"
    docker run --rm --network host -u "$(id -u):$(id -g)" -v "$work/certs:/certs:ro" "$CURL_IMAGE" \
      -sS -v --max-time 10 --cacert /certs/internal-ca.pem --cert /certs/connector.pem --key /certs/connector.key \
      --resolve "controller.$td:$p:127.0.0.1" "https://controller.$td:$p/" 2>&1 |
      grep -E 'SSL connection|ALPN: server|^(controller)|curl: \(' >>"$out" || true
  done
  cat "$out"
  stop_gw
}

run_browser() { # run_browser chromium|firefox
  start_gw "$1"
  docker run --rm --network host -u "$(id -u):$(id -g)" -e HOME=/tmp \
    -v "$work/certs:/certs:ro" -v "$here/scripts/in-container:/scripts:ro" \
    "$PLAYWRIGHT_IMAGE" /bin/bash "/scripts/$1.sh" "$port" "$relay" \
    | tee "$here/results/real-clients/$1/client.txt"
  stop_gw
}

clients=("$@")
[[ ${#clients[@]} -eq 0 ]] && clients=(go curl chromium firefox)
for c in "${clients[@]}"; do
  case $c in
    go) run_go ;;
    curl) run_curl ;;
    chromium | firefox) run_browser "$c" ;;
    *) echo "unknown client $c" >&2; exit 2 ;;
  esac
done
go -C "$here" run ./cmd/s3summary -results "$here/results/real-clients" >"$here/results/real-clients/summary.md"
cat "$here/results/real-clients/summary.md"
