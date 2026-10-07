#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Runs spike S2 and writes the raw output to results/. Usage:
#   ./run.sh criteria           all criteria, stdlib + x/net wrapper (Go 1.27)  → results/criteria.txt
#   ./run.sh legacy             the same with -tags http2legacy (x/net's own h2) → results/criteria-legacy.txt
#   ./run.sh race               criteria with -race and smaller transfers        → results/criteria-race.txt
#   ./run.sh measure            open latency and throughput measurements         → results/measure.txt
#   ./run.sh one <regex> [-short]  one test pattern, verbose                     → results/dev-run.txt
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
export PATH=$HOME/.local/go1.27.1/bin:$PATH
mkdir -p "$here/results"
summary() { grep -E '^(--- |    --- |        --- |ok|FAIL|panic)|_test.go:[0-9]+: ' "$1" | cut -c1-300 || true; }
run() {
  local out=$1
  shift
  { go version; go -C "$here" list -m golang.org/x/net; echo "args: $*"; } >"$out"
  set +e
  go -C "$here" test -count=1 -v "$@" ./... >>"$out" 2>&1
  local rc=$?
  set -e
  summary "$out"
  echo "exit=$rc → $out"
  return $rc
}
case ${1-} in
  criteria) run "$here/results/criteria.txt" -timeout 30m ;;
  legacy) run "$here/results/criteria-legacy.txt" -tags http2legacy -timeout 30m ;;
  race) run "$here/results/criteria-race.txt" -race -timeout 30m ;;
  measure) S2_MEASURE=1 run "$here/results/measure.txt" -run 'TestMeasure' -timeout 30m ;;
  one) run "$here/results/dev-run.txt" -run "$2" "${@:3}" -timeout 15m ;;
  *) echo "usage: $0 criteria|legacy|race|measure|one <regex> [flags]" >&2; exit 2 ;;
esac
