#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Runs the benchmark suite (docs/12-testing-and-quality.md, "Benchmarks") on this host with Docker
# and writes, in the output directory, <testbed>.jsonl (the measurements), <testbed>.meta.txt (the
# host) and <testbed>.md (the tables, the targets of 03 and the regression check). The run is
# started by hand: the bench workflow on GitHub-hosted runners (D49), or this script locally.
#
#   PROFILE=smoke     one point of every workload, a few minutes: does the suite work?
#   PROFILE=standard  RTT 1 and 80 ms, loss 0 and 1 %, 3 repetitions (the default)
#   PROFILE=full      the axes of docs/12: RTT 1, 20, 80, 200 ms, loss 0, 0.5, 1, 2 %
#   BENCH_ARGS        more flags of `bench run`, such as "-gso off"
#   BASELINE          results of the last release's run on the same runners, for the regression
#                     check, which is report-only for v0.x (D49); default
#                     bench/baselines/<testbed>.jsonl if it exists
#
# Needs Docker with Compose and the go command; netem needs no privileges on the host.
#
# Usage: run-bench.sh <testbed label, e.g. gh-amd64> [<output directory, default bench-results>]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

root=$(repo_root)
testbed=${1:?a testbed label is required, e.g. gh-amd64}
out=$(realpath -m "${2:-bench-results}")
case ${PROFILE:-standard} in
smoke) args=(-rtts 1 -losses 0 -reps 1 -duration 3s -setup-duration 2s -extra-duration 6s -rate 200 -routes 20 -idle 3) ;;
standard) args=(-rtts "1,80" -losses "0,1" -reps 3 -duration 10s -setup-duration 5s -extra-duration 30s -routes 200 -idle 10) ;;
full) args=(-rtts "1,20,80,200" -losses "0,0.5,1,2" -reps 3 -duration 20s -setup-duration 10s -extra-duration 60s -routes 1000 -idle 20) ;;
*)
  fail "PROFILE is smoke, standard or full, not ${PROFILE}"
  finish
  ;;
esac
read -r -a extra <<<"${BENCH_ARGS-}"
mkdir -p "$out"
if ! (cd "$root" && go run ./bench/cmd/bench run -testbed "$testbed" -out "$out/$testbed.jsonl" "${args[@]}" "${extra[@]}"); then
  fail "the benchmark run failed (see above)"
  finish
fi
summary=(-in "$out/$testbed.jsonl")
baseline=${BASELINE:-$root/bench/baselines/$testbed.jsonl}
if [[ -f $baseline ]]; then
  summary+=(-baseline "$baseline")
else
  echo "no baseline at $baseline: no regression check"
fi
(cd "$root" && go run ./bench/cmd/bench summarize "${summary[@]}") >"$out/$testbed.md"
if [[ -n ${GITHUB_STEP_SUMMARY-} ]]; then
  cat "$out/$testbed.md" >>"$GITHUB_STEP_SUMMARY"
fi
echo "results: $out/$testbed.jsonl, summary: $out/$testbed.md"
finish
