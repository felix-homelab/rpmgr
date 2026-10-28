#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The Go checks that need only the go command (docs/12-testing-and-quality.md, "Continuous
# integration"): formatting, a tidy go.mod, go vet, the banned TLS and QUIC settings
# (tools/bannedapi), and every test with the race detector, which needs cgo for its runtime only
# (release builds stay CGO_ENABLED=0). Lint runs in check-golangci.sh.
#
# Two environment variables, both unset locally and in the nightly run:
#   GO_TEST_CACHE=1     let go test reuse cached results (no -count=1). Pull requests set it. The
#                       tests read only files and environment variables inside the module, which
#                       the go command tracks, so a cached pass is as good as a new one; what is
#                       external is covered by the nightly run, which never caches.
#   GO_TEST_SHARD=i/n   run only the i-th of n shares of the test packages (CI runs 3 jobs in
#                       parallel); shard 1 also runs the checks that are not tests.
#
# Usage: check-go.sh [<repository root>]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

root=${1:-$(repo_root)}
cd "$root"
if [[ ! -f go.mod ]]; then
  echo "no go.mod"
  exit 0
fi

shard=${GO_TEST_SHARD-}
if ! shard_valid "$shard"; then
  fail "GO_TEST_SHARD must be <i>/<n> with 1 <= i <= n, not '$shard'"
  finish
fi
count=(-count=1)
if [[ ${GO_TEST_CACHE-} == 1 ]]; then
  count=()
fi

if shard_first "$shard"; then
  unformatted=$(git ls-files -z '*.go' | { grep -zv '/testdata/' || true; } | xargs -0 -r gofmt -l)
  if [[ -n $unformatted ]]; then
    fail "not gofmt-formatted: $unformatted"
  fi
  if ! go mod tidy -diff; then
    fail "go.mod or go.sum is not tidy; run 'go mod tidy'"
  fi
  if ! go vet ./...; then
    fail "go vet reported problems"
  fi
  if ! go run ./tools/bannedapi; then
    fail "banned TLS or QUIC settings (see above)"
  fi
fi
# internal/controller runs for nearly 10 minutes with -race on a CI runner, go test's default limit
# per package, so each package gets 20.
# Only packages with test files, so the shards deal out real work.
all=$(go list -f '{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}}{{end}}' ./... | grep -v '^$' || true)
if [[ -z $all ]]; then
  fail "go list found no packages"
  finish
fi
mapfile -t pkgs < <(sort <<<"$all" | shard_select "$shard")
echo "== tests of ${#pkgs[@]} packages (shard ${shard:-all})"
if ((${#pkgs[@]} > 0)) && ! go test -race "${count[@]}" -timeout 20m "${pkgs[@]}"; then
  fail "tests failed"
fi
# The test-only code of the rpmgrtest build (D60): vet everything with the tag, and test the
# packages that have files of their own under it.
if shard_first "$shard" && ! go vet -tags rpmgrtest ./...; then
  fail "go vet reported problems in the rpmgrtest build"
fi
mapfile -t tagged < <(git ls-files -z '*.go' | { xargs -0 -r grep -l '^//go:build rpmgrtest' || true; } |
  xargs -r -n1 dirname | sort -u | sed 's#^#./#' | shard_select "$shard")
if ((${#tagged[@]} > 0)) && ! go test -race "${count[@]}" -timeout 20m -tags rpmgrtest "${tagged[@]}"; then
  fail "tests of the rpmgrtest build failed"
fi
finish
