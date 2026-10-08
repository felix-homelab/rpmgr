#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The Go checks that need only the go command (docs/12-testing-and-quality.md, "Continuous
# integration"): formatting, a tidy go.mod, go vet, the banned TLS and QUIC settings
# (tools/bannedapi), and every test with the race detector, which needs cgo for its runtime only
# (release builds stay CGO_ENABLED=0). Lint runs in check-golangci.sh.
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
if ! go test -race -count=1 ./...; then
  fail "tests failed"
fi
# The test-only code of the rpmgrtest build (D60): vet everything with the tag, and test the
# packages that have files of their own under it.
if ! go vet -tags rpmgrtest ./...; then
  fail "go vet reported problems in the rpmgrtest build"
fi
tagged=$(git ls-files -z '*.go' | { xargs -0 -r grep -l '^//go:build rpmgrtest' || true; } | xargs -r -n1 dirname | sort -u |
  sed 's#^#./#')
if [[ -n $tagged ]] && ! go test -race -count=1 -tags rpmgrtest $tagged; then
  fail "tests of the rpmgrtest build failed"
fi
finish
