#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The protobuf checks (docs/12-testing-and-quality.md, "Continuous integration"): buf lint; buf
# breaking against the base branch, which a PR labelled `breaking` with `!` in its title may pass
# before v1.0.0 (ALLOW_BREAKING=1, D56); and generated code that matches the .proto files. buf runs
# at a pinned version through the go command; the code generators are tool dependencies in go.mod.
#
# Usage: check-buf.sh [<repository root>]
#   BUF_BREAKING_AGAINST  git ref to compare with (default origin/main)
#   ALLOW_BREAKING=1      report breaking changes without failing
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

root=${1:-$(repo_root)}
version=v1.73.0 # github.com/bufbuild/buf; updated by hand like the tool images
against=${BUF_BREAKING_AGAINST:-origin/main}
cd "$root"
if [[ ! -f buf.yaml ]]; then
  echo "no buf.yaml"
  exit 0
fi
buf() { go run "github.com/bufbuild/buf/cmd/buf@$version" "$@"; }

if ! buf lint; then
  fail "buf lint reported problems"
fi

if base=$(git rev-parse --verify --quiet "$against^{commit}") && git cat-file -e "$base:buf.yaml" 2>/dev/null; then
  if ! buf breaking --against ".git#ref=$base"; then
    if [[ ${ALLOW_BREAKING-} == 1 ]]; then
      echo "breaking changes allowed: the PR is labelled 'breaking' and its title has '!' (D56)"
    else
      fail "breaking changes against $against; before v1.0.0 only a PR labelled 'breaking' with '!' in its title may make them (D56)"
    fi
  fi
else
  echo "no buf.yaml on $against; nothing to compare for breaking changes"
fi

if ! buf generate; then
  fail "buf generate failed"
elif drift=$(git diff --name-only -- gen; git ls-files --others --exclude-standard -- gen) && [[ -n $drift ]]; then
  echo "$drift"
  fail "generated code does not match the .proto files; run 'buf generate' and commit gen/"
fi
finish
