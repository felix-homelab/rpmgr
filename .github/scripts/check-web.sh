#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Checks the web UI in web/ (docs/12-testing-and-quality.md, "Continuous integration"): installs
# its dependencies from the lockfile without running install scripts, audits them, lints,
# type-checks, runs the unit tests and builds it without warnings; then the Go tests of
# internal/webui check the build that the controller embeds. Needs the Node major version of
# web/.nvmrc with npm, network access for npm and buf, and Go.
#
# Usage: check-web.sh [<repository root>]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

root=${1:-$(repo_root)}
web=$root/web
[[ -f $web/package.json && -f $web/package-lock.json ]] || { fail "web/package.json or its lockfile is missing"; finish; }
want=$(<"$web/.nvmrc")
command -v npm >/dev/null || { fail "npm is not installed (Node $want, web/.nvmrc)"; finish; }
have=$(node -p 'process.versions.node.split(".")[0]')
[[ $have == "$want" ]] || { fail "Node $have, want Node $want (web/.nvmrc)"; finish; }

step() {
  echo "== $1"
  shift
  "$@" || fail "$*"
}
step "install from the lockfile" npm --prefix "$web" ci --ignore-scripts --no-fund --no-audit
# Any advisory of a dependency that reaches the browser fails; of a build or test tool, high and
# critical ones do.
step "audit of the UI's dependencies" npm --prefix "$web" audit --omit=dev --audit-level=low
step "audit of the build and test tools" npm --prefix "$web" audit --audit-level=high
step "lint" npm --prefix "$web" run lint
step "type check" npm --prefix "$web" run typecheck
step "unit tests" npm --prefix "$web" test
echo "== build"
if out=$(npm --prefix "$web" run build 2>&1); then
  echo "$out" | tail -n 15
  if grep -qE '^\(!\)|[Ww]arning:' <<<"$out"; then
    fail "the build warned: $(grep -m1 -E '^\(!\)|[Ww]arning:' <<<"$out")"
  fi
else
  echo "$out"
  fail "the build failed"
fi
step "the embedded build (internal/webui)" go -C "$root" test -count=1 ./internal/webui/
finish
