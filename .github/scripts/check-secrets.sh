#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Scans the git history for secrets with gitleaks, using the default rules plus rpmgr's token
# rules from .gitleaks.toml (docs/12-testing-and-quality.md, "Security testing"). Needs Docker.
#
# Usage: check-secrets.sh [<repository root or directory>] [git|dir]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

root=$(cd "${1:-$(repo_root)}" && pwd)
mode=${2:-git}
config=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/.gitleaks.toml
image='ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f'

# A worktree's .git file names the repository's git directory by its host path, so the scanned
# directory and that git directory are mounted at their host paths. Otherwise gitleaks reads no
# history, logs an error and still reports no leaks; an error therefore fails the check too.
mounts=(-v "$root:$root:ro")
if [[ $mode == git ]]; then
  common=$(git -C "$root" rev-parse --path-format=absolute --git-common-dir)
  [[ $common == "$root"/* ]] || mounts+=(-v "$common:$common:ro")
fi
report=$(mktemp)
trap 'rm "$report"' EXIT
if ! docker run --rm -u "$(id -u):$(id -g)" "${mounts[@]}" -v "$config:/gitleaks.toml:ro" \
  -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0='*' \
  "$image" "$mode" --config /gitleaks.toml --redact --no-banner --no-color --exit-code 1 "$root" 2>&1 | tee "$report"; then
  fail "gitleaks found a secret, or could not run (see its report above)"
elif grep -q ' ERR ' "$report"; then
  fail "gitleaks reported an error (see its report above)"
fi
finish
