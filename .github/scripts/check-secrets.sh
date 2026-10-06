#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Scans the git history for secrets with gitleaks, using the default rules plus rpmgr's token
# rules from .gitleaks.toml (docs/12-testing-and-quality.md, "Security testing"). Needs Docker.
#
# Usage: check-secrets.sh [<repository root or directory>] [git|dir]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

root=${1:-$(repo_root)}
mode=${2:-git}
config=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/.gitleaks.toml
image='ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f'

if ! docker run --rm -u "$(id -u):$(id -g)" -v "$root:/scan:ro" -v "$config:/gitleaks.toml:ro" \
  -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0='*' \
  "$image" "$mode" --config /gitleaks.toml --redact --no-banner --exit-code 1 /scan; then
  fail "gitleaks found a secret, or could not run (see its report above)"
fi
finish
