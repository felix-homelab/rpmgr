#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Runs the root updater on a real systemd host in a container (docs/12-testing-and-quality.md,
# "Continuous integration"; slice 2.11): /var on a tmpfs, the service user's permissions, a
# replayed manifest and a hostile staging directory. Needs Docker.
#
# Usage: check-ota.sh [<repository root>]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

root=${1:-$(repo_root)}
cd "$root"
if [[ ! -f test/ota/ota_test.go ]]; then
  echo "no test/ota"
  exit 0
fi
if ! command -v docker >/dev/null; then
  fail "docker is needed for the OTA tests"
fi
if ! go test -tags ota -count=1 -timeout 20m ./test/ota/...; then
  fail "the OTA tests failed"
fi
finish
