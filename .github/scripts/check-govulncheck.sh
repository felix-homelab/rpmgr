#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Reports known vulnerabilities in the code paths rpmgr actually calls, with govulncheck and the
# Go vulnerability database (docs/12-testing-and-quality.md, "Security testing"). Runs on every PR
# and nightly, so a newly published vulnerability is found without a code change. Needs network.
#
# Usage: check-govulncheck.sh [<repository root>]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

root=${1:-$(repo_root)}
version=v1.8.0 # golang.org/x/vuln; updated by hand like the tool images
cd "$root"
if [[ ! -f go.mod ]]; then
  echo "no go.mod"
  exit 0
fi
if ! go run "golang.org/x/vuln/cmd/govulncheck@$version" ./...; then
  fail "govulncheck found vulnerabilities in called code, or could not run (see above)"
fi
finish
