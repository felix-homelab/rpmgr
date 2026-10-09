#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Runs the controller's /install.sh in containers of the supported distributions (test/installsh,
# build tag installsh; docs/10-operations.md, "Supported platforms"; VB-15). Needs Docker, the go
# command and port 7383 free on this host.
#
# Usage: check-install.sh [<repository root>]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

root=$(cd "${1:-$(repo_root)}" && pwd)
if ! (cd "$root" && go test -count=1 -tags installsh -timeout 20m ./test/installsh/); then
  fail "the install script failed on a distribution (see above)"
fi
finish
