#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Creates the spike's Go module with the pinned dependency versions (D39). Run once.
set -euo pipefail
dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$dir"
[[ -f go.mod ]] || go mod init github.com/felix-homelab/rpmgr/spikes/s5
go get entgo.io/ent@v0.14.6 ariga.io/atlas@v1.3.0 modernc.org/sqlite@v1.60.1 \
  github.com/jackc/pgx/v5@v5.11.0 github.com/google/uuid@v1.6.0
go mod edit -toolchain=go1.27.1
