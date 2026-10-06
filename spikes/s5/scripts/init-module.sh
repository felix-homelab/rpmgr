#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# How the spike's go.mod was created, with the pinned versions (D39). go.mod and go.sum are
# committed; this script only documents the steps.
set -euo pipefail
dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$dir"
[[ -f go.mod ]] || go mod init github.com/felix-homelab/rpmgr/spikes/s5
go mod edit -toolchain=go1.27.1
go get -tool entgo.io/ent/cmd/ent@v0.14.6
# Ent v0.14.6 requires an x/tools that cannot load packages with Go 1.27; raise it.
go get golang.org/x/tools@v0.51.0
# Ent v0.14.6 requires a pre-release of ariga.io/atlas; pin the current release explicitly, or
# `go mod tidy` falls back to Ent's requirement.
go get ariga.io/atlas@v1.3.0 entgo.io/ent@v0.14.6 modernc.org/sqlite@v1.60.1 \
  github.com/jackc/pgx/v5@v5.11.0 github.com/google/uuid@v1.6.0
go mod tidy
