#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Builds the release artifacts of one version (RELEASING.md, "Release process"): the web UI from
# its lockfile, when the repository has one, then rpmgr for every released platform with
# CGO_ENABLED=0, -trimpath, no build tags, no VCS stamp and the Go toolchain that go.mod pins, so
# two builds of the same commit are equal byte for byte. The environment cannot add build tags:
# GOFLAGS and the go env file are ignored, so no rpmgrtest build can become a release (D60).
# Writes rpmgr-<version>-linux-<arch> and SHA256SUMS into the output directory, which must not
# exist, and checks them with check-release-artifacts.sh. Needs Go, and for the web UI the Node
# version of web/.nvmrc with npm and network access for npm.
#
# Usage: build-release.sh <version> <commit> <output directory> [<repository root>]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

version=${1:?version required} commit=${2:?commit required} out=${3:?output directory required}
root=${4:-$(repo_root)}

if ! [[ $version =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.]+)?$ ]]; then
  fail "version '$version' is not a semantic version without a leading v"
fi
[[ $commit =~ ^[0-9a-f]{40}$ ]] || fail "commit '$commit' is not a full commit hash"
if [[ -e $out ]]; then
  fail "$out exists already"
fi
finish

# A go env file (go env -w) could set GOFLAGS, GOAMD64 and others: none counts.
export GOENV=off
unset GOFLAGS GOEXPERIMENT
pinned=$(sed -n 's/^toolchain //p' "$root/go.mod")
have=$(go -C "$root" env GOVERSION)
if [[ -z $pinned || $have != "$pinned" ]]; then
  fail "Go $have, want the toolchain go.mod pins ('${pinned:-none}')"
  finish
fi

if [[ -f $root/web/package.json ]]; then
  want=$(<"$root/web/.nvmrc")
  node=$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || true)
  [[ $node == "$want" ]] || { fail "Node '${node:-none}', want Node $want (web/.nvmrc)"; finish; }
  echo "== web UI"
  npm --prefix "$root/web" ci --ignore-scripts --no-fund --no-audit
  npm --prefix "$root/web" run build
fi

mkdir -p "$out"
ldflags="-s -w -buildid= -X github.com/felix-homelab/rpmgr/internal/version.Version=$version"
ldflags+=" -X github.com/felix-homelab/rpmgr/internal/version.Commit=$commit"
for arch in "${RELEASE_ARCHES[@]}"; do
  name=rpmgr-$version-linux-$arch
  echo "== $name"
  # The micro-architecture levels are the Go defaults, set so the environment cannot change them.
  env CGO_ENABLED=0 GOOS=linux GOARCH="$arch" GOAMD64=v1 GOARM64=v8.0 GOARM=7 GORISCV64=rva20u64 \
    go -C "$root" build -trimpath -buildvcs=false -ldflags "$ldflags" -o "$(realpath "$out")/$name" ./cmd/rpmgr ||
    fail "the build of $name failed"
done
finish
(cd "$out" && sha256sum -- rpmgr-* >SHA256SUMS)
cat "$out/SHA256SUMS"
"$(dirname "${BASH_SOURCE[0]}")/check-release-artifacts.sh" "$out" "$version" "$commit" "$root"
