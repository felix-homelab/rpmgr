#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Checks the release artifacts of one version in a directory (RELEASING.md, "Release process"):
# one rpmgr-<version>-linux-<arch> per released architecture and a SHA256SUMS that lists exactly
# them, and nothing else; each a build of ./cmd/rpmgr for its platform, with the Go toolchain that
# go.mod pins, CGO_ENABLED=0, -trimpath and no build tags, stamped with the version and commit. A
# build with the rpmgrtest tag is refused (D60). The artifact of this host's architecture is also
# run: `rpmgr version --verbose` must name the version and commit and no test root keys; with
# REQUIRE_ROOTS=1, as on release tags, it must name release root keys, which it prints for the
# signer to compare with the record of the key ceremony (D48). Needs Go.
#
# Usage: check-release-artifacts.sh <directory> <version> <commit> [<repository root>]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

dir=${1:?directory required} version=${2:?version required} commit=${3:?commit required}
root=${4:-$(repo_root)}
pinned=$(sed -n 's/^toolchain //p' "$root/go.mod")

want=(SHA256SUMS)
for arch in "${RELEASE_ARCHES[@]}"; do
  want+=("rpmgr-$version-linux-$arch")
done
have=$(find "$dir" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)
if [[ $have != "$(printf '%s\n' "${want[@]}" | sort)" ]]; then
  fail "$dir holds $(echo "$have" | paste -sd ' '), want $(printf '%s\n' "${want[@]}" | sort | paste -sd ' ')"
  finish
fi
if [[ $(awk '{ print $2 }' "$dir/SHA256SUMS" | sort) != "$(printf '%s\n' "${want[@]:1}" | sort)" ]]; then
  fail "SHA256SUMS does not list exactly the artifacts"
fi
if ! (cd "$dir" && sha256sum --quiet --strict -c SHA256SUMS); then
  fail "an artifact does not match SHA256SUMS"
fi

has() { grep -qxF -- "$2" <<<"$1"; }
for arch in "${RELEASE_ARCHES[@]}"; do
  f=$dir/rpmgr-$version-linux-$arch
  if ! info=$(go version -m "$f" 2>&1); then
    fail "$f is not a Go binary: $info"
    continue
  fi
  for line in "$f: $pinned" $'\tpath\tgithub.com/felix-homelab/rpmgr/cmd/rpmgr' $'\tbuild\tCGO_ENABLED=0' \
    $'\tbuild\t-trimpath=true' $'\tbuild\tGOOS=linux' $'\tbuild\tGOARCH='"$arch"; do
    has "$info" "$line" || fail "$f: no '${line//$'\t'/ }' in its build information"
  done
  if grep -q $'^\tbuild\t-tags=' <<<"$info"; then
    fail "$f was built with build tags: $(grep $'^\tbuild\t-tags=' <<<"$info" | cut -f3)"
  fi
  # -trimpath keeps -ldflags out of the build information; the stamped strings are in the data.
  if ! grep -qaF -- "$commit" "$f" || ! grep -qaF -- "$version" "$f"; then
    fail "$f is not stamped with version $version and commit $commit"
  fi
done
finish

host=$(GOENV=off go env GOOS)/$(GOENV=off go env GOARCH)
if [[ $host != linux/* || ! -f $dir/rpmgr-$version-linux-${host#linux/} ]]; then
  echo "skipped: running the artifact of $host (none)"
  exit 0
fi
out=$("$dir/rpmgr-$version-$(tr / - <<<"$host")" version --verbose)
echo "$out"
if [[ $(head -n 1 <<<"$out") != "rpmgr $version (commit $commit, $pinned, $host)" ]]; then
  fail "the $host artifact reports another version, commit or toolchain"
fi
if grep -q '^test release root keys' <<<"$out"; then
  fail "the $host artifact carries the test root keys of an rpmgrtest build (D60)"
fi
if [[ ${REQUIRE_ROOTS-} == 1 ]] && grep -q '^release root keys: none' <<<"$out"; then
  fail "the $host artifact carries no release root keys; add the interim keys first (D48, RELEASING.md)"
fi
finish
