#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Verifies the role units of `rpmgr systemd-unit` with `systemd-analyze verify`
# (docs/10-operations.md, "Hardened systemd units"): on Debian 13 (systemd 257), with the KEK as an
# encrypted credential, and on Ubuntu 22.04 (systemd 249), whose controller takes the KEK from a
# file. Needs Docker and the go command; the containers install systemd and procps (for kill), as
# standard installations have them. The work directory is removed file by file, never as a tree.
#
# Usage: check-units.sh [<repository root>] [<directory of units to verify on both>]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

root=$(cd "${1:-$(repo_root)}" && pwd)
given=${2-}
debian='debian@sha256:913f6706df59a68922d1dd08f78c2476560a8d367897200a6005b00e5f67c2d5'
ubuntu='ubuntu@sha256:5ec03bb3441e8b0bf3b4f9cd4629a1ae763010dc3035bb8da3ae6cf026486401'
work=$(mktemp -d)
cleanup() {
  rm -f "$work"/bin/rpmgr "$work"/rpmgr-host "$work"/*.yaml "$work"/credential/*.service "$work"/file/*.service
  rmdir "$work"/bin "$work"/credential "$work"/file "$work"
}
trap cleanup EXIT
mkdir -p "$work/bin" "$work/credential" "$work/file"

# A stand-in for the binary, which verify needs to find; the units name /usr/local/bin/rpmgr.
printf '#!/bin/sh\n' >"$work/bin/rpmgr"
chmod 0755 "$work/bin/rpmgr"
if [[ -n $given ]]; then
  cp "$given"/*.service "$work/credential/"
  cp "$given"/*.service "$work/file/"
else
  (cd "$root" && CGO_ENABLED=0 go build -o "$work/rpmgr-host" ./cmd/rpmgr)
  printf 'version: 1\npublic_url: https://panel.example.com\n' >"$work/credential.yaml"
  printf 'version: 1\npublic_url: https://panel.example.com\nkek: {source: file, path: /etc/rpmgr/kek}\n' >"$work/file.yaml"
  for role in gateway connector; do
    "$work/rpmgr-host" systemd-unit "$role" >"$work/credential/rpmgr-$role.service"
    cp "$work/credential/rpmgr-$role.service" "$work/file/"
  done
  "$work/rpmgr-host" systemd-unit --config "$work/credential.yaml" controller >"$work/credential/rpmgr-controller.service"
  "$work/rpmgr-host" systemd-unit --config "$work/file.yaml" controller >"$work/file/rpmgr-controller.service"
  grep -q '^LoadCredentialEncrypted=rpmgr-kek:' "$work/credential/rpmgr-controller.service" ||
    fail "the controller's unit for a credential KEK loads no credential"
  ! grep -q '^LoadCredential' "$work/file/rpmgr-controller.service" ||
    fail "the controller's unit for a KEK file loads a credential"
fi

verify() {
  local image=$1 units=$2 out
  if ! out=$(docker run --rm -v "$work/bin/rpmgr:/usr/local/bin/rpmgr:ro" -v "$units:/units:ro" "$image" sh -c \
    'apt-get update -qq >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends systemd procps >/dev/null &&
     systemctl --version | head -n 1 && systemd-analyze verify /units/*.service' 2>&1); then
    echo "$out"
    fail "systemd-analyze verify failed on $image"
    return
  fi
  echo "$out"
  # verify reports unknown settings as warnings, not errors.
  if grep -qiE 'unknown (key|lvalue)|ignoring' <<<"$out"; then
    fail "systemd on $image ignores settings of the units (see above)"
  fi
}
verify "$debian" "$work/credential"
verify "$ubuntu" "$work/file"
finish
