#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Decides which CI stages a pull request needs (D64, until v1.0.0): the Go stages when it changes
# anything but documents and the web app, the web stage when it changes anything but documents,
# the tests of the repository checks when it changes anything but documents, the web app's
# sources and the Go sources, and the host checks (systemd units, install script) when it changes
# what they test. It prints go=, web=, checks=, ops= and md= (whether a Markdown file changed),
# each true or false, for $GITHUB_OUTPUT.
#
# Usage: changed-areas.sh <base commit> <head commit>   the stages a pull request needs
#        changed-areas.sh --all                         every stage (the nightly run)
#        changed-areas.sh --none                        only the stages that always run (main)
set -euo pipefail

emit() { printf 'go=%s\nweb=%s\nchecks=%s\nops=%s\nmd=%s\n' "$1" "$2" "$3" "$4" "$5"; }
case ${1-} in
  --all) emit true true true true true && exit 0 ;;
  --none) emit false false false false false && exit 0 ;;
esac
if [[ $# -ne 2 ]]; then
  echo "usage: changed-areas.sh <base> <head> | --all | --none" >&2
  exit 2
fi
files=$(git diff --name-only --no-renames "$1...$2")
go=false web=false checks=false ops=false md=false
while IFS= read -r f; do
  [[ -z $f ]] && continue
  [[ $f == *.md ]] && md=true
  case $f in
    docs/* | *.md) ;;
    web/*) web=true ;;
    *) go=true web=true ;;
  esac
  case $f in
    docs/* | *.md | web/src/* | web/e2e/* | internal/* | cmd/* | gen/* | proto/* | test/* | spikes/*) ;;
    *) checks=true ;;
  esac
  case $f in
    internal/units/* | internal/installsh/* | internal/release/* | test/installsh/* | cmd/rpmgr/* | \
      .github/scripts/check-units.sh | .github/scripts/check-install.sh) ops=true ;;
  esac
done <<<"$files"
emit "$go" "$web" "$checks" "$ops" "$md"
