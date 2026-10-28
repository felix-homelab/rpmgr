# SPDX-License-Identifier: Apache-2.0
#
# Shared helpers for the repository checks in this directory. Sourced, not executed.

# fail prints an error (as a GitHub Actions annotation when running in CI) and records it.
failures=0
fail() {
  if [[ ${GITHUB_ACTIONS-} == true ]]; then
    echo "::error::$*"
  else
    echo "error: $*" >&2
  fi
  failures=$((failures + 1))
}

# finish exits non-zero if fail was called.
finish() {
  if ((failures > 0)); then
    exit 1
  fi
}

# repo_root prints the top-level directory of the git work tree that contains this script.
repo_root() {
  git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel
}

# Sharding of test packages across parallel CI jobs. A shard is "<i>/<n>" (1 <= i <= n); an empty
# one means all packages. The lines are dealt out round-robin from a sorted list, so the split is
# deterministic and the shards together cover every line exactly once. The lines that match
# SHARD_HEAVY go first, one to each of the first shards, and the other lines share the remaining
# shards, so that the slowest package does not run next to others (internal/controller alone runs
# for nearly 10 minutes with -race on a CI runner; check-go.sh splits it into two lines by test
# name, "<package>#<k>/<m>"). With no more shards than heavy lines, everything is dealt round-robin.
SHARD_HEAVY='/internal/controller(#[0-9]+/[0-9]+)?$'

# shard_valid <shard> succeeds for an empty or well-formed shard.
shard_valid() {
  [[ -z $1 ]] && return 0
  [[ $1 =~ ^([1-9][0-9]*)/([1-9][0-9]*)$ ]] && ((BASH_REMATCH[1] <= BASH_REMATCH[2]))
}

# shard_select <shard> filters the sorted lines on standard input down to the shard's own.
shard_select() {
  if [[ -z $1 ]]; then
    cat
  else
    awk -v i="${1%/*}" -v n="${1#*/}" -v heavy="$SHARD_HEAVY" '
      $0 ~ heavy { h[nh++] = $0; next }
      { o[no++] = $0 }
      END {
        for (x = 0; x < nh; x++) { if (x % n == i - 1) print h[x] }
        base = nh < n ? nh : 0
        width = n - base
        for (x = 0; x < no; x++) { if (base + x % width == i - 1) print o[x] }
      }'
  fi
}

# split_names <k> <m> reads sorted test names on standard input and prints the k-th of m parts:
# every m-th name, from the k-th. The m parts together hold every name once.
split_names() {
  awk -v k="$1" -v m="$2" 'NR % m == k % m'
}

# shard_first <shard> succeeds when there is no sharding or this is the first shard, which runs the
# checks that are not tests (formatting, vet, lint of migrations), so they run once.
shard_first() {
  [[ -z $1 || $1 == 1/* ]]
}

# The Playwright image of the browser checks, by digest; PLAYWRIGHT_VERSION is its playwright-core,
# which @playwright/test in web/package.json must equal.
export PLAYWRIGHT_IMAGE='mcr.microsoft.com/playwright:v1.63.0-noble@sha256:eff16c30e6f3f4af0a03fa4b706120d5e9b0891c344a27d64559aff5900a4a27'
export PLAYWRIGHT_VERSION=1.63.0

# The Linux architectures rpmgr is released for, as GOARCH names them and as the release artifacts
# are named; arm is armv7 (GOARM=7).
RELEASE_ARCHES=(amd64 arm64 arm riscv64)

# The platforms that get the connector-only build only (D119, D122), as <GOOS>/<GOARCH>; every
# Linux architecture above gets it too.
CONNECTOR_ONLY_PLATFORMS=(windows/amd64 darwin/amd64 darwin/arm64)

# connector_artifacts prints the names of the connector-only build's artifacts of a version, one
# per line: rpmgr-<version>-<os>-<arch>-connector, with .exe on Windows (docs/04-security.md,
# "Release signing").
connector_artifacts() {
  local p
  for p in "${RELEASE_ARCHES[@]/#/linux/}" "${CONNECTOR_ONLY_PLATFORMS[@]}"; do
    printf 'rpmgr-%s-%s-%s-connector%s\n' "$1" "${p%/*}" "${p#*/}" "$([[ ${p%/*} == windows ]] && echo .exe)"
  done
}

# release_artifacts prints the names of every artifact of a version, one per line: the full build
# for every Linux architecture, then the connector-only build. SHA256SUMS lists exactly these; the
# release check and the image workflow's download both take them from here.
release_artifacts() {
  local arch
  for arch in "${RELEASE_ARCHES[@]}"; do
    printf 'rpmgr-%s-linux-%s\n' "$1" "$arch"
  done
  connector_artifacts "$1"
}
