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
