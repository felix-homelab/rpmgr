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
