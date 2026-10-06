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
