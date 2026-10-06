#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Checks that every tracked source file names its license with an SPDX identifier in its first
# five lines (CONTRIBUTING.md, "License, sign-off and third-party code"). Generated files
# ("Code generated ... DO NOT EDIT."), test data, migrations and vendored code are exempt.
#
# Usage: check-spdx.sh [<repository root>]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

root=${1:-$(repo_root)}
sources='\.(go|proto|ts|tsx|js|jsx|mjs|cjs|sh|bash|py|sql|css)$'
exempt='(^|/)(testdata|node_modules|vendor|migrations)/'

while IFS= read -r -d '' f; do
  [[ $f =~ $sources ]] || continue
  [[ $f =~ $exempt ]] && continue
  [[ -f $root/$f ]] || continue # deleted in the work tree
  if head -n 10 "$root/$f" | grep -qE 'Code generated .* DO NOT EDIT\.'; then
    continue
  fi
  if ! head -n 5 "$root/$f" | grep -q 'SPDX-License-Identifier: Apache-2.0'; then
    fail "$f: no 'SPDX-License-Identifier: Apache-2.0' header in its first five lines"
  fi
done < <(git -C "$root" ls-files -z)
finish
