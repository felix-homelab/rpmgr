#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Renders every ```mermaid block of the repository's Markdown files with mermaid-cli, so a
# diagram that GitHub cannot render fails CI (docs/12-testing-and-quality.md, "Continuous
# integration"). Needs Docker.
#
# Usage: check-mermaid.sh [<repository root>]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

root=${1:-$(repo_root)}
image='mirror.gcr.io/minlag/mermaid-cli:12.0.0@sha256:fa995339034aae7e5cd4f61482248b7f5c51be355b1a6f6eda11a2bbf8401f5f'
work=$(mktemp -d)
# Only files are created in $work (<n>.mmd, <n>.svg, <n>.log, index.txt), so they are removed by
# name and the directory with rmdir; nothing here deletes a tree.
trap 'rm "$work"/* 2>/dev/null; rmdir "$work"' EXIT
chmod 0777 "$work" # the image runs as its own unprivileged user

# Extract each block into <n>.mmd and record "<n> <file>:<line>" in index.txt.
n=0
while IFS= read -r -d '' f; do
  [[ $f == *.md ]] || continue
  n=$(awk -v out="$work" -v file="$f" -v n="$n" '
    /^```mermaid[[:space:]]*$/ { inside = 1; n++; start = NR; next }
    inside && /^```[[:space:]]*$/ { inside = 0; printf "%d %s:%d\n", n, file, start >> (out "/index.txt"); next }
    inside { print > (out "/" n ".mmd") }
    END { print n }
  ' "$root/$f")
done < <(git -C "$root" ls-files -z)

if ((n == 0)); then
  echo "no Mermaid diagrams found"
  exit 0
fi

# One container renders all diagrams; it prints the numbers of the diagrams that failed.
failed=$(docker run --rm -v "$work:/data" --entrypoint sh "$image" -c '
  for f in /data/*.mmd; do
    i=$(basename "$f" .mmd)
    if ! /home/mermaidcli/node_modules/.bin/mmdc -p /puppeteer-config.json -q \
        -i "$f" -o "/data/$i.svg" >"/data/$i.log" 2>&1; then
      echo "$i"
    fi
  done')

for i in $failed; do
  where=$(awk -v i="$i" '$1 == i { print $2 }' "$work/index.txt")
  fail "$where: Mermaid diagram does not render: $(grep -m1 -iE 'error|expect' "$work/$i.log" || head -n1 "$work/$i.log")"
done
if ((failures == 0)); then
  echo "rendered $n Mermaid diagrams"
fi
finish
