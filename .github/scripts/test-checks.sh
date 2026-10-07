#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests for the repository checks in this directory: valid input must pass, invalid input and
# boundary violations must fail. Tests of the Docker-based checks are skipped when Docker is
# missing, unless REQUIRE_DOCKER=1 (as in CI). The test repositories are created under one
# directory in $TMPDIR, which is printed at the end and not deleted: the script never deletes
# directory trees.
#
# Usage: test-checks.sh
set -euo pipefail
shopt -s inherit_errexit # a failing command substitution stops the script too
export LC_ALL=C.UTF-8
# Test commits take their identity and settings from the environment, so the script never writes a
# git configuration, not even by accident in the repository that contains it.
export GIT_AUTHOR_NAME="Test Author" GIT_AUTHOR_EMAIL="author@example.org"
export GIT_COMMITTER_NAME="Test Author" GIT_COMMITTER_EMAIL="author@example.org"
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=commit.gpgsign GIT_CONFIG_VALUE_0=false
dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
passed=0
failed=0
tmproot=$(mktemp -d "${TMPDIR:-/tmp}/rpmgr-check-tests.XXXXXX")

# expect pass|fail "<description>" <command> [args...]
expect() {
  local want=$1 desc=$2 got
  shift 2
  if "$@" >/dev/null 2>&1; then got=pass; else got=fail; fi
  if [[ $got == "$want" ]]; then
    passed=$((passed + 1))
  else
    echo "FAIL: $desc: expected $want, got $got"
    failed=$((failed + 1))
  fi
}

# new_repo prints the path of a fresh git repository with one commit on main.
new_repo() {
  local r
  r=$(mktemp -d "$tmproot/repo.XXXXXX")
  # An empty path would make "git -C" act on the current directory's repository.
  if [[ -z $r || ! -d $r || $r != "$tmproot"/* ]]; then
    echo "new_repo: no temporary directory (got '$r')" >&2
    exit 1
  fi
  git -C "$r" init -q -b main
  echo base >"$r/file.txt"
  git -C "$r" add file.txt
  git -C "$r" commit -q -s -m "chore: base"
  echo "$r"
}
in_repo() { (cd "$1" && shift && "$@"); }

# --- PR title ------------------------------------------------------------------------------
t="$dir/check-pr-title.sh"
for ok in "ci: add repository-rule and documentation checks" \
  "feat(dns)!: publish route hostnames" \
  "docs(adr): accept ADR-0005 after spike S2" \
  "revert: feat(dns): publish route hostnames" \
  'fix(tunnel): reject `StreamOpen` without a route' \
  "chore(release): v1.4.0" \
  "build(deps): bump golang.org/x/net from 0.57.0 to 0.59.0" \
  "ci(deps): bump actions/checkout from 7.0.1 to 7.0.2" \
  "feat: $(printf 'a%.0s' {1..66})"; do
  expect pass "title '$ok'" "$t" "$ok"
done
for bad in "" "Add feature" "feat: Add thing" "feat: add thing." "feature: add thing" \
  "feat(unknown): add thing" "feat (dns): add thing" "feat:add thing" "feat: add  thing" \
  "feat: add thing " "feat(): add thing" "FEAT: add thing" \
  "feat: $(printf 'a%.0s' {1..67})"; do
  expect fail "title '$bad'" "$t" "$bad"
done

# --- Branch names --------------------------------------------------------------------------
b="$dir/check-branch-name.sh"
for ok in feature/42-dns-automation bugfix/57-etag-mismatch-on-retry improvement/contribution-rules \
  merge/release-1.4-into-main feature/1-s2-reverse-h2-result improvement/v1.2-notes \
  dependabot/github_actions/actions/checkout-7.0.2 \
  "improvement/$(printf 'a%.0s' {1..48})"; do
  expect pass "branch '$ok'" "$b" "$ok" main
done
expect pass "backport to a release branch" "$b" bugfix/57-etag-mismatch-on-retry-1.4 release/1.4
for bad in tmp/s2-reverse-h2 feature/dns-automation Feature/42-dns feature/42-dns_automation \
  improvement/x--y improvement/-x release/1.4 foo/bar feature/42- main \
  "improvement/$(printf 'a%.0s' {1..49})"; do
  expect fail "branch '$bad'" "$b" "$bad" main
done
expect fail "base branch develop" "$b" feature/42-dns develop
expect fail "base branch release/1.x" "$b" feature/42-dns release/1.x

# --- Changelog -----------------------------------------------------------------------------
r=$(new_repo)
base=$(git -C "$r" rev-parse HEAD)
git -C "$r" switch -q -c feature/1-x
echo change >>"$r/file.txt"
git -C "$r" commit -q -s -am "feat: change"
nochange=$(git -C "$r" rev-parse HEAD)
echo "- entry" >"$r/CHANGELOG.md"
git -C "$r" add CHANGELOG.md
git -C "$r" commit -q -s -m "docs: changelog"
withentry=$(git -C "$r" rev-parse HEAD)
c="$dir/check-changelog.sh"
expect fail "no CHANGELOG change, no label" in_repo "$r" "$c" "$base" "$nochange" ""
expect fail "no CHANGELOG change, similar label" in_repo "$r" "$c" "$base" "$nochange" "no-changelog-x type:docs"
expect pass "no CHANGELOG change, no-changelog label" in_repo "$r" "$c" "$base" "$nochange" "type:docs no-changelog"
expect pass "CHANGELOG changed" in_repo "$r" "$c" "$base" "$withentry" ""

# --- DCO -----------------------------------------------------------------------------------
d="$dir/check-dco.sh"
r=$(new_repo)
base=$(git -C "$r" rev-parse HEAD)
git -C "$r" switch -q -c feature/1-x
echo 1 >>"$r/file.txt" && git -C "$r" commit -q -s -am "feat: signed"
signed=$(git -C "$r" rev-parse HEAD)
expect pass "signed-off commit" in_repo "$r" "$d" "$base" "$signed"
echo 2 >>"$r/file.txt" && git -C "$r" commit -q -am "feat: unsigned"
expect fail "commit without sign-off" in_repo "$r" "$d" "$base" "$(git -C "$r" rev-parse HEAD)"
git -C "$r" reset -q --hard "$signed"
echo 3 >>"$r/file.txt"
git -C "$r" commit -q -am "feat: wrong signer" -m "Signed-off-by: Someone Else <else@example.org>"
expect fail "sign-off by someone else" in_repo "$r" "$d" "$base" "$(git -C "$r" rev-parse HEAD)"
git -C "$r" reset -q --hard "$signed"
echo 4 >>"$r/file.txt"
GIT_AUTHOR_NAME="dependabot[bot]" GIT_AUTHOR_EMAIL="49699333+dependabot[bot]@users.noreply.github.com" \
  git -C "$r" commit -q -am "ci(deps): bump x"
expect pass "dependency-bot commit without sign-off" in_repo "$r" "$d" "$base" "$(git -C "$r" rev-parse HEAD)"
git -C "$r" reset -q --hard "$signed"
git -C "$r" switch -q main && echo m >"$r/main.txt" && git -C "$r" add main.txt && git -C "$r" commit -q -s -m "chore: main"
git -C "$r" switch -q feature/1-x && git -C "$r" merge -q --no-edit main
expect pass "merge commit of main without sign-off" in_repo "$r" "$d" "$base" "$(git -C "$r" rev-parse HEAD)"

# --- Commit headers ------------------------------------------------------------------------
m="$dir/check-commits.sh"
r=$(new_repo)
base=$(git -C "$r" rev-parse HEAD)
git -C "$r" switch -q -c feature/1-x
echo 1 >>"$r/file.txt" && git -C "$r" commit -q -s -am "feat(dns): publish route hostnames"
good=$(git -C "$r" rev-parse HEAD)
expect pass "Conventional Commit headers" in_repo "$r" "$m" "$base" "$good"
git -C "$r" switch -q main && echo m >"$r/main.txt" && git -C "$r" add main.txt && git -C "$r" commit -q -s -m "chore: main"
git -C "$r" switch -q feature/1-x && git -C "$r" merge -q --no-edit main
expect pass "merge of main with Git's default message" in_repo "$r" "$m" "$base" "$(git -C "$r" rev-parse HEAD)"
echo 2 >>"$r/file.txt" && git -C "$r" commit -q -s -am "fix review comments"
expect fail "commit header that is not a Conventional Commit" in_repo "$r" "$m" "$base" "$(git -C "$r" rev-parse HEAD)"
git -C "$r" reset -q --hard "$good"
echo 3 >>"$r/file.txt" && git -C "$r" commit -q -s -am "fixup! feat(dns): publish route hostnames"
expect fail "fix-up commit" in_repo "$r" "$m" "$base" "$(git -C "$r" rev-parse HEAD)"

# --- SPDX headers --------------------------------------------------------------------------
s="$dir/check-spdx.sh"
r=$(new_repo)
printf '// SPDX-License-Identifier: Apache-2.0\npackage a\n' >"$r/a.go"
printf '#!/bin/sh\n# SPDX-License-Identifier: Apache-2.0\necho\n' >"$r/a.sh"
printf '// Code generated by protoc-gen-go. DO NOT EDIT.\npackage a\n' >"$r/a.pb.go"
mkdir -p "$r/testdata" "$r/migrations" && echo "package t" >"$r/testdata/t.go" && echo "SELECT 1;" >"$r/migrations/1.sql"
echo "# no header needed" >"$r/README.md"
git -C "$r" add -A
expect pass "headers present, exempt files skipped" "$s" "$r"
printf 'package b\n' >"$r/b.go" && git -C "$r" add b.go
expect fail "Go file without header" "$s" "$r"
git -C "$r" rm -q --cached b.go && rm "$r/b.go"
printf '#!/bin/sh\n\n\n\n\n# SPDX-License-Identifier: Apache-2.0\n' >"$r/late.sh" && git -C "$r" add late.sh
expect fail "header after line five" "$s" "$r"

# --- Go checks (need the go command) ----------------------------------------------------------
if ! command -v go >/dev/null 2>&1; then
  if [[ ${REQUIRE_GO-} == 1 ]]; then
    echo "FAIL: the go command is required but not available"
    failed=$((failed + 1))
  else
    echo "skipped: Go checks (go not available)"
  fi
else
  # A tiny module with the real tools/bannedapi, so check-go.sh runs exactly as in the repository.
  r=$(new_repo)
  printf 'module github.com/felix-homelab/rpmgr\n\ngo 1.26.0\n' >"$r/go.mod"
  mkdir -p "$r/p" "$r/tools"
  cp -r "$dir/../../tools/bannedapi" "$r/tools/"
  printf '// SPDX-License-Identifier: Apache-2.0\n\npackage p\n\n// Add adds.\nfunc Add(a, b int) int { return a + b }\n' >"$r/p/p.go"
  cat >"$r/p/p_test.go" <<'EOF'
package p

import "testing"

func TestAdd(t *testing.T) {
	if Add(1, 2) != 3 {
		t.Fatal("Add")
	}
}

func FuzzAdd(f *testing.F) {
	f.Add(1, 2)
	f.Fuzz(func(t *testing.T, a, b int) {
		if Add(a, b) != Add(b, a) {
			t.Fatal("not commutative")
		}
	})
}
EOF
  git -C "$r" add -A
  g="$dir/check-go.sh"
  expect pass "Go module that is formatted, vetted and tested" "$g" "$r"
  expect pass "fuzz smoke run" "$dir/check-fuzz.sh" 1s "$r"
  printf 'package p\nfunc  Bad( ) {}\n' >"$r/p/bad.go" && git -C "$r" add -A
  expect fail "unformatted Go file" "$g" "$r"
  printf 'package p\n\nimport "fmt"\n\nfunc Bad() { fmt.Printf("%%d\\n", "x") }\n' >"$r/p/bad.go"
  expect fail "go vet finding" "$g" "$r"
  printf 'package p\n\nimport "crypto/tls"\n\nvar C = &tls.Config{InsecureSkipVerify: true}\n' >"$r/p/bad.go"
  expect fail "banned TLS setting in a composite literal" "$g" "$r"
  git -C "$r" rm -q -f p/bad.go
  printf 'package p\n\nimport "testing"\n\nfunc TestFails(t *testing.T) { t.Fatal("boom") }\n' >"$r/p/fail_test.go"
  git -C "$r" add -A
  expect fail "failing test" "$g" "$r"
  git -C "$r" rm -q -f p/fail_test.go
  cat >"$r/p/crash_test.go" <<'EOF'
package p

import "testing"

func FuzzCrash(f *testing.F) {
	f.Add(7)
	f.Fuzz(func(t *testing.T, a int) {
		if a != 7 {
			panic("crash")
		}
	})
}
EOF
  git -C "$r" add -A
  expect fail "fuzz target that crashes" "$dir/check-fuzz.sh" 2s "$r"
fi

# --- Docker-based checks -------------------------------------------------------------------
if ! docker info >/dev/null 2>&1; then
  if [[ ${REQUIRE_DOCKER-} == 1 ]]; then
    echo "FAIL: Docker is required but not available"
    failed=$((failed + 1))
  else
    echo "skipped: Docker-based checks (Docker not available)"
  fi
else
  # Links and anchors.
  r=$(new_repo)
  printf '# Title\n\n## Phase 0 — spikes\n\n[ok](#phase-0--spikes) [file](b.md)\n' >"$r/a.md"
  printf '# B\n' >"$r/b.md"
  git -C "$r" add -A
  expect pass "valid links and anchors" "$dir/check-links.sh" "$r"
  printf '[bad](a.md#phase-0-spikes)\n' >"$r/c.md" && git -C "$r" add c.md
  expect fail "broken anchor" "$dir/check-links.sh" "$r"
  printf '[bad](missing.md)\n' >"$r/c.md"
  expect fail "missing file" "$dir/check-links.sh" "$r"

  # Mermaid.
  r=$(new_repo)
  printf '# A\n\n```mermaid\nflowchart LR\n  A --> B\n```\n' >"$r/a.md" && git -C "$r" add a.md
  expect pass "valid Mermaid diagram" "$dir/check-mermaid.sh" "$r"
  printf '# B\n\n```mermaid\nflowchart LR\n  A -->\n```\n' >"$r/b.md" && git -C "$r" add b.md
  expect fail "invalid Mermaid diagram" "$dir/check-mermaid.sh" "$r"

  # Secrets: a well-formed fake token is found; the documented format is not. The token is
  # assembled at runtime so that this file itself never contains one.
  r=$(mktemp -d "$tmproot/dir.XXXXXX")
  echo 'token format: rpmgr_enr_<base62(32 random bytes)>_<6-char CRC32 checksum>' >"$r/doc.md"
  expect pass "documented token format is not a secret" "$dir/check-secrets.sh" "$r" dir
  printf 'token = "%s_%s_%s_%s"\n' rpmgr enr "$(printf 'k7Q2%.0s' {1..10})Zx9" "aB3dE5" >"$r/leak.txt"
  expect fail "rpmgr token detected" "$dir/check-secrets.sh" "$r" dir

  # Workflows: pinned actions pass, a tag fails.
  r=$(new_repo)
  mkdir -p "$r/.github/workflows"
  cat >"$r/.github/workflows/w.yml" <<'EOF'
name: w
on: push
permissions: {}
jobs:
  j:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
EOF
  git -C "$r" add -A
  expect pass "actions pinned by SHA" "$dir/check-workflows.sh" "$r"
  sed -i 's/@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1/@v7/' "$r/.github/workflows/w.yml"
  expect fail "action pinned by tag" "$dir/check-workflows.sh" "$r"
  # golangci-lint: the repository's .golangci.yml on a clean module, then one broken rule at a
  # time. Needs the go command for the module cache it mounts.
  if command -v go >/dev/null 2>&1; then
    r=$(new_repo)
    cp -r "$dir/testdata/golint/." "$r/"
    cp "$dir/../../.golangci.yml" "$r/"
    git -C "$r" add -A
    gl="$dir/check-golangci.sh"
    expect pass "golangci-lint on a clean module" "$gl" "$r"
    lint_case() { # lint_case <description> <file> <content>
      mkdir -p "$r/$(dirname "$2")"
      printf '%s\n' "$3" >"$r/$2"
      expect fail "$1" "$gl" "$r"
      rm "$r/$2"
    }
    lint_case "math/rand in internal/pki" internal/pki/rand.go \
      $'package pki\n\nimport "math/rand"\n\n// N is not random enough.\nfunc N() int { return rand.Int() }'
    lint_case "math/rand/v2 in internal/token" internal/token/rand.go \
      $'package token\n\nimport "math/rand/v2"\n\n// N is not random enough.\nfunc N() int { return rand.Int() }'
    lint_case "Reveal outside the allow-list" internal/other/reveal.go \
      $'package other\n\nimport "github.com/felix-homelab/rpmgr/internal/secret"\n\n// Show leaks.\nfunc Show(v secret.Value) string { return v.Reveal() }'
    lint_case "DecisionContext outside internal/store" internal/other/decision.go \
      $'package other\n\nimport (\n\t"context"\n\n\t"github.com/felix-homelab/rpmgr/internal/privacy"\n)\n\n// Skip skips.\nfunc Skip(ctx context.Context) context.Context { return privacy.DecisionContext(ctx, nil) }'
    lint_case "InsecureSkipVerify assigned" internal/other/tls.go \
      $'package other\n\nimport "crypto/tls"\n\n// Weaken weakens.\nfunc Weaken(c *tls.Config) { c.InsecureSkipVerify = true }'
  elif [[ ${REQUIRE_GO-} == 1 ]]; then
    echo "FAIL: the go command is required but not available"
    failed=$((failed + 1))
  fi
fi

echo "check tests: $passed passed, $failed failed (test repositories in $tmproot)"
((failed == 0))
