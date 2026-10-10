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
  "ci(deps): bump the actions group with 3 updates" \
  "build(deps): bump the go group with 12 updates" \
  "build(deps): bump the go-sec group across 1 directory with 12 updates" \
  "ci(deps): bump the actions-sec group across 1 directory with 12 updates" \
  "build(deps): bump the npm group in /web with 12 updates" \
  "build(deps): bump the npm-sec group across 1 directory with 12 updates" \
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

# --- Release tags ----------------------------------------------------------------------------
r=$(new_repo)
cat >"$r/CHANGELOG.md" <<'EOF'
# Changelog

## [Unreleased]

## [2.0.0]

- No date.

## [1.3.0-rc.1] - 2026-10-01

- A candidate.

## [1.2.3] - 2026-09-01

### Added

- A thing.

## [1.1.0] - 2026-08-01

[Unreleased]: https://example.org/compare
EOF
t="$dir/check-release-tag.sh"
expect pass "a release tag with its changelog section" "$t" v1.2.3 "$r"
expect pass "a release candidate with its changelog section" "$t" v1.3.0-rc.1 "$r"
for bad in 1.2.3 v1.2 v1.2.3.4 v01.2.3 v1.02.3 v1.2.3-rc.0 v1.2.3-rc v1.2.3-pre.1 v1.2.3+build.1 spike/s1 ""; do
  expect fail "tag '$bad'" "$t" "$bad" "$r"
done
expect fail "a tag without a changelog section" "$t" v1.2.4 "$r"
expect fail "a changelog section without a date" "$t" v2.0.0 "$r"
expect fail "an empty changelog section" "$t" v1.1.0 "$r"
notes=$("$t" v1.2.3 "$r" 2>/dev/null || true)
expect pass "the release notes are the section's text" test "$notes" = $'### Added\n\n- A thing.'

# --- Security regression test registry ------------------------------------------------------
st="$dir/check-security-tests.sh"
r=$(new_repo)
mkdir -p "$r/docs" "$r/.github/scripts" "$r/p"
printf '| Test | Asserts |\n|---|---|\n| `TestDone` | x |\n| `TestLater` | y |\n| `TestOpen` | z |\n' \
  >"$r/docs/12-testing-and-quality.md"
printf '# registry\n\nTestDone\tdone\t1.1\t#1\nTestLater\tp2\t-\t-\tlater\nTestOpen\tpending\t2.3\t#9\tnote\n' \
  >"$r/.github/scripts/security-tests.txt"
printf 'package p\n\nimport "testing"\n\nfunc TestDone(t *testing.T) {}\n' >"$r/p/p_test.go"
git -C "$r" add -A
expect pass "registry consistent with the document and the code" "$st" "$r"
expect fail "pending test at the end of the phase" env REQUIRE_COMPLETE=1 "$st" "$r"
printf '| `TestNew` | w |\n' >>"$r/docs/12-testing-and-quality.md"
expect fail "test named in the document but not registered" "$st" "$r"
git -C "$r" checkout -q -- docs
printf 'TestGone\tp3\t-\t-\tx\n' >>"$r/.github/scripts/security-tests.txt"
expect fail "registered test not named in the document" "$st" "$r"
git -C "$r" checkout -q -- .github
printf 'func TestOpen(t *testing.T) {}\n' >>"$r/p/p_test.go" && git -C "$r" add -A
expect fail "pending test that already exists" "$st" "$r"
printf 'package p\n\nimport "testing"\n\nfunc TestRenamed(t *testing.T) {}\n' >"$r/p/p_test.go" && git -C "$r" add -A
expect fail "done test that does not exist" "$st" "$r"
printf 'package p\n\nimport "testing"\n\nfunc TestDone(t *testing.T) {}\n' >"$r/p/p_test.go" && git -C "$r" add -A
sed -i 's/^TestLater\tp2/TestLater\tsomeday/' "$r/.github/scripts/security-tests.txt"
expect fail "unknown status" "$st" "$r"
sed -i 's/^TestLater\tsomeday/TestLater\tp2/; s/^TestOpen\tpending\t2.3\t#9/TestOpen\tpending\t-\t-/' "$r/.github/scripts/security-tests.txt"
expect fail "pending test without slice and issue" "$st" "$r"

# --- Size of changes -------------------------------------------------------------------------
z="$dir/check-size.sh"
r=$(new_repo)
base=$(git -C "$r" rev-parse HEAD)
git -C "$r" switch -q -c feature/1-x
lines() { for ((i = 1; i <= $1; i++)); do echo "var v$i = $i"; done; }
size_commit() { # size_commit <path> <lines> [header]: a commit that adds a file of that many lines
  mkdir -p "$r/$(dirname "$1")"
  { [[ -n ${3-} ]] && echo "$3"; lines "$2"; } >"$r/$1"
  git -C "$r" add -A && git -C "$r" commit -q -s -m "feat: add $1"
  git -C "$r" rev-parse HEAD
}
expect pass "399 production lines" in_repo "$r" "$z" "$base" "$(size_commit p/a.go 399)" ""
expect pass "400 production lines: a warning only" in_repo "$r" "$z" "$base" "$(size_commit p/b.go 1)" ""
expect pass "800 production lines" in_repo "$r" "$z" "$base" "$(size_commit p/c.go 400)" ""
over=$(size_commit p/d.go 1)
expect fail "801 production lines" in_repo "$r" "$z" "$base" "$over" ""
expect pass "801 lines labelled mechanical" in_repo "$r" "$z" "$base" "$over" "type:improvement mechanical"
r=$(new_repo)
base=$(git -C "$r" rev-parse HEAD)
expect pass "tests do not count" in_repo "$r" "$z" "$base" "$(size_commit p/a_test.go 900)" ""
expect pass "generated code does not count" in_repo "$r" "$z" "$base" \
  "$(size_commit p/a.pb.go 900 '// Code generated by protoc-gen-go. DO NOT EDIT.')" ""
# Far larger than a pipe buffer, so a reader that stops after the header closes the pipe early.
expect pass "large generated file does not count" in_repo "$r" "$z" "$base" \
  "$(size_commit p/big.pb.go 60000 '// Code generated by protoc-gen-go. DO NOT EDIT.')" ""
size_commit docs/a.md 900 >/dev/null
size_commit p/testdata/x.go 900 >/dev/null
expect pass "documents, test data and migrations do not count" in_repo "$r" "$z" "$base" \
  "$(size_commit migrations/1.sql 900)" ""
expect pass "the benchmark suite does not count" in_repo "$r" "$z" "$base" "$(size_commit bench/cmd/bench/run.go 900)" ""
expect fail "a package named like it does" in_repo "$r" "$z" "$base" "$(size_commit internal/bench/x.go 900)" ""
expect fail "unknown commit" in_repo "$r" "$z" "$base" 0000000000000000000000000000000000000000 ""

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

# --- Changed areas (D64) --------------------------------------------------------------------
# areas <expected output on one line> <file>...: a pull request that adds the files needs exactly
# the stages expected.
areas() {
  local want=$1 r base got
  shift
  r=$(new_repo)
  base=$(git -C "$r" rev-parse HEAD)
  for f in "$@"; do
    mkdir -p "$r/$(dirname "$f")"
    echo x >"$r/$f"
  done
  git -C "$r" add -A
  git -C "$r" commit -q -s -m "feat: change"
  got=$(cd "$r" && "$dir/changed-areas.sh" "$base" HEAD | tr '\n' ' ')
  if [[ $got == "$want " ]]; then
    passed=$((passed + 1))
  else
    echo "FAIL: changed areas of $*: expected '$want', got '$got'"
    failed=$((failed + 1))
  fi
}
areas "go=false web=false checks=false md=true" docs/03-connections.md README.md
areas "go=false web=true checks=false md=false" web/src/app.tsx web/e2e/a.spec.ts
areas "go=false web=true checks=true md=false" web/package.json
areas "go=true web=true checks=false md=false" internal/x/x.go proto/rpmgr/v1/x.proto
areas "go=true web=true checks=true md=false" .github/scripts/check-go.sh
areas "go=true web=true checks=true md=true" go.mod docs/x.md
expect pass "every stage" "$dir/changed-areas.sh" --all
expect fail "one commit only" "$dir/changed-areas.sh" HEAD
[[ $("$dir/changed-areas.sh" --none | tr '\n' ' ') == "go=false web=false checks=false md=false " ]] && passed=$((passed + 1)) ||
  { echo "FAIL: changed areas --none"; failed=$((failed + 1)); }

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

# --- Web UI: the refusals before any install; the CI job web runs the whole check ------------
w="$dir/check-web.sh"
r=$(new_repo)
expect fail "no web/package.json" "$w" "$r"
mkdir -p "$r/web" && echo '{}' >"$r/web/package.json" && echo '{}' >"$r/web/package-lock.json"
echo 1 >"$r/web/.nvmrc"
expect fail "another Node major version than web/.nvmrc" "$w" "$r"
echo '{"devDependencies": {"@playwright/test": "0.0.1"}}' >"$r/web/package.json"
expect fail "@playwright/test of another version than the Playwright image" "$dir/check-web-e2e.sh" "$r"

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
  git -C "$r" rm -q -f p/crash_test.go

  # Builds for every platform; tests per architecture.
  expect pass "build and vet on every platform" "$dir/check-build.sh" "$r"
  expect pass "vet only, on every platform" "$dir/check-build.sh" "$r" vet
  expect fail "an unknown build mode" "$dir/check-build.sh" "$r" fast
  expect pass "tests on this machine's architecture" "$dir/check-test-arch.sh" "$(go env GOARCH)" "$r"
  expect fail "unknown architecture" "$dir/check-test-arch.sh" mips "$r"
  # Without cgo the go command drops a file that imports "C"; code that needs it no longer builds.
  printf 'package p\n\n// #include <stdlib.h>\nimport "C"\n\n// One comes from C.\nfunc One() int { return int(C.int(1)) }\n' >"$r/p/cgo.go"
  printf 'package p\n\n// Two needs the cgo file.\nfunc Two() int { return One() + 1 }\n' >"$r/p/two.go"
  git -C "$r" add -A
  expect fail "package that needs cgo" "$dir/check-build.sh" "$r"
  expect fail "package that needs cgo, vet only" "$dir/check-build.sh" "$r" vet
  git -C "$r" rm -q -f p/cgo.go p/two.go
  printf 'package p\n\nimport "syscall"\n\n// Winch only compiles on Unix.\nfunc Winch() syscall.Signal { return syscall.SIGWINCH }\n' >"$r/p/unix.go"
  git -C "$r" add -A
  expect fail "Unix-only code without a Windows stub" "$dir/check-build.sh" "$r"
  expect fail "Unix-only code without a Windows stub, vet only" "$dir/check-build.sh" "$r" vet
  expect pass "Unix-only code, Linux platforms only" env RPMGR_PLATFORMS="linux/amd64 linux/arm64" "$dir/check-build.sh" "$r" vet
  git -C "$r" rm -q -f p/unix.go

  # govulncheck (needs network): no finding in clean code; a called function of a vulnerable
  # golang.org/x/text version (GO-2022-1059) is found.
  expect pass "govulncheck without findings" "$dir/check-govulncheck.sh" "$r"
  r=$(new_repo)
  printf 'module example.org/v\n\ngo 1.26.0\n\nrequire golang.org/x/text v0.3.7\n' >"$r/go.mod"
  mkdir -p "$r/p"
  printf 'package p\n\nimport "golang.org/x/text/language"\n\n// Parse parses.\nfunc Parse(s string) ([]language.Tag, []float32, error) { return language.ParseAcceptLanguage(s) }\n' >"$r/p/p.go"
  (cd "$r" && go mod tidy >/dev/null 2>&1)
  expect fail "govulncheck finds a called vulnerable function" "$dir/check-govulncheck.sh" "$r"

  # buf (needs network on first use): lint, breaking changes against main with and without the
  # override of D56, and generated code that must match. The fixture uses rpmgr's own go.mod, so
  # the code generators are the tool dependencies pinned there.
  r=$(new_repo)
  cp "$dir/../../go.mod" "$dir/../../go.sum" "$dir/../../buf.yaml" "$dir/../../buf.gen.yaml" "$r/"
  # The type exclusions name rpmgr's packages, which the fixture lacks, and buf refuses those.
  sed -i '/exclude_types:/d' "$r/buf.gen.yaml"
  mkdir -p "$r/proto/fixture/v1"
  cat >"$r/proto/fixture/v1/fixture.proto" <<'EOF'
syntax = "proto3";

package fixture.v1;

option go_package = "github.com/felix-homelab/rpmgr/gen/fixture/v1;fixturev1";

// Thing is a fixture.
message Thing {
  // The name.
  string name = 1;
  // The size.
  uint32 size = 2;
}
EOF
  (cd "$r" && go run github.com/bufbuild/buf/cmd/buf@v1.73.0 generate >/dev/null 2>&1)
  git -C "$r" add -A && git -C "$r" commit -q -s -m "feat: fixture"
  git -C "$r" switch -q -c feature/1-x
  bc="$dir/check-buf.sh"
  expect pass "protobuf lint, no breaking change, generated code current" env BUF_BREAKING_AGAINST=main "$bc" "$r"
  sed -i 's/^message Thing {/message thing_t {/' "$r/proto/fixture/v1/fixture.proto"
  expect fail "protobuf lint error" env BUF_BREAKING_AGAINST=main "$bc" "$r"
  git -C "$r" checkout -q HEAD -- proto gen
  sed -i '/The size/d; /uint32 size = 2;/d' "$r/proto/fixture/v1/fixture.proto"
  (cd "$r" && go run github.com/bufbuild/buf/cmd/buf@v1.73.0 generate >/dev/null 2>&1)
  git -C "$r" add -A
  expect fail "breaking change: a field removed" env BUF_BREAKING_AGAINST=main "$bc" "$r"
  expect pass "breaking change allowed with the override" env BUF_BREAKING_AGAINST=main ALLOW_BREAKING=1 "$bc" "$r"
  git -C "$r" checkout -q HEAD -- proto gen
  sed -i 's|// The name.|// The name of the thing.|' "$r/proto/fixture/v1/fixture.proto"
  expect fail "generated code older than the .proto file" env BUF_BREAKING_AGAINST=main "$bc" "$r"
  git -C "$r" checkout -q HEAD -- proto gen
  expect pass "nothing to compare when the base has no buf.yaml" env BUF_BREAKING_AGAINST=does-not-exist "$bc" "$r"

  # Release builds: a module with rpmgr's path, toolchain and version package, whose command
  # prints what `rpmgr version --verbose` prints, and the test root keys with the rpmgrtest tag.
  r=$(new_repo)
  grep -E '^(module|go|toolchain) ' "$dir/../../go.mod" >"$r/go.mod"
  mkdir -p "$r/cmd/rpmgr" "$r/internal/version"
  cp "$dir/../../internal/version/version.go" "$r/internal/version/"
  cat >"$r/cmd/rpmgr/main.go" <<'EOF'
package main

import (
	"fmt"
	"os"

	"github.com/felix-homelab/rpmgr/internal/version"
)

func main() {
	fmt.Println(version.Get())
	if len(os.Args) > 2 && os.Args[2] == "--verbose" {
		fmt.Println(roots)
	}
}
EOF
  printf '//go:build !rpmgrtest\n\npackage main\n\nconst roots = "release root keys: none; this build verifies no release"\n' >"$r/cmd/rpmgr/roots.go"
  printf '//go:build rpmgrtest\n\npackage main\n\nconst roots = "test release root keys (rpmgrtest build):"\n' >"$r/cmd/rpmgr/roots_rpmgrtest.go"
  git -C "$r" add -A && git -C "$r" commit -q -s -m "feat: fixture"
  commit=$(git -C "$r" rev-parse HEAD)
  rb="$dir/build-release.sh" ra="$dir/check-release-artifacts.sh"
  # GOFLAGS cannot add the rpmgrtest tag to a release build.
  expect pass "a release build" env GOFLAGS=-tags=rpmgrtest "$rb" 1.2.3 "$commit" "$r/a" "$r"
  expect pass "its artifacts" "$ra" "$r/a" 1.2.3 "$commit" "$r"
  expect fail "its artifacts, release root keys required" env REQUIRE_ROOTS=1 "$ra" "$r/a" 1.2.3 "$commit" "$r"
  expect fail "its artifacts, as another version" "$ra" "$r/a" 1.2.4 "$commit" "$r"
  expect fail "its artifacts, as another commit" "$ra" "$r/a" 1.2.3 "${commit//[0-9a-f]/0}" "$r"
  expect fail "a build into an existing directory" "$rb" 1.2.3 "$commit" "$r/a" "$r"
  expect fail "a version with a leading v" "$rb" v1.2.3 "$commit" "$r/v" "$r"
  expect fail "a short commit hash" "$rb" 1.2.3 "${commit:0:12}" "$r/s" "$r"
  expect pass "a second build of the commit" "$rb" 1.2.3 "$commit" "$r/b" "$r"
  expect pass "the two builds are equal" "$dir/check-reproducible.sh" "$r/a" "$r/b"
  expect pass "a build stamped with another commit" "$rb" 1.2.3 "${commit//[0-9a-f]/1}" "$r/c" "$r"
  expect fail "builds stamped with two commits differ" "$dir/check-reproducible.sh" "$r/a" "$r/c"
  # One artifact replaced, with SHA256SUMS made anew.
  replaced() { # replaced <description> <go build flags...>
    local desc=$1 t
    shift
    t=$(mktemp -d "$tmproot/release.XXXXXX")
    cp "$r/a"/* "$t/"
    env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go -C "$r" build -buildvcs=false "$@" \
      -ldflags "-X github.com/felix-homelab/rpmgr/internal/version.Version=1.2.3 -X github.com/felix-homelab/rpmgr/internal/version.Commit=$commit" \
      -o "$t/rpmgr-1.2.3-linux-amd64" ./cmd/rpmgr
    (cd "$t" && sha256sum -- rpmgr-* >SHA256SUMS)
    expect fail "$desc" "$ra" "$t" 1.2.3 "$commit" "$r"
  }
  replaced "an artifact built with the rpmgrtest tag" -trimpath -tags rpmgrtest
  replaced "an artifact built without -trimpath"
  t=$(mktemp -d "$tmproot/release.XXXXXX")
  cp "$r/a"/* "$t/"
  cp "$r/a/rpmgr-1.2.3-linux-arm64" "$t/rpmgr-1.2.3-linux-amd64"
  (cd "$t" && sha256sum -- rpmgr-* >SHA256SUMS)
  expect fail "an artifact of another architecture" "$ra" "$t" 1.2.3 "$commit" "$r"
  t=$(mktemp -d "$tmproot/release.XXXXXX")
  cp "$r/a"/* "$t/"
  echo x >>"$t/rpmgr-1.2.3-linux-riscv64"
  expect fail "an artifact changed after SHA256SUMS" "$ra" "$t" 1.2.3 "$commit" "$r"
  t=$(mktemp -d "$tmproot/release.XXXXXX")
  cp "$r/a"/* "$t/"
  touch "$t/notes.txt"
  expect fail "a file besides the artifacts" "$ra" "$t" 1.2.3 "$commit" "$r"
  t=$(mktemp -d "$tmproot/release.XXXXXX")
  cp "$r/a"/rpmgr-1.2.3-linux-amd64 "$r/a"/rpmgr-1.2.3-linux-arm64 "$r/a"/rpmgr-1.2.3-linux-arm "$t/"
  (cd "$t" && sha256sum -- rpmgr-* >SHA256SUMS)
  expect fail "an architecture missing" "$ra" "$t" 1.2.3 "$commit" "$r"
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
  printf 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n' >"$r/leak.txt"
  expect pass "the RFC 6455 sample key is not a secret" "$dir/check-secrets.sh" "$r" dir
  # Git mode reads the history of a worktree too, whose .git file names a git directory outside
  # it, and fails outside a repository rather than scanning nothing.
  r=$(new_repo)
  printf 'token = "%s_%s_%s_%s"\n' rpmgr enr "$(printf 'k7Q2%.0s' {1..10})Zx9" "aB3dE5" >"$r/leak.txt"
  git -C "$r" add leak.txt && git -C "$r" commit -q -s -m "chore: leak"
  git -C "$r" rm -q leak.txt && git -C "$r" commit -q -s -m "chore: remove the leak"
  wt=$(mktemp -d "$tmproot/wt.XXXXXX")
  git -C "$r" worktree add -q -b side "$wt"
  expect fail "a token in a worktree's history" "$dir/check-secrets.sh" "$wt" git
  expect fail "git mode outside a repository" "$dir/check-secrets.sh" "$(mktemp -d "$tmproot/dir.XXXXXX")" git

  # Atlas lint: generated migrations pass, a destructive change is reported.
  r=$(mktemp -d "$tmproot/dir.XXXXXX")
  cp "$dir/../../internal/store/migrations/sqlite/"* "$r/"
  expect pass "atlas lint of the SQLite migrations" "$dir/check-atlas-lint.sh" "$r" "sqlite://dev?mode=memory"
  printf 'DROP TABLE `gateway_groups`;\n' >"$r/20991231000000_drop.sql"
  rm "$r/atlas.sum"
  docker run --rm -u "$(id -u):$(id -g)" -v "$r:/m" \
    mirror.gcr.io/arigaio/atlas:1.3.3-community@sha256:9c9958f5b8d26d404ab2e28098c8629526eb4bec647f790278611e58a0b19839 \
    migrate hash --dir file:///m >/dev/null 2>&1
  expect fail "atlas lint reports a destructive change" "$dir/check-atlas-lint.sh" "$r" "sqlite://dev?mode=memory"

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
