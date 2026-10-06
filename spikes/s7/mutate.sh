#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Mutation checks for spike S7: each mutation removes one control from a copy of this module and
# must make at least one test fail. Shows that the tests pass for the right reasons.
#
# Usage: ./mutate.sh   (from spikes/s7)
set -euo pipefail
src=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

mutate() { # name file old new test-pattern
  local name=$1 file=$2 old=$3 new=$4 pattern=$5 work
  work=$(mktemp -d)
  cp "$src"/*.go "$src"/go.mod "$work"/
  python3 - "$work/$file" "$old" "$new" <<'EOF'
import sys
p, a, b = sys.argv[1:4]
s = open(p).read()
assert s.count(a) == 1, a
open(p, "w").write(s.replace(a, b))
EOF
  local out
  if out=$(go -C "$work" test -count=1 -run "$pattern" ./... 2>&1); then
    echo "SURVIVED  $name"
  else
    echo "killed    $name: $(grep -E -- '--- FAIL' <<<"$out" | sed 's/^ *//' | tr '\n' ' ' | cut -c1-160)"
  fi
  rm -r "$work"
}

mutate "deny-list not checked in VerifyConnection" tlsconfig.go \
  'if e.Deny != nil && e.Deny.Denied(leaf) {' 'if false && e.Deny != nil && e.Deny.Denied(leaf) {' \
  'TestResumption|TestServerNamePerPeer'
mutate "SPIFFE ID not checked in VerifyConnection" tlsconfig.go \
  'if e.Exact != nil && id != *e.Exact {' 'if false && e.Exact != nil && id != *e.Exact {' \
  'TestServerNamePerPeer'
mutate "Reauth endpoint issues and accepts tickets" reauth.go \
  'reauth.SessionTicketsDisabled = true' 'reauth.SessionTicketsDisabled = false' 'TestReauth'
mutate "Reauth without the database checks" reauth.go \
  'if err := ca.CheckReauthable(leaf, grace); err != nil {' 'if err := error(nil); err != nil {' 'TestReauth'
mutate "Reauth verifier never selected by SNI" reauth.go \
  'if hello.ServerName == reauthName {' 'if false && hello.ServerName == reauthName {' 'TestReauth'
mutate "intermediate without name constraints" helpers_test.go \
  'ca, err := NewCA(td, clk.Now, true)' 'ca, err := NewCA(td, clk.Now, false)' 'TestNameConstraints'
mutate "CSR binding not compared" binding.go \
  'if subtle.ConstantTimeCompare(got, want) != 1 {' 'if subtle.ConstantTimeCompare(got, want) != 1 && false {' 'TestCSRBinding'
mutate "renewal accepts the same key" ca.go \
  'ok && pub.Equal(old) {' 'ok && pub.Equal(old) && false {' 'TestLeafIssueAndRenew'
