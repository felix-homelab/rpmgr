#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Rehearses the external S6 run (README.md, "External run") on one machine: the same s6run
# commands, as separate processes, with Pebble and the fake Cloudflare API instead of Let's
# Encrypt staging and a real zone. Two controller replicas obtain the same names at once; replica
# "a" then forces one renewal of each. Prints the checks and exits non-zero if one fails.
#
# Usage: ./rehearse.sh [output-file]
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
out=${1:-/dev/stdout}
work=$(mktemp -d)
pids=()
cleanup() {
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

go -C "$here" build -o "$work/s6run" ./cmd/s6run
umask 077
head -c 24 /dev/urandom | base64 >"$work/cf-token"
head -c 24 /dev/urandom | base64 >"$work/control-token"

"$work/s6run" testbed --state-dir "$work" --cf-token-file "$work/cf-token" \
  >"$work/testbed.out" 2>"$work/testbed.err" &
tb=$!
pids+=("$tb")
for _ in $(seq 100); do [[ -s $work/testbed.json ]] && break; sleep 0.1; done
eval "$(python3 -c '
import json, sys
s = json.load(open(sys.argv[1]))
for k in ("directory", "acme_ca_file", "cf_base_url", "resolver", "http_port", "tls_port"):
    print(f"{k}={s[k]!r}")
' "$work/testbed.json")"
control_port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')

"$work/s6run" gateway --http "127.0.0.1:$http_port" --tls "127.0.0.1:$tls_port" \
  --control "127.0.0.1:$control_port" --control-token-file "$work/control-token" \
  >"$work/gateway.out" 2>"$work/gateway.err" &
gw=$!
pids+=("$gw")
sleep 0.5

names="s6.managed.test,*.s6.managed.test,s6.other.test"
common=(--db "$work/controller.db" --directory "$directory" --acme-ca-file "$acme_ca_file"
  --email spike@rpmgr.test --cf-token-file "$work/cf-token" --cf-base-url "$cf_base_url"
  --dns01-zone managed.test --resolver "$resolver" --dns-propagation-timeout=-1ns
  --gateway-control "http://127.0.0.1:$control_port" --control-token-file "$work/control-token"
  --names "$names")
"$work/s6run" controller --id a --force-renew "${common[@]}" >"$work/a.out" 2>"$work/a.err" &
a=$!
"$work/s6run" controller --id b "${common[@]}" >"$work/b.out" 2>"$work/b.err" &
b=$!
status=0
wait "$a" || { echo "replica a failed:"; tail -5 "$work/a.err"; status=1; }
wait "$b" || { echo "replica b failed:"; tail -5 "$work/b.err"; status=1; }
kill -TERM "$gw" "$tb"
wait "$gw" "$tb" 2>/dev/null || true
pids=()

rc=0
python3 - "$work" "$names" >"$out" <<'EOF' || rc=$?
import json, sys
work, names = sys.argv[1], sys.argv[2].split(",")
def events(f):
    return [json.loads(l) for l in open(f"{work}/{f}") if l.startswith("{")]
a, b, tb, gw = events("a.out"), events("b.out"), events("testbed.out"), events("gateway.out")
ok = True
def check(cond, msg):
    global ok
    ok &= bool(cond)
    print(("PASS " if cond else "FAIL ") + msg)
first = {}
for n in names:
    sa = {e["serial"] for e in a if e["event"] == "certificate" and e["name"] == n}
    sb = {e["serial"] for e in b if e["event"] == "certificate" and e["name"] == n}
    ra = {e["serial"] for e in a if e["event"] == "renewed_certificate" and e["name"] == n}
    # b reads the shared storage before or after a's forced renewal, so it holds one of the two.
    check(len(sa) == 1 and len(sb) == 1 and sb <= (sa | ra),
          f"{n}: replica b holds a certificate replica a obtained (shared storage, no second order)")
    check(len(ra) == 1 and not (ra & sa), f"{n}: forced renewal by replica a yields a new certificate")
    dns01 = [e["dns01"] for e in a if e["event"] == "certificate" and e["name"] == n]
    print(f"     {n}: challenge {'dns-01' if dns01 and dns01[0] else 'http-01/tls-alpn-01'}")
obtained = [e for e in a + b if e["event"] == "obtained"]
for n in names:
    first_issuances = [e for e in obtained if e["name"] == n and not e["renewal"]]
    check(len(first_issuances) == 1, f"{n}: exactly one first issuance across both replicas "
          f"(by {[e['replica'] for e in first_issuances]})")
t = [e for e in tb if e["event"] == "testbed_orders"][-1]
check(t["new_orders"] == 2 * len(names), f"CA saw {t['new_orders']} orders (want {2*len(names)}: one first issuance and one renewal per name)")
check(t["txt_left"] == 0 and t["txt_creates"] == t["txt_deletes"] > 0, f"DNS-01 TXT records: created {t['txt_creates']}, deleted {t['txt_deletes']}, left {t['txt_left']}")
g = [e for e in gw if e["event"] == "gateway_stats"][-1]
check(g["http01_answered"] + g["tlsalpn01_answered"] > 0, f"gateway answered {g['http01_answered']} HTTP-01 and {g['tlsalpn01_answered']} TLS-ALPN-01 validations")
w = sum(e["n"] for e in a + b if e["event"] == "lock_waits")
print(f"     lock acquisitions that waited for the other replica: {w}")
sys.exit(0 if ok else 1)
EOF
if ((status | rc)) && [[ -n ${KEEP_LOGS-} ]]; then
  mkdir -p "$KEEP_LOGS"
  cp "$work"/*.out "$work"/*.err "$KEEP_LOGS"/
fi
exit $((status | rc))
