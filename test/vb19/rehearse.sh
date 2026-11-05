#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Rehearses the VB-19 run sheet (README.md) locally, without Let's Encrypt: the same rpmgr
# commands against Pebble, in a container without a network, where iptables stands in for the
# cloud firewall. It builds rpmgr from this checkout, Pebble at the version of go.mod and the
# fakes of ./fakes (the fake Cloudflare API and the authoritative DNS server of the repo's tests),
# runs every step of the sheet, DNS-01 included, and checks the outcome. Needs Go and Docker.
#
# Differences from the real run, each because the rehearsal has no internet:
# - Pebble is the CA, at https://localhost:14000/dir; rpmgr trusts its TLS through SSL_CERT_FILE.
# - The zone is vz.test, the sheet's <zone>; <name> is vb19.vz.test. Every name of the zone resolves
#   to 127.0.0.2 for the CA (the fakes' DNS server, which also answers a TXT record as the fake
#   Cloudflare holds it), which plays the VM's public IP; for the host itself, /etc/hosts sends the
#   names to 127.0.0.1, as the run sheet's /etc/hosts entries do on the VM. The firewall rules close
#   80 or 443 of 127.0.0.2 only.
# - Cloudflare is the fake of internal/dns/cftest. rpmgr's client has the API's address compiled in:
#   /etc/hosts sends api.cloudflare.com to 127.0.0.3, a NAT rule to the fake, whose certificate a CA
#   in rpmgr's root file signs. rpmgr is the release build, with no test hook.
# - The first user and the API token, which the run sheet makes in the web UI, are made here with
#   the same API calls the web UI sends.
# - Pebble reuses every valid authorisation of an account (PEBBLE_AUTHZREUSE=100), so that the
#   rehearsal shows that the run sheet's new ACME account per phase makes the CA validate again.
#
# Usage: rehearse.sh [<log file>]
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

if [[ ${1-} != --inside ]]; then
  log=${1:-/dev/null}
  root=$(git -C "$here" rev-parse --show-toplevel)
  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT
  mkdir -p "$work/bin" "$work/pebble"
  ver=$(go -C "$root" list -m -f '{{.Version}}' github.com/letsencrypt/pebble/v2)
  echo "== building rpmgr, and Pebble $ver"
  CGO_ENABLED=0 go -C "$root" build -o "$work/bin/rpmgr" ./cmd/rpmgr
  CGO_ENABLED=0 go -C "$root" build -o "$work/bin/fakes" ./test/vb19/fakes
  CGO_ENABLED=0 GOBIN="$work/bin" go install "github.com/letsencrypt/pebble/v2/cmd/pebble@$ver"
  certs="$(go -C "$root" list -m -f '{{.Dir}}' github.com/letsencrypt/pebble/v2)/test/certs"
  cp "$certs/localhost/cert.pem" "$certs/localhost/key.pem" "$certs/pebble.minica.pem" "$work/pebble/"
  cp "$here/rehearse.sh" "$work/"
  docker build -q -t rpmgr-vb19-rehearsal "$here" >/dev/null
  docker run --rm --network none --cap-add NET_ADMIN \
    --add-host vb19.vz.test:127.0.0.1 --add-host app.vb19.vz.test:127.0.0.1 \
    --add-host dns.vb19.vz.test:127.0.0.1 --add-host api.cloudflare.com:127.0.0.3 \
    -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" -v "$work:/vb19" \
    rpmgr-vb19-rehearsal bash /vb19/rehearse.sh --inside 2>&1 | tee "$log"
  exit "${PIPESTATUS[0]}"
fi

# --- Inside the container, as root --------------------------------------------------------------

S=/vb19/state
mkdir -p "$S"
export PATH=/vb19/bin:$PATH RPMGR_CREDENTIALS=$S/credentials.yaml
public=127.0.0.2 # the VM's public IP, as the CA sees it
finish() {
  status=$?
  if ((status != 0)); then
    echo "-- the all-in-one's log, last lines:"
    tail -n 30 "$S/aio.log" 2>/dev/null || true
    if [[ -f $S/verify.out ]]; then
      echo "-- the last rpmgr verify domain:"
      cat "$S/verify.out"
    fi
  fi
  chown -R "$HOST_UID:$HOST_GID" /vb19
  exit "$status"
}
trap finish EXIT

step() { printf '\n== %s\n' "$*"; }
fail() {
  printf 'FAIL: %s\n' "$*"
  exit 1
}
# pass <id> <what>: a verdict line, the form the run sheet asks to paste back.
pass() { printf 'PASS %s\n' "$*"; }
# within <seconds> <what> <command>...: runs the command every second until it succeeds.
within() {
  local n=$1 what=$2
  shift 2
  for ((i = 0; i < n; i++)); do
    if "$@" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  fail "$what: not within ${n} s"
}
# served <host> [<field>]: what the CA would see at 443 of the public IP: issuer, serial, end date.
served() {
  openssl s_client -connect "$public:443" -servername "$1" </dev/null 2>/dev/null |
    openssl x509 -noout -issuer -serial -enddate
}
issued_by_pebble() { served "$1" | grep -q '^issuer=.*Pebble'; }
validations() { grep -c 'set VALID by completed challenge' "$S/pebble.log" || true; }
refusals() { grep -c 'set INVALID by completed challenge' "$S/pebble.log" || true; }
http_attempts() { grep -c 'Attempting to validate w/ HTTP' "$S/pebble.log" || true; }

step "the fakes: Cloudflare and the zone's DNS server; the CA: Pebble"
zone=vz.test
install -m 0600 /dev/null "$S/cf-token"
printf 'vb19-%s\n' "$(openssl rand -hex 16)" >"$S/cf-token"
fakes -dir "$S" -token-file "$S/cf-token" -zone "$zone" -public "$public" \
  -foreign 'MX,vz.test,10 mail.vz.test' -foreign 'A,mail.vz.test,192.0.2.99' -foreign 'TXT,keep.vz.test,not-rpmgrs' >"$S/fakes.log" 2>&1 &
within 30 "the fakes" test -s "$S/dns.addr"
dnsaddr=$(cat "$S/dns.addr")
# rpmgr asks its resolver, and the zone's name servers on port 53: all of them are the fake DNS.
printf 'nameserver 127.0.0.1\n' >/etc/resolv.conf
for proto in udp tcp; do
  iptables -t nat -A OUTPUT -d 127.0.0.0/8 -p "$proto" --dport 53 -j REDIRECT --to-ports "${dnsaddr##*:}"
done
iptables -t nat -A OUTPUT -d 127.0.0.3 -p tcp --dport 443 -j REDIRECT --to-ports 9443
cat >"$S/pebble.json" <<'EOF'
{"pebble": {"listenAddress": "127.0.0.1:14000", "managementListenAddress": "127.0.0.1:15000",
  "certificate": "/vb19/pebble/cert.pem", "privateKey": "/vb19/pebble/key.pem",
  "httpPort": 80, "tlsPort": 443, "ocspResponderURL": "", "externalAccountBindingRequired": false}}
EOF
PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=0 PEBBLE_AUTHZREUSE=100 \
  pebble -config "$S/pebble.json" -dnsserver "$dnsaddr" >"$S/pebble.log" 2>&1 &
within 30 "Pebble's directory" curl -fsS --cacert /vb19/pebble/pebble.minica.pem https://localhost:14000/dir

step "install, as docs/10 describes it, with the KEK in a file (no systemd here)"
install -m 0755 /vb19/bin/rpmgr /usr/local/bin/rpmgr
useradd --system --user-group --home-dir /var/lib/rpmgr --shell /usr/sbin/nologin rpmgr
install -d -m 0755 /etc/rpmgr
install -d -m 0750 -o rpmgr -g rpmgr /var/lib/rpmgr
rpmgr all-in-one init --config /etc/rpmgr/all-in-one.yaml --public-url https://vb19.vz.test \
  --kek-source file --kek-path /etc/rpmgr/kek | tee "$S/init.out"
link=$(grep -o 'https://vb19.vz.test/setup#[^[:space:]]*' "$S/init.out") || fail "no setup link"
grep -q '^tls:' /etc/rpmgr/all-in-one.yaml && fail "init wrote a tls section; the sheet adds one"

step "a self-signed certificate until the CA is staging"
install -d -m 0755 /etc/rpmgr/tls
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=vb19.vz.test \
  -addext subjectAltName=DNS:vb19.vz.test -keyout /etc/rpmgr/tls/panel.key -out /etc/rpmgr/tls/panel.crt 2>/dev/null
chgrp rpmgr /etc/rpmgr/tls/panel.key && chmod 0640 /etc/rpmgr/tls/panel.key
printf 'tls:\n  cert_file: %s\n  key_file: %s\n' /etc/rpmgr/tls/panel.crt /etc/rpmgr/tls/panel.key \
  >>/etc/rpmgr/all-in-one.yaml
# init gives what it created in the state directory to the service user (docs/10, "Install").
[[ -z $(find /var/lib/rpmgr ! -user rpmgr) ]] || fail "init left files in /var/lib/rpmgr that rpmgr does not own"

# start runs the all-in-one as the unit does: as the user rpmgr, with CAP_NET_BIND_SERVICE only. It
# trusts Pebble's and the fake Cloudflare's TLS certificates through SSL_CERT_FILE, a copy the user
# can read.
cat /vb19/pebble/pebble.minica.pem "$S/cloudflare-ca.pem" >/etc/rpmgr/pebble-ca.pem
chmod 0644 /etc/rpmgr/pebble-ca.pem
start() {
  SSL_CERT_FILE=/etc/rpmgr/pebble-ca.pem setpriv --reuid rpmgr --regid rpmgr --init-groups \
    --inh-caps +net_bind_service --ambient-caps +net_bind_service \
    rpmgr all-in-one --config /etc/rpmgr/all-in-one.yaml >>"$S/aio.log" 2>&1 &
  aio=$!
  within 60 "the all-in-one ready" curl -fsS http://127.0.0.1:7381/readyz
}
stop() {
  kill -TERM "$aio"
  wait "$aio" || true
}
start

step "the first user and an API token, as the web UI makes them"
cacert=/etc/rpmgr/tls/panel.crt # the CA file of rpmgr login from phase a on
api() { # api <service/method> <JSON body>
  curl -fsS --cacert "$cacert" -b "$S/cookies" -c "$S/cookies" -H 'Content-Type: application/json' \
    -H 'Origin: https://vb19.vz.test' "https://vb19.vz.test/rpmgr.v1.$1" -d "$2"
}
pw=$(openssl rand -hex 16)
api AuthService/CompletePasswordReset "{\"token\":\"${link#*#}\",\"newPassword\":\"$pw\",\"email\":\"ada@vb19.vz.test\",\"displayName\":\"Ada\"}" >/dev/null
api AuthService/Login "{\"email\":\"ada@vb19.vz.test\",\"password\":\"$pw\"}" >/dev/null
api AuthService/StepUp "{\"password\":\"$pw\"}" >/dev/null
org=$(api AuthService/GetSession '{}' | jq -r '.memberships[0].orgId')
install -m 0600 /dev/null "$S/token"
api TokenService/CreateAPIToken "{\"orgId\":\"$org\",\"name\":\"vb19\",\"ttl\":\"86400s\",\"scopes\":[\"org.read\",\"routes.write\",\"infrastructure.write\",\"instance.admin\"]}" |
  jq -r .token >"$S/token"

step "rpmgr login"
cp /etc/rpmgr/tls/panel.crt "$S/ca.pem"
rpmgr login --controller https://vb19.vz.test --org "$org" --token-file "$S/token" --ca-file "$S/ca.pem"

step "the instance's ACME settings"
rpmgr get --instance settings | tee "$S/settings.before"
grep -q acme_directory_url "$S/settings.before" || fail "no setting acme_directory_url"
grep -q acme_email "$S/settings.before" || fail "no setting acme_email"
rpmgr update settings --instance --set acme_directory_url=https://localhost:14000/dir --set acme_email=vb19-a@vb19.vz.test

step "phase a: the controller's own certificate, from the CA"
sed -i '/^tls:$/,/^  key_file:/d' /etc/rpmgr/all-in-one.yaml
grep -q '^tls:' /etc/rpmgr/all-in-one.yaml && fail "the tls section is still there"
stop
start
within 120 "the controller's own certificate from the CA" issued_by_pebble vb19.vz.test
served vb19.vz.test
# The run sheet's command: the chain's issuing certificates join the CA file.
openssl s_client -connect 127.0.0.1:443 -servername vb19.vz.test -showcerts </dev/null 2>/dev/null |
  awk '/BEGIN CERT/{n++} n>=2' | sed -n '/BEGIN CERT/,/END CERT/p' >>"$S/ca.pem"
(($(grep -c 'BEGIN CERT' "$S/ca.pem") > 1)) || fail "the served chain has no issuing certificate"
cacert=$S/ca.pem
rpmgr list route >/dev/null || fail "the CLI does not trust the controller's new certificate"
pass "a1 the controller's certificate is from the CA"

step "the domain, claimed for an HTTP proof and marked trusted"
# /etc/hosts sends vb19.vz.test to loopback, which an HTTP proof never connects to, as on the VM of
# the run sheet (README, step 5): the proof is refused as such, and the claim is marked trusted.
rpmgr create domain --fqdn vb19.vz.test --wildcard --method http | tee "$S/domain.out"
did=$(grep -o -m 1 'dom_[0-9A-Z]*' "$S/domain.out")
refused() {
  rpmgr verify domain "$did" >"$S/verify.out" 2>&1 || true
  grep -q 'not public' "$S/verify.out"
}
within 90 "the HTTP proof refused for loopback" refused
cat "$S/verify.out"
api AuthService/StepUp "{\"password\":\"$pw\"}" >/dev/null
api DomainService/MarkDomainTrusted "{\"domainId\":\"$did\"}" | jq -e '.domain.status == "DOMAIN_STATUS_VERIFIED"' >/dev/null ||
  fail "the claim was not marked trusted"
rpmgr get domain "$did"

step "phase a: the route's certificate"
rpmgr create route --name vb19 --group default --http --hostname app.vb19.vz.test --tls-mode acme
within 120 "the route's certificate from the CA" issued_by_pebble app.vb19.vz.test
rpmgr list -o json certificate >"$S/certs.json"
cat "$S/certs.json"
cid=$(jq -r '[.. | objects | select(has("sans")) | select(.sans | index("app.vb19.vz.test"))][0].id' "$S/certs.json")
[[ -n $cid && $cid != null ]] || fail "no certificate for app.vb19.vz.test in rpmgr list certificate"
rpmgr get certificate "$cid"
a=$(served app.vb19.vz.test | grep serial)
echo "phase a: $a"
pass "a2 the route's certificate is from the CA"

# renew_phase <phase> <closed port> <account e-mail>: closes the port of the public IP, renews with a
# new ACME account, opens it again and prints the served serial.
renew_phase() {
  local phase=$1 port=$2 email=$3 before_valid before_invalid before_http end_before
  before_valid=$(validations)
  before_invalid=$(refusals)
  before_http=$(http_attempts)
  end_before=$(rpmgr get -o json certificate "$cid" | jq -r '.. | .notAfter? // .not_after? // empty' | head -n 1)
  iptables -I INPUT -d "$public" -p tcp --dport "$port" -j REJECT --reject-with tcp-reset
  rpmgr update settings --instance --set "acme_email=$email"
  rpmgr renew certificate "$cid"
  renewed() {
    local end
    end=$(rpmgr get -o json certificate "$cid" | jq -r '.. | .notAfter? // .not_after? // empty' | head -n 1)
    [[ -n $end && $end != "$end_before" ]]
  }
  within 180 "phase $phase: the renewal with $port closed" renewed
  iptables -D INPUT -d "$public" -p tcp --dport "$port" -j REJECT --reject-with tcp-reset
  rpmgr get certificate "$cid"
  echo "phase $phase: authorisations validated +$(($(validations) - before_valid)), refused +$(($(refusals) - before_invalid)); HTTP-01 requests of the CA +$(($(http_attempts) - before_http))"
  (($(validations) > before_valid)) || fail "phase $phase: the CA validated nothing; the new account did not take"
}

step "phase b: TCP 443 closed, renewal with a new account: HTTP-01"
renew_phase b 443 vb19-b@vb19.vz.test
within 60 "phase b: the renewed certificate served" bash -c "! openssl s_client -connect $public:443 -servername app.vb19.vz.test </dev/null 2>/dev/null | openssl x509 -noout -serial | grep -qx '$a'"
b=$(served app.vb19.vz.test | grep serial)
echo "phase b: $b"
pass "b1 renewed with TCP 443 closed (HTTP-01), new serial"

step "phase c: TCP 80 closed, renewal with a new account: TLS-ALPN-01"
renew_phase c 80 vb19-c@vb19.vz.test
within 60 "phase c: the renewed certificate served" bash -c "! openssl s_client -connect $public:443 -servername app.vb19.vz.test </dev/null 2>/dev/null | openssl x509 -noout -serial | grep -qx '$b'"
c=$(served app.vb19.vz.test | grep serial)
echo "phase c: $c"
pass "c1 renewed with TCP 80 closed (TLS-ALPN-01), new serial"

# --- Phase d: DNS-01 through Cloudflare ---------------------------------------------------------

# The CLI asks for a step-up on /dev/tty where the sheet's person types their password; here the
# token steps itself up with the first user's password (D63), for ten minutes.
stepup() {
  install -m 0600 /dev/null "$S/authhdr"
  printf 'Authorization: Bearer %s\n' "$(cat "$S/token")" >"$S/authhdr"
  curl -fsS --cacert "$cacert" -H @"$S/authhdr" -H 'Content-Type: application/json' \
    "https://vb19.vz.test/rpmgr.v1.AuthService/StepUp" -d "{\"password\":\"$pw\"}" >/dev/null
}
# record <type> <name>: the content of the record at the provider, read live (the run sheet's check
# of the zone), or nothing. Read from the provider, so that it sees records the ledger does not hold.
record() {
  rpmgr list dns-record --zone "$zone" --foreign -o json |
    jq -r --arg t "$1" --arg n "$2" '[.. | objects | select(.type? == $t and .name? == $n) | .content] | join(",")'
}
record_is() { [[ $(record "$1" "$2") == "$3" ]]; }
record_gone() { [[ -z $(record "$1" "$2") ]]; }
# cert_for <host>: the ID of the certificate whose names include host, from rpmgr list certificate.
cert_for() {
  rpmgr list -o json certificate |
    jq -r --arg h "$1" '[.. | objects | select(has("sans")) | select(.sans | index($h))][0].id // empty'
}
cert_active() { rpmgr list -o json certificate | jq -e --arg h "$1" '[.. | objects | select(has("sans")) | select(.sans | index($h)) | select(.status == "CERTIFICATE_STATUS_ACTIVE")] | length > 0' >/dev/null; }
# foreign: the records at the provider that rpmgr does not own, one line each, sorted.
foreign() {
  rpmgr list dns-record --zone "$zone" --foreign -o json |
    jq -r '[.. | objects | select(has("type")) | select((.id // "") == "") | "\(.type) \(.name) \(.content)"] | sort | .[]'
}
route_id() { rpmgr list -o json route | jq -r --arg n "$1" '[.. | objects | select(.name? == $n) | .id][0] // empty'; }

step "phase d: Cloudflare connected, the zone imported (held), a DNS target for the group"
http_before=$(http_attempts)
stepup
rpmgr connect dns-provider --kind cloudflare --name cf --token-file "$S/cf-token"
rpmgr list dns-provider
rpmgr list provider-zone cf | tee "$S/provider-zones.out"
grep -q "$zone" "$S/provider-zones.out" || fail "the provider's zones do not list $zone"
rpmgr list dns-provider -o json |
  jq -e '[.. | objects | select(.name? == "cf" and .status? == "PROVIDER_STATUS_OK")] | length == 1' >/dev/null ||
  fail "the provider is not listed as ok"
pass "d1 the provider is connected, its token is ok, and it lists the zone"
rpmgr import zone --provider cf "$zone"
rpmgr get zone "$zone" -o json | tee "$S/zone.json"
jq -e '.syncState == "ZONE_SYNC_STATE_HELD"' "$S/zone.json" >/dev/null || fail "an imported zone is not held"
pass "d2 the zone is imported and held"
rpmgr update gateway-group default --dns-address 192.0.2.10 # TEST-NET-1: the group's DNS target
foreign >"$S/foreign.before"
cat "$S/foreign.before"
(($(wc -l <"$S/foreign.before") == 3)) || fail "the records of others are not listed as three"
step "phase d: an http route and a wildcard route, certificates by DNS-01 while the zone is held"
rpmgr create route --name vb19d --group default --http --hostname dns.vb19.vz.test --tls-mode acme
rpmgr create route --name vb19w --group default --http --hostname '*.w.vb19.vz.test' --tls-mode acme
within 180 "the certificate of dns.vb19.vz.test" cert_active dns.vb19.vz.test
within 180 "the wildcard certificate" cert_active '*.w.vb19.vz.test'
d=$(served dns.vb19.vz.test)
w=$(served x.w.vb19.vz.test)
echo "$d"
echo "$w"
echo "$d" | grep -q '^issuer=.*Pebble' || fail "dns.vb19.vz.test: the issuer is not the CA: $d"
echo "$w" | grep -q '^issuer=.*Pebble' || fail "*.w.vb19.vz.test: the issuer is not the CA: $w"
dcert=$(cert_for dns.vb19.vz.test)
wcert=$(cert_for '*.w.vb19.vz.test')
rpmgr get certificate "$dcert"
rpmgr get certificate "$wcert"
# The CA validated by DNS-01: the TXT was there, with rpmgr's marker, and nobody asked for HTTP-01.
for h in dns.vb19.vz.test w.vb19.vz.test; do
  grep -q "^dns: TXT _acme-challenge.$h answered, record comment \"rpmgr [^ ]* acme\"" "$S/fakes.log" ||
    fail "the DNS never answered a marked challenge TXT for $h"
done
echo "the DNS answered marked challenge TXT records for both names; HTTP-01 requests since phase d began: +$(($(http_attempts) - http_before))"
(($(http_attempts) == http_before)) || fail "a name of the zone was validated by HTTP-01"
pass "d3 dns.vb19.vz.test is issued by the CA through DNS-01"
pass "d4 *.w.vb19.vz.test is issued by the CA through DNS-01"

step "phase d: the challenge TXT is removed; a held zone publishes no route name"
txt_gone() { record_gone TXT _acme-challenge.dns.vb19.vz.test && record_gone TXT _acme-challenge.w.vb19.vz.test; }
within 60 "the challenge TXT removed" txt_gone
rpmgr list dns-record --zone "$zone" --foreign
record_gone A dns.vb19.vz.test || fail "a held zone has a record of a route"
pass "d5 the challenge TXT records are removed"
pass "d6 a held zone has no record of the route"

step "phase d: the plan is approved, the address record is published, the controller's name is not"
plan_ready() { rpmgr plan zone "$zone" -o json >"$S/plan.json" && jq -e '.hash != ""' "$S/plan.json" >/dev/null; }
within 60 "the plan" plan_ready
cat "$S/plan.json"
jq -e --arg n dns.vb19.vz.test '[.creates[] | select(.type == "A" and .name == $n and .content == "192.0.2.10")] | length == 1' "$S/plan.json" >/dev/null ||
  fail "the plan does not create the address record of dns.vb19.vz.test"
jq -e '[.creates[] | select(.name == "vb19.vz.test")] | length == 0' "$S/plan.json" >/dev/null || fail "the plan writes the controller's own name"
stepup
rpmgr approve zone "$zone" --plan-hash "$(jq -r .hash "$S/plan.json")"
zone_active() { rpmgr get zone "$zone" -o json | jq -e '.syncState == "ZONE_SYNC_STATE_ACTIVE"' >/dev/null; }
within 60 "the zone active after the approval" zone_active
published() { record_is A dns.vb19.vz.test 192.0.2.10; }
within 120 "the A record of dns.vb19.vz.test" published
pass "d7 the address record is published after the approval"
rpmgr list dns-record --zone "$zone" --foreign
rpmgr list route
# The controller's URL is reserved, and a wildcard is held back until the zone allows wildcards.
owned_at() { rpmgr list dns-record --zone "$zone" --foreign -o json |
  jq -e --arg n "$1" '[.. | objects | select((.id // "") != "") | select(.name == $n)] | length == 0' >/dev/null; }
owned_at vb19.vz.test || fail "the controller's own name was written"
owned_at '*.w.vb19.vz.test' || fail "a wildcard was published in a zone that does not allow them"
pass "d8 the controller's name and the wildcard are not written"

step "phase d: the route goes, its record goes"
stepup
rpmgr delete route "$(route_id vb19d)"
rpmgr sync zone "$zone"
within 120 "the record of the deleted route removed" record_gone A dns.vb19.vz.test
within 5 "the challenge TXT still removed" record_gone TXT _acme-challenge.dns.vb19.vz.test
foreign >"$S/foreign.after"
diff "$S/foreign.before" "$S/foreign.after" || fail "a record of someone else changed"
pass "d9 the address record is removed with its route"
pass "d10 the records of others are unchanged"

step "phase d: clean up: the wildcard route, the zone with the records rpmgr owns, the provider"
stepup
rpmgr delete route "$(route_id vb19w)"
rpmgr plan zone "$zone" --delete-records -o json >"$S/removal.json"
cat "$S/removal.json"
jq -e '(.deletes | length) > 0' "$S/removal.json" >/dev/null || fail "the removal plan deletes nothing; the zone's claim TXT is rpmgr's"
jq -e --arg z "$zone" '[.deletes[] | select((.name == $z or (.name | endswith("." + $z))) | not)] | length == 0' "$S/removal.json" >/dev/null ||
  fail "the removal plan names a record outside the zone"
stepup
rpmgr remove zone "$zone" --delete-records --plan-hash "$(jq -r .hash "$S/removal.json")"
zone_gone() { ! rpmgr list zone -o json | grep -q "\"$zone\""; }
within 120 "the zone removed" zone_gone
stepup
rpmgr delete dns-provider "$(rpmgr list dns-provider -o json | jq -r '[.. | objects | select(.name? == "cf") | .id][0]')"
[[ -z $(rpmgr list dns-provider -o json | jq -r '.. | objects | select(.name? == "cf") | .id') ]] || fail "the provider is still listed"
pass "d11 the zone is removed with its records, and the provider is deleted"

step "result"
[[ $a != "$b" && $b != "$c" && $a != "$c" ]] || fail "the serials did not change per phase: $a $b $c"
echo "PASS: own certificate and route certificate issued; renewed by HTTP-01 alone and by TLS-ALPN-01 alone"
echo "PASS: DNS-01 through Cloudflare: name and wildcard issued by the CA, challenge TXT removed, address record published and removed with its route"
stop
