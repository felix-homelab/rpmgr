#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Rehearses the VB-19 run sheet (README.md) locally, without Let's Encrypt: the same rpmgr
# commands against Pebble, in a container without a network, where iptables stands in for the
# cloud firewall. It builds rpmgr from this checkout, Pebble and its DNS server at the version of
# go.mod, runs every step of the sheet and checks the outcome. Needs Go and Docker.
#
# Differences from the real run, each because the rehearsal has no internet:
# - Pebble is the CA, at https://localhost:14000/dir; rpmgr trusts its TLS through SSL_CERT_FILE.
# - The names vb19.test and app.vb19.test resolve to 127.0.0.2 for the CA (its own DNS server),
#   which plays the VM's public IP; for the host itself, /etc/hosts sends them to 127.0.0.1, as
#   the run sheet's /etc/hosts entries do on the VM. The firewall rules close 80 or 443 of
#   127.0.0.2 only.
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
  CGO_ENABLED=0 GOBIN="$work/bin" go install "github.com/letsencrypt/pebble/v2/cmd/pebble@$ver" \
    "github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@$ver"
  certs="$(go -C "$root" list -m -f '{{.Dir}}' github.com/letsencrypt/pebble/v2)/test/certs"
  cp "$certs/localhost/cert.pem" "$certs/localhost/key.pem" "$certs/pebble.minica.pem" "$work/pebble/"
  cp "$here/rehearse.sh" "$work/"
  docker build -q -t rpmgr-vb19-rehearsal "$here" >/dev/null
  docker run --rm --network none --cap-add NET_ADMIN \
    --add-host vb19.test:127.0.0.1 --add-host app.vb19.test:127.0.0.1 \
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

step "the CA: Pebble and its DNS server"
pebble-challtestsrv -defaultIPv4 "$public" -defaultIPv6 "" -dnsserver 127.0.0.1:8053 -http01 "" \
  -https01 "" -tlsalpn01 "" -doh "" -management 127.0.0.1:8055 >"$S/challtestsrv.log" 2>&1 &
cat >"$S/pebble.json" <<'EOF'
{"pebble": {"listenAddress": "127.0.0.1:14000", "managementListenAddress": "127.0.0.1:15000",
  "certificate": "/vb19/pebble/cert.pem", "privateKey": "/vb19/pebble/key.pem",
  "httpPort": 80, "tlsPort": 443, "ocspResponderURL": "", "externalAccountBindingRequired": false}}
EOF
PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=0 PEBBLE_AUTHZREUSE=100 \
  pebble -config "$S/pebble.json" -dnsserver 127.0.0.1:8053 >"$S/pebble.log" 2>&1 &
within 30 "Pebble's directory" curl -fsS --cacert /vb19/pebble/pebble.minica.pem https://localhost:14000/dir

step "install, as docs/10 describes it, with the KEK in a file (no systemd here)"
install -m 0755 /vb19/bin/rpmgr /usr/local/bin/rpmgr
useradd --system --user-group --home-dir /var/lib/rpmgr --shell /usr/sbin/nologin rpmgr
install -d -m 0755 /etc/rpmgr
install -d -m 0750 -o rpmgr -g rpmgr /var/lib/rpmgr
rpmgr all-in-one init --config /etc/rpmgr/all-in-one.yaml --public-url https://vb19.test \
  --kek-source file --kek-path /etc/rpmgr/kek | tee "$S/init.out"
link=$(grep -o 'https://vb19.test/setup#[^[:space:]]*' "$S/init.out") || fail "no setup link"
grep -q '^tls:' /etc/rpmgr/all-in-one.yaml && fail "init wrote a tls section; the sheet adds one"

step "a self-signed certificate until the CA is staging"
install -d -m 0755 /etc/rpmgr/tls
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=vb19.test \
  -addext subjectAltName=DNS:vb19.test -keyout /etc/rpmgr/tls/panel.key -out /etc/rpmgr/tls/panel.crt 2>/dev/null
chgrp rpmgr /etc/rpmgr/tls/panel.key && chmod 0640 /etc/rpmgr/tls/panel.key
printf 'tls:\n  cert_file: %s\n  key_file: %s\n' /etc/rpmgr/tls/panel.crt /etc/rpmgr/tls/panel.key \
  >>/etc/rpmgr/all-in-one.yaml
# init gives what it created in the state directory to the service user (docs/10, "Install").
[[ -z $(find /var/lib/rpmgr ! -user rpmgr) ]] || fail "init left files in /var/lib/rpmgr that rpmgr does not own"

# start runs the all-in-one as the unit does: as the user rpmgr, with CAP_NET_BIND_SERVICE only. It
# trusts Pebble's TLS certificate through SSL_CERT_FILE, a copy the user can read.
install -m 0644 /vb19/pebble/pebble.minica.pem /etc/rpmgr/pebble-ca.pem
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
api() { # api <service/method> <JSON body>
  curl -fsS --cacert /etc/rpmgr/tls/panel.crt -b "$S/cookies" -c "$S/cookies" -H 'Content-Type: application/json' \
    -H 'Origin: https://vb19.test' "https://vb19.test/rpmgr.v1.$1" -d "$2"
}
pw=$(openssl rand -hex 16)
api AuthService/CompletePasswordReset "{\"token\":\"${link#*#}\",\"newPassword\":\"$pw\",\"email\":\"ada@vb19.test\",\"displayName\":\"Ada\"}" >/dev/null
api AuthService/Login "{\"email\":\"ada@vb19.test\",\"password\":\"$pw\"}" >/dev/null
api AuthService/StepUp "{\"password\":\"$pw\"}" >/dev/null
org=$(api AuthService/GetSession '{}' | jq -r '.memberships[0].orgId')
install -m 0600 /dev/null "$S/token"
api TokenService/CreateAPIToken "{\"orgId\":\"$org\",\"name\":\"vb19\",\"ttl\":\"86400s\",\"scopes\":[\"org.read\",\"routes.write\",\"infrastructure.write\",\"instance.admin\"]}" |
  jq -r .token >"$S/token"

step "rpmgr login"
cp /etc/rpmgr/tls/panel.crt "$S/ca.pem"
rpmgr login --controller https://vb19.test --org "$org" --token-file "$S/token" --ca-file "$S/ca.pem"

step "the instance's ACME settings"
rpmgr get --instance settings | tee "$S/settings.before"
grep -q acme_directory_url "$S/settings.before" || fail "no setting acme_directory_url"
grep -q acme_email "$S/settings.before" || fail "no setting acme_email"
rpmgr update settings --instance --set acme_directory_url=https://localhost:14000/dir --set acme_email=vb19-a@vb19.test

step "phase a: the controller's own certificate, from the CA"
sed -i '/^tls:$/,/^  key_file:/d' /etc/rpmgr/all-in-one.yaml
grep -q '^tls:' /etc/rpmgr/all-in-one.yaml && fail "the tls section is still there"
stop
start
within 120 "the controller's own certificate from the CA" issued_by_pebble vb19.test
served vb19.test
# The run sheet's command: the chain's issuing certificates join the CA file.
openssl s_client -connect 127.0.0.1:443 -servername vb19.test -showcerts </dev/null 2>/dev/null |
  awk '/BEGIN CERT/{n++} n>=2' | sed -n '/BEGIN CERT/,/END CERT/p' >>"$S/ca.pem"
(($(grep -c 'BEGIN CERT' "$S/ca.pem") > 1)) || fail "the served chain has no issuing certificate"
rpmgr list route >/dev/null || fail "the CLI does not trust the controller's new certificate"

step "the domain, proved over HTTP"
rpmgr create domain --fqdn vb19.test --wildcard --method http | tee "$S/domain.out"
did=$(grep -o -m 1 'dom_[0-9A-Z]*' "$S/domain.out")
verified() {
  rpmgr verify domain "$did" >"$S/verify.out" 2>&1
  grep -q 'is VERIFIED' "$S/verify.out"
}
within 90 "the domain verified" verified
cat "$S/verify.out"
rpmgr get domain "$did"

step "phase a: the route's certificate"
rpmgr create route --name vb19 --group default --http --hostname app.vb19.test --tls-mode acme
within 120 "the route's certificate from the CA" issued_by_pebble app.vb19.test
rpmgr list -o json certificate >"$S/certs.json"
cat "$S/certs.json"
cid=$(jq -r '[.. | objects | select(has("sans")) | select(.sans | index("app.vb19.test"))][0].id' "$S/certs.json")
[[ -n $cid && $cid != null ]] || fail "no certificate for app.vb19.test in rpmgr list certificate"
rpmgr get certificate "$cid"
a=$(served app.vb19.test | grep serial)
echo "phase a: $a"

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
renew_phase b 443 vb19-b@vb19.test
within 60 "phase b: the renewed certificate served" bash -c "! openssl s_client -connect $public:443 -servername app.vb19.test </dev/null 2>/dev/null | openssl x509 -noout -serial | grep -qx '$a'"
b=$(served app.vb19.test | grep serial)
echo "phase b: $b"

step "phase c: TCP 80 closed, renewal with a new account: TLS-ALPN-01"
renew_phase c 80 vb19-c@vb19.test
within 60 "phase c: the renewed certificate served" bash -c "! openssl s_client -connect $public:443 -servername app.vb19.test </dev/null 2>/dev/null | openssl x509 -noout -serial | grep -qx '$b'"
c=$(served app.vb19.test | grep serial)
echo "phase c: $c"

step "result"
[[ $a != "$b" && $b != "$c" && $a != "$c" ]] || fail "the serials did not change per phase: $a $b $c"
echo "PASS: own certificate and route certificate issued; renewed by HTTP-01 alone and by TLS-ALPN-01 alone"
stop
