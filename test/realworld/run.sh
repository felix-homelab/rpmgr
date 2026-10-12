#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The real-world run (README.md): real release binaries on hosts that run systemd, installed and
# operated the way docs/10, docs/16 and the VB-19 run sheet tell an operator to. It verifies the
# release, installs an all-in-one on Debian 12, a second gateway on Ubuntu 24.04 and connectors on
# Ubuntu 24.04 and Rocky Linux 9 through the controller's /install.sh, creates a route of every
# Phase 1 type, sends traffic through both gateways, changes access and local policies, restarts
# services and hosts, and backs the controller up and restores it. Pebble stands in for the ACME
# CA; the networks are internal, so nothing reaches the internet. Needs Docker, Go and minisign.
#
# Usage: run.sh [--release <dir>] [--binary <rpmgr>] [--kek file|systemd-credential] [--keep]
#               [--from <flow>]
#   --release  the release files (manifest, signatures, binaries), default: v0.1.0-rc.1 downloaded
#              with gh into the run directory
#   --binary   the rpmgr installed on the all-in-one, default the release's linux-amd64; the agents
#              always get the release's binary through /install.sh
#   --kek      the all-in-one's KEK source; default: what init chooses (systemd-credential)
#   --keep     leave the containers running afterwards
#   --from     with the containers of a run kept with --keep, run the flows from this one on:
#              aio, login, gateway, connectors, routes, traffic, policies, restarts, backup
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(git -C "$here" rev-parse --show-toplevel)
version=0.1.0-rc.1
release='' binary='' kek='' keep=0 from=''
while (($#)); do
  case $1 in
    --release) release=$2; shift 2 ;;
    --binary) binary=$2; shift 2 ;;
    --kek) kek=$2; shift 2 ;;
    --keep) keep=1; shift ;;
    --from) from=$2; keep=1; shift 2 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done

export RW_RUN=${RW_RUN:-$(mktemp -d)}
mkdir -p "$RW_RUN"/{bin,release,pebble,svc,out}
dc() { docker compose -f "$here/compose.yaml" "$@"; }
step() { printf '\n== %s (%s)\n' "$*" "$(date -u +%H:%M:%S)"; }
fail() {
  printf 'FAIL: %s\n' "$*"
  exit 1
}
# on <host> <script>: runs a bash script on a host, as root, as an operator's shell would.
on() { dc exec -T "$1" bash -euo pipefail -c "$2"; }
# within <seconds> <what> <host> <script>: runs the script on the host every 2 s until it succeeds.
within() {
  local n=$1 what=$2 host=$3 script=$4
  for ((i = 0; i < n; i += 2)); do
    if on "$host" "$script" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  on "$host" "$script" || true
  fail "$what: not within $n s"
}
# stepup steps the CLI's token up through the API, for the commands that need one: rpmgr asks for
# the factor on a terminal only.
stepup() {
  on aio 'curl -fsS --cacert /root/ca.pem -H "Authorization: Bearer $(cat /root/token)" -H "Content-Type: application/json" \
    https://panel.rw.test/rpmgr.v1.AuthService/StepUp -d "{\"password\":\"$(cat /root/password)\"}" >/dev/null'
}
finish() {
  status=$?
  if ((status != 0)); then
    for h in aio gw2 con1 con2; do
      echo "-- journal of $h, last lines:"
      on "$h" 'journalctl -u "rpmgr-*" -n 25 --no-pager' 2>/dev/null || true
    done
  fi
  if ((keep == 0)); then
    dc down -t 1 >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap finish EXIT

prepare() {
step "prepare: release, binaries, images"
if [[ -z $release ]]; then
  release=$RW_RUN/download
  mkdir -p "$release"
  gh release download "v$version" --repo felix-homelab/rpmgr --dir "$release" --clobber \
    --pattern 'manifest.json*' --pattern 'signing-key.json*' --pattern SHA256SUMS --pattern "rpmgr-$version-linux-*"
fi
for f in manifest.json manifest.json.minisig signing-key.json signing-key.json.minisig SHA256SUMS; do
  install -m 0644 "$release/$f" "$RW_RUN/release/$f"
done
for f in "$release"/rpmgr-"$version"-linux-*; do
  install -m 0644 "$f" "$RW_RUN/release/"
done
install -m 0755 "${binary:-$release/rpmgr-$version-linux-amd64}" "$RW_RUN/bin/rpmgr"
export PATH=$HOME/.local/go1.27.1/bin:$PATH
CGO_ENABLED=0 go -C "$root" build -o "$RW_RUN/bin/e2eclient" ./test/e2e/e2eclient
pv=$(go -C "$root" list -m -f '{{.Version}}' github.com/letsencrypt/pebble/v2)
CGO_ENABLED=0 GOBIN="$RW_RUN/bin" go install "github.com/letsencrypt/pebble/v2/cmd/pebble@$pv" \
  "github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@$pv"
certs="$(go -C "$root" list -m -f '{{.Dir}}' github.com/letsencrypt/pebble/v2)/test/certs"
install -m 0644 "$certs/localhost/cert.pem" "$certs/localhost/key.pem" "$certs/pebble.minica.pem" "$RW_RUN/pebble/"
if [[ ! -f $RW_RUN/svc/tls.crt ]]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -subj /CN=svc-backend \
    -addext subjectAltName=DNS:pt.rw.test -keyout "$RW_RUN/svc/tls.key" -out "$RW_RUN/svc/tls.crt" 2>/dev/null
  chmod 0644 "$RW_RUN/svc/tls.key"
fi
cat >"$RW_RUN/pebble.json" <<'EOF'
{"pebble": {"listenAddress": "0.0.0.0:14000", "managementListenAddress": "0.0.0.0:15000",
  "certificate": "/rw/pebble/cert.pem", "privateKey": "/rw/pebble/key.pem",
  "httpPort": 80, "tlsPort": 443, "ocspResponderURL": "", "externalAccountBindingRequired": false}}
EOF
for d in debian12 ubuntu2404 rocky9; do
  docker build -q -t "rpmgr-rw-$d" -f "$here/hosts/$d.Dockerfile" "$here/hosts" >/dev/null
done
docker build -q -t rpmgr-rw-tools -f "$here/tools.Dockerfile" "$here" >/dev/null
dc down -t 1 >/dev/null 2>&1 || true
dc up -d >/dev/null
for h in aio gw2 con1 con2; do
  within 60 "systemd on $h" "$h" 'systemctl is-system-running --wait | grep -qE "running|degraded"'
done

step "the CA: Pebble and its DNS, with the names of the hosts"
dc exec -T -d ca sh -c '/rw/bin/pebble-challtestsrv -defaultIPv4 "" -defaultIPv6 "" -dnsserver :8053 -http01 "" \
  -https01 "" -tlsalpn01 "" -doh "" -management :8055 >/tmp/challtestsrv.log 2>&1'
dc exec -T -d -e PEBBLE_VA_NOSLEEP=1 -e PEBBLE_WFE_NONCEREJECT=0 ca \
  sh -c '/rw/bin/pebble -config /rw/pebble.json -dnsserver 127.0.0.1:8053 >/tmp/pebble.log 2>&1'
within 30 "Pebble" client 'curl -fsS --cacert /rw/pebble/pebble.minica.pem https://pebble:14000/dir'
for n in panel app cert pt; do
  on ca "curl -fsS -X POST localhost:8055/add-a -d '{\"host\":\"$n.rw.test\",\"addresses\":[\"172.40.0.10\"]}'"
done
for n in gw2 app2; do
  on ca "curl -fsS -X POST localhost:8055/add-a -d '{\"host\":\"$n.rw.test\",\"addresses\":[\"172.40.0.11\"]}'"
done
# Pebble's issuing root stands in for a CA every host trusts, as Let's Encrypt's root is.
on ca 'curl -fsS --cacert /rw/pebble/pebble.minica.pem https://localhost:15000/roots/0' >"$RW_RUN/pebble/root.pem"
for h in aio gw2 con1 con2 client; do
  case $h in
    con2) on "$h" 'cp /rw/pebble/root.pem /etc/pki/ca-trust/source/anchors/rw-acme.pem && update-ca-trust' ;;
    client) ;;
    *) on "$h" 'cp /rw/pebble/root.pem /usr/local/share/ca-certificates/rw-acme.crt && update-ca-certificates >/dev/null' ;;
  esac
done
# The controller fetches the ACME directory over TLS: Pebble's own server certificate.
on aio 'cp /rw/pebble/pebble.minica.pem /usr/local/share/ca-certificates/rw-pebble.crt && update-ca-certificates >/dev/null'
}

flows=(aio login gateway connectors routes traffic policies restarts backup)
if [[ -z $from ]]; then
  prepare
  from=aio
fi
started=0
for f in "${flows[@]}"; do
  [[ $f == "$from" ]] && started=1
  if ((started)); then
    # shellcheck source=/dev/null
    . "$here/flows/$f.sh"
  fi
done
((started)) || fail "no flow $from"
step "done in $SECONDS s"
