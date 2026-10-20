# SPDX-License-Identifier: Apache-2.0
#
# Flow routes of the real-world run (sourced by run.sh): the org's domain proved over HTTP, then a
# route of every Phase 1 type with targets on both connectors: tcp and udp on the default group, http
# with ACME on both groups, http with an uploaded certificate, and tls_passthrough.

step "aio: the domain rw.test, claimed for an HTTP proof and marked trusted"
# rw.test resolves to the gateways' addresses on the run's private network, which an HTTP proof
# never connects to (docs/04-security.md, "Route and hostname ownership"): the proof is refused as
# such, and the Instance Admin marks the claim trusted, as a LAN-only installation does.
on aio 'rpmgr create domain --fqdn rw.test --wildcard --method http | tee /root/domain.out
grep -o -m 1 "dom_[0-9A-Z]*" /root/domain.out >/root/domain'
within 90 "the HTTP proof refused for a private address" \
  aio 'rpmgr verify domain "$(cat /root/domain)" 2>&1 | grep -q "not public"'
stepup
on aio 'rpmgr trust domain "$(cat /root/domain)" | grep -q "is VERIFIED"'

step "aio: a certificate to upload for cert.rw.test, from a private CA"
on aio 'cd /root && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -subj /CN=rw-private-ca \
  -keyout private-ca.key -out private-ca.pem 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=cert.rw.test -keyout cert.key -out cert.csr 2>/dev/null
printf "subjectAltName=DNS:cert.rw.test\n" >cert.ext
openssl x509 -req -in cert.csr -CA private-ca.pem -CAkey private-ca.key -CAcreateserial -days 30 -extfile cert.ext -out cert.pem 2>/dev/null
cat cert.pem private-ca.pem >cert-chain.pem
chmod 0600 cert.key
rpmgr upload certificate --chain cert-chain.pem --key cert.key | tee /root/upload.out
grep -o -m 1 "crt_[0-9A-Z]*" /root/upload.out >/root/cert'
cp_ca=$(on aio 'cat /root/private-ca.pem')
printf '%s\n' "$cp_ca" >"$RW_RUN/out/private-ca.pem"

step "aio: the routes and their targets"
on aio 'svc=172.41.0.30
route() { rpmgr create route "$@"; }
target() { for c in con1 con2; do rpmgr create route-target --route "$1" --connector "$c" --address "$svc:$2"; done; }
route --name echo-tcp --group default --tcp && target echo-tcp 7007
route --name echo-udp --group default --udp && target echo-udp 7008
route --name web --group default --http --hostname app.rw.test --tls-mode acme && target web 7080
route --name web-cert --group default --http --hostname cert.rw.test --tls-mode certificate --certificate "$(cat /root/cert)" && target web-cert 7080
route --name passthrough --group default --tls-passthrough --hostname pt.rw.test && target passthrough 7443
route --name web-edge --group edge --http --hostname app2.rw.test --tls-mode acme && target web-edge 7080
route --name echo-edge --group edge --tcp && target echo-edge 7007
rpmgr list route'
