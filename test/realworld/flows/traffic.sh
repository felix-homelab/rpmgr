# SPDX-License-Identifier: Apache-2.0
#
# Flow traffic of the real-world run (sourced by run.sh): a client on the public network uses every
# route through the gateway that serves it.

# `rpmgr get` takes an ID only: the public port comes from the list, by the route's name.
port_of() { on aio "rpmgr list -o json route | jq -r '.[] | select(.name == \"$1\") | (.tcp // .udp).port'"; }
tcp_port=$(port_of echo-tcp)
udp_port=$(port_of echo-udp)
edge_port=$(port_of echo-edge)
echo "public ports: tcp $tcp_port, udp $udp_port, edge tcp $edge_port"
[[ $tcp_port =~ ^[0-9]+$ && $udp_port =~ ^[0-9]+$ && $edge_port =~ ^[0-9]+$ ]] || fail "a route without a public port"

step "client: tcp and udp through the all-in-one's gateway, tcp through gw2"
within 60 "tcp through aio" client "/rw/bin/e2eclient check -addr 172.40.0.10:$tcp_port"
within 60 "udp through aio" client "/rw/bin/e2eclient udp -addr 172.40.0.10:$udp_port -sizes 100,1200"
within 60 "tcp through gw2" client "/rw/bin/e2eclient check -addr 172.40.0.11:$edge_port"

step "client: http with ACME certificates, on both groups"
within 180 "app.rw.test with a certificate from the CA" client \
  'curl -fsS --cacert /rw/pebble/root.pem --resolve app.rw.test:443:172.40.0.10 https://app.rw.test/hello | grep -q "app.rw.test /hello"'
within 180 "app2.rw.test through gw2" client \
  'curl -fsS --cacert /rw/pebble/root.pem --resolve app2.rw.test:443:172.40.0.11 https://app2.rw.test/hello | grep -q "app2.rw.test /hello"'

step "client: http with the uploaded certificate, and tls_passthrough to the service's own certificate"
within 60 "cert.rw.test" client \
  'curl -fsS --cacert /rw/out/private-ca.pem --resolve cert.rw.test:443:172.40.0.10 https://cert.rw.test/x | grep -q "cert.rw.test /x"'
within 60 "pt.rw.test passed through" client \
  'openssl s_client -connect 172.40.0.10:443 -servername pt.rw.test </dev/null 2>/dev/null | openssl x509 -noout -subject | grep -q svc-backend'
