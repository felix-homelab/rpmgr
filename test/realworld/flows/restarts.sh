# SPDX-License-Identifier: Apache-2.0
#
# Flow restarts of the real-world run (sourced by run.sh): systemctl restarts of every service, a
# reboot of a connector host and of the all-in-one host, and the agents' own status and diagnostics.

tcp_port=$(on aio "rpmgr list -o json route | jq -r '.[] | select(.name == \"echo-tcp\") | .tcp.port'")
edge_port=$(on aio "rpmgr list -o json route | jq -r '.[] | select(.name == \"echo-edge\") | .tcp.port'")
served() {
  within 120 "$1" client "/rw/bin/e2eclient check -addr 172.40.0.10:$tcp_port && /rw/bin/e2eclient check -addr 172.40.0.11:$edge_port &&
    curl -fsS --cacert /rw/pebble/root.pem --resolve app2.rw.test:443:172.40.0.11 https://app2.rw.test/r | grep -q app2"
}

step "systemctl restart of every service"
on gw2 'systemctl restart rpmgr-gateway'
on con1 'systemctl restart rpmgr-connector'
on aio 'systemctl restart rpmgr-all-in-one'
served "the routes after the restarts"

step "con1 and aio rebooted"
dc restart -t 10 con1 aio >/dev/null
within 90 "systemd on con1" con1 'systemctl is-system-running --wait | grep -qE "running|degraded"'
within 90 "systemd on aio" aio 'systemctl is-system-running --wait | grep -qE "running|degraded"'
within 60 "the all-in-one ready after its reboot" aio 'curl -fsS http://127.0.0.1:7381/readyz'
within 60 "con1 ready after its reboot" con1 'curl -fsS http://127.0.0.1:7383/readyz'
served "the routes after the reboots"

step "the agents' status and diagnostics"
on con1 'rpmgr status'
on gw2 'rpmgr status'
# The binary under test reads the gateway's boot file /install.sh wrote as a gateway's.
on gw2 '/rw/bin/rpmgr status | grep -E "^Role: +gateway "'
on con1 'rpmgr diag transport'
on gw2 'rpmgr diag clock'
