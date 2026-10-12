# SPDX-License-Identifier: Apache-2.0
#
# Flow policies of the real-world run (sourced by run.sh): an access policy that denies the client,
# then the connector-local policy of each connector, changed with `rpmgr policy` on its host.

tcp_port=$(on aio "rpmgr list -o json route | jq -r '.[] | select(.name == \"echo-tcp\") | .tcp.port'")

step "aio: an access policy denies the client on echo-tcp, then is taken off again"
on aio "rpmgr create access-policy --name no-client --rule deny:172.40.0.40/32
rpmgr update route --policy no-client echo-tcp"
within 60 "the client refused" client "! /rw/bin/e2eclient check -addr 172.40.0.10:$tcp_port"
on aio "rpmgr update route --policy '' echo-tcp && rpmgr delete access-policy no-client"
within 60 "the client served again" client "/rw/bin/e2eclient check -addr 172.40.0.10:$tcp_port"

step "con1, con2: the local policy takes the tcp target out on each connector, then allows it again"
on con1 'rpmgr policy remove-target 172.41.0.30:7007 && rpmgr policy show'
within 60 "echo-tcp served by con2 alone" client "/rw/bin/e2eclient check -addr 172.40.0.10:$tcp_port"
on con2 'rpmgr policy remove-target 172.41.0.30:7007'
within 60 "echo-tcp refused by both local policies" client "! /rw/bin/e2eclient check -addr 172.40.0.10:$tcp_port"
on aio "rpmgr list -o json route | jq -r '.[] | select(.name == \"echo-tcp\") | .status'"
on con1 'rpmgr policy allow-target 172.41.0.30:7007'
on con2 'rpmgr policy allow-target 172.41.0.30:7007'
within 60 "echo-tcp served again" client "/rw/bin/e2eclient check -addr 172.40.0.10:$tcp_port"
