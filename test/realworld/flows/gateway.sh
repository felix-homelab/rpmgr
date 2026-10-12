# SPDX-License-Identifier: Apache-2.0
#
# Flow gateway of the real-world run (sourced by run.sh): a second gateway group with its gateway on
# Ubuntu 24.04, installed with the command the controller gives (`rpmgr get install-command`) and
# the controller's /install.sh, and the port pools of both groups.

step "aio: the gateway group edge and its gateway gw2"
on aio 'rpmgr create gateway-group --name edge --public-hostname gw2.rw.test
rpmgr create gateway --group edge --name gw2 --tunnel-endpoint gw2.rw.test:443
rpmgr create port-pool --group default --protocol tcp --from 20000 --to 20099
rpmgr create port-pool --group default --protocol udp --from 20000 --to 20099
rpmgr create port-pool --group edge --protocol tcp --from 21000 --to 21099
rpmgr list gateway'
stepup
on aio 'gw=$(rpmgr list -o json gateway | jq -r "[.. | objects | select(.name? == \"gw2\")][0].id")
rpmgr create gateway-token --gateway "$gw" >/root/gw2-token.out
cat /root/gw2-token.out | sed "s/rpmgr_[a-z]*_[0-9A-Za-z_]*/<token>/g"
grep -o "rpmgr_[a-z]*_[0-9A-Za-z_]*" /root/gw2-token.out | head -n 1 >/root/gw2-token
rpmgr get --role gateway install-command >/root/gw2-install'
on aio 'cat /root/gw2-install'

step "gw2: install the gateway with the controller's command"
cmd=$(on aio 'cat /root/gw2-install')
tok=$(on aio 'cat /root/gw2-token')
on gw2 "install -m 0600 /dev/null /root/token && printf '%s\n' '$tok' >/root/token"
# The command as the controller prints it, run as root (no sudo on these hosts), with the token
# from a file, as the install script's usage says.
on gw2 "${cmd//sudo /} \\
  --token-file /root/token"
within 60 "gw2 active" gw2 'systemctl is-active rpmgr-gateway'
within 60 "gw2 ready" gw2 'curl -fsS http://127.0.0.1:7382/readyz'

