# SPDX-License-Identifier: Apache-2.0
#
# Flow connectors of the real-world run (sourced by run.sh): two connectors on Ubuntu 24.04 and
# Rocky Linux 9, installed with the command the controller gives and its /install.sh, allowed to
# reach the services on the private network.

step "aio: the connectors' install command"
on aio 'rpmgr get --allow-target 172.41.0.30:7007 --allow-target 172.41.0.30:7008 --allow-target 172.41.0.30:7080 \
  --allow-target 172.41.0.30:7443 install-command >/root/con-install
cat /root/con-install'
cmd=$(on aio 'cat /root/con-install')
for c in con1 con2; do
  step "$c: an enrollment token, then the connector installed with the controller's command"
  stepup
  # A token enrolls one connector, unless it is for ephemeral connectors.
  tok=$(on aio 'rpmgr create enrollment-token | grep -o "rpmgr_[a-z]*_[0-9A-Za-z_]*" | head -n 1')
  on "$c" "install -m 0600 /dev/null /root/token && printf '%s\n' '$tok' >/root/token"
  on "$c" "${cmd//sudo /} \\
  --token-file /root/token"
  within 60 "$c active" "$c" 'systemctl is-active rpmgr-connector'
  within 60 "$c ready" "$c" 'curl -fsS http://127.0.0.1:7383/readyz'
done
on aio 'rpmgr list connector'
for h in gw2 con1 con2; do
  on "$h" '[[ $(stat -c %a /etc/sysctl.d/60-rpmgr.conf) == 644 ]]' || fail "$h: /etc/sysctl.d/60-rpmgr.conf is not 0644"
done
