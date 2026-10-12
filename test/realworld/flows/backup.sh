# SPDX-License-Identifier: Apache-2.0
#
# Flow backup of the real-world run (sourced by run.sh): a backup of the running all-in-one, a change
# after it, a restore with the service stopped (docs/10, "Backup and restore"), and the journal.

step "aio: a backup, then a route created after it"
on aio 'rpmgr backup --out /root/rw.backup
rpmgr create route --name after-backup --group default --tcp
rpmgr list route | grep -q after-backup'

step "aio: the restore, with the service stopped"
on aio "systemctl stop rpmgr-all-in-one
rpmgr restore --in /root/rw.backup
systemctl start rpmgr-all-in-one"
within 60 "the all-in-one ready after the restore" aio 'curl -fsS http://127.0.0.1:7381/readyz'
within 60 "the CLI works after the restore" aio 'rpmgr list route'
on aio '! rpmgr list route | grep -q after-backup'
tcp_port=$(on aio "rpmgr list -o json route | jq -r '.[] | select(.name == \"echo-tcp\") | .tcp.port'")
within 120 "echo-tcp after the restore" client "/rw/bin/e2eclient check -addr 172.40.0.10:$tcp_port"

step "the journal: warnings and errors by message"
# The all-in-one's jq reads every journal: the agent hosts have none.
problems() { dc exec -T aio jq -Rr 'fromjson? | select(.level == "ERROR" or .level == "WARN") | [.level, .msg] | @tsv'; }
for h in aio gw2 con1 con2; do
  echo "-- $h"
  on "$h" 'journalctl -u "rpmgr-*" --no-pager -o cat' | problems | sort | uniq -c | sort -rn
done
# The controller logs no error at all, and no warning but the release check, which cannot reach
# GitHub from the internal networks; the agents' warnings are those of the restarts.
if on aio 'journalctl -u rpmgr-all-in-one --no-pager -o cat' | problems | grep -v $'^WARN\trelease check failed' | grep .; then
  fail "the all-in-one logged errors or warnings"
fi
