# SPDX-License-Identifier: Apache-2.0
#
# Flow aio of the real-world run (sourced by run.sh): verify the release and install the
# all-in-one on Debian 12 as docs/10 and the VB-19 run sheet tell an operator to.

root1=RWQHGtnjCdWFdPvZeuywSw5/cVCITz37J5OJpW8a6b3o1IrSSH3WUJ+/
v=$version

step "aio: verify the release (VB-19 run sheet, step 1)"
on aio "mkdir -p /root/rel && cp /rw/release/* /root/rel/ && cd /root/rel
minisign -Vm signing-key.json -P $root1
signer=\$(sed -n 's/.*\"signer\": *\"\\([^\"]*\\)\".*/\\1/p' signing-key.json)
minisign -Vm manifest.json -P \"\$signer\"
h=\$(sha256sum rpmgr-$v-linux-amd64 | cut -d' ' -f1)
grep -q \"\\\"sha256\\\": *\\\"\$h\\\"\" manifest.json"

step "aio: install the all-in-one (docs/10, Supported platforms)"
kekflag=''
[[ -n $kek ]] && kekflag="--kek-source $kek"
on aio "install -m 0755 /rw/bin/rpmgr /usr/local/bin/rpmgr
rpmgr version --verbose
useradd --system --user-group --home-dir /var/lib/rpmgr --shell /usr/sbin/nologin rpmgr
install -d -m 0755 /etc/rpmgr
install -d -m 0750 -o rpmgr -g rpmgr /var/lib/rpmgr
rpmgr all-in-one init --public-url https://panel.rw.test $kekflag >/root/init.out
sed 's|setup#.*|setup#<link>|' /root/init.out"

step "aio: a self-signed certificate until the instance points at the CA (run sheet, step 2)"
on aio 'install -d -m 0755 /etc/rpmgr/tls
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=panel.rw.test \
  -addext subjectAltName=DNS:panel.rw.test -keyout /etc/rpmgr/tls/panel.key -out /etc/rpmgr/tls/panel.crt 2>/dev/null
chgrp rpmgr /etc/rpmgr/tls/panel.key && chmod 0640 /etc/rpmgr/tls/panel.key
printf "tls:\n  cert_file: %s\n  key_file: %s\n" /etc/rpmgr/tls/panel.crt /etc/rpmgr/tls/panel.key >>/etc/rpmgr/all-in-one.yaml'

step "aio: the systemd unit"
on aio 'rpmgr systemd-unit all-in-one >/etc/systemd/system/rpmgr-all-in-one.service
systemctl daemon-reload
systemctl enable --now rpmgr-all-in-one'
within 60 "the all-in-one ready" aio 'curl -fsS http://127.0.0.1:7381/readyz'
on aio 'systemctl is-active rpmgr-all-in-one; journalctl -u rpmgr-all-in-one -n 5 --no-pager -o cat'

