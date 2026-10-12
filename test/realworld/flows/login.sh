# SPDX-License-Identifier: Apache-2.0
#
# Flow login of the real-world run (sourced by run.sh): the first user and an API token as the web
# UI makes them, rpmgr login, the instance's ACME CA and the release in the controller's mirror.

v=$version
step "aio: the first user and an API token, with the calls the web UI makes"
on aio 'link=$(grep -o "https://panel.rw.test/setup#[^[:space:]]*" /root/init.out)
api() { curl -fsS --cacert /etc/rpmgr/tls/panel.crt -b /root/cookies -c /root/cookies -H "Content-Type: application/json" \
  -H "Origin: https://panel.rw.test" "https://panel.rw.test/rpmgr.v1.$1" -d "$2"; }
pw=$(openssl rand -hex 16); echo "$pw" >/root/password
api AuthService/CompletePasswordReset "{\"token\":\"${link#*#}\",\"newPassword\":\"$pw\",\"email\":\"ops@rw.test\",\"displayName\":\"Ops\"}" >/dev/null
api AuthService/Login "{\"email\":\"ops@rw.test\",\"password\":\"$pw\"}" >/dev/null
api AuthService/StepUp "{\"password\":\"$pw\"}" >/dev/null
api AuthService/GetSession "{}" | jq -r ".memberships[0].orgId" >/root/org
install -m 0600 /dev/null /root/token
api TokenService/CreateAPIToken "{\"orgId\":\"$(cat /root/org)\",\"name\":\"ops\",\"ttl\":\"86400s\",\"scopes\":[\"org.read\",\"org.write\",\"routes.write\",\"connectors.write\",\"infrastructure.write\",\"audit.read\",\"instance.admin\"]}" |
  jq -r .token >/root/token'

step "aio: rpmgr login"
on aio 'cp /etc/rpmgr/tls/panel.crt /root/ca.pem
rpmgr login --controller https://panel.rw.test --org "$(cat /root/org)" --token-file /root/token --ca-file /root/ca.pem'

step "aio: the instance's ACME CA, then the controller's own certificate from it"
on aio 'rpmgr update settings --instance --set acme_directory_url=https://pebble:14000/dir --set acme_email=ops@rw.test
sed -i "/^tls:$/,/^  key_file:/d" /etc/rpmgr/all-in-one.yaml
systemctl restart rpmgr-all-in-one'
within 120 "the controller's own certificate from the CA" aio \
  'openssl s_client -connect 127.0.0.1:443 -servername panel.rw.test </dev/null 2>/dev/null | openssl x509 -noout -issuer | grep -q Pebble'
on aio 'openssl s_client -connect 127.0.0.1:443 -servername panel.rw.test -showcerts </dev/null 2>/dev/null |
  awk "/BEGIN CERT/{n++} n>=2" | sed -n "/BEGIN CERT/,/END CERT/p" >>/root/ca.pem
rpmgr list route >/dev/null'

step "aio: the release in the controller's /dl/ mirror"
on aio 'rpmgr release import /root/rel'
within 30 "the mirror serves the manifest" client "curl -fsS --cacert /rw/pebble/root.pem https://panel.rw.test/dl/$v/manifest.json"
