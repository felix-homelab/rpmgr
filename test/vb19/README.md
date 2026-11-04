# VB-19 run sheet: ACME against Let's Encrypt staging, and a first install of the rc

This sheet is all of VB-19 ([13](../../docs/13-roadmap.md#verification-backlog)): the HTTP-01 and
TLS-ALPN-01 part, which v0.1.0 was released without, and the DNS-01 part through Cloudflare. It runs
in one session on a public VM, before the first release with DNS-01, v0.4.0
([D98](../../docs/14-open-decisions.md#project-and-process)). On a release candidate, the same
session is its "fresh install" of the release checklist
([RELEASING](../../RELEASING.md#release-process)).

The real product runs on a throw-away VM: an all-in-one installed from the release under test. It
obtains the certificate of its public URL and of one route from Let's Encrypt **staging**, then:
- **renews** the route's certificate twice: with TCP 443 closed, which only HTTP-01 can pass, and
  with TCP 80 closed, which only TLS-ALPN-01 can pass (phases b and c);
- **connects Cloudflare** with a scoped token, imports your zone, and has the product obtain the
  certificate of a route and a wildcard certificate by DNS-01, publish the route's address record,
  and remove it again with its route (phase d).

Each validation comes from the internet, from Let's Encrypt's several vantage points.

`rehearse.sh` runs the same steps locally against Pebble and the fakes of this repository, and
checks the outcome ([Rehearsal](#rehearsal)). Never point the instance at Let's Encrypt's
production directory during this run.

**What you do, in short:** prepare ([Prepare](#prepare), about 45 minutes), then steps 1 to 5 and
the phases a to d ([about 2 hours](#how-long-it-takes)), then paste back the PASS and FAIL lines
([Record](#record)). Nothing here prints a token.

## Prepare

Placeholders in angle brackets (`<vm-ip>`, `<email-1>`, `<org ID>`) are the values to fill in;
everything else is typed as it stands.

- **VM:** a Linux of the supported list ([10](../../docs/10-operations.md#supported-platforms)),
  for example Debian 12, with a public IPv4 address, called `<vm-ip>`, and SSH. Install `openssl`,
  `curl`, `jq`, `dnsutils` (for `dig`) and `minisign`.
- **Firewall:** the provider's firewall in front of the VM allows TCP 80 and TCP 443 from
  anywhere. During the run you close one of them at a time, so find out beforehand how to change
  the rules quickly. A VM without such a firewall uses `iptables` on its public interface instead
  ([Phase b](#phase-b-tcp-443-closed-http-01)).
- **Names:** a name in your Cloudflare zone `zpxse.cc`, called `<name>` below, for example
  `vb19.zpxse.cc`. Make two A records in the Cloudflare dashboard, **DNS only** (grey cloud, no
  proxy), both with `<vm-ip>`: `<name>`, the controller's public URL, and `app.<name>`, the first
  route. Phase d starts with the records of `app.<name>` deleted, because rpmgr publishes that name
  itself.
- **E-mail:** three addresses that reach you, one ACME account each:
  - `<email-1>` for phase a, the certificates of the controller and of the route;
  - `<email-2>` for phase b, the renewal with 443 closed (HTTP-01);
  - `<email-3>` for phase c, the renewal with 80 closed (TLS-ALPN-01), and the account that phase d
    goes on with.

  An ACME account may reuse an authorisation it validated before, without a new validation. A new
  account per phase makes the CA validate again, through the one port left open. `you+vb19a@…`,
  `you+vb19b@…` and `you+vb19c@…` do.
- **Cloudflare token:** an API token, not the Global API Key, with the permissions Zone / Zone /
  Read and Zone / DNS / Edit, restricted to the zone `zpxse.cc` and expiring within a few days. Put
  it in a file on your workstation, `./cf-token`, mode 0600, and copy it to the VM in step 6 with
  `scp`. It is never typed on a command line and never printed.
- **Keys:** the public keys of the two roots from the key ceremony
  ([RELEASING](../../RELEASING.md#release-signing-keys)), and the key IDs recorded on paper.
- **Workstation:** a second machine for the checks "from the internet". With `gh`, it also
  verifies the release's provenance attestation, the keyless signature of each release file.

Below, `v` is the version and `a` the architecture. On the VM, and again on the workstation, set
the variables, and define the two helpers that write the verdict lines. The workstation gets the
VM's address too:

```sh
v=0.4.0-rc.1   # the release candidate or release under test
a=amd64        # or arm64
zone=zpxse.cc
name=vb19.zpxse.cc
ip=<vm-ip>     # on the workstation
pass() { echo "PASS $*" | tee -a ~/vb19-results.txt; }
fail() { echo "FAIL $*" | tee -a ~/vb19-results.txt; }
```

Every verdict, PASS or FAIL, goes to `~/vb19-results.txt` of the machine that gives it.

## 1. Download and verify the release

On the VM, as root, in an empty directory:

```sh
base=https://github.com/felix-homelab/rpmgr/releases/download/v$v
for f in rpmgr-$v-linux-$a manifest.json manifest.json.minisig \
  signing-key.json signing-key.json.minisig; do
  curl -fsSLO "$base/$f"
done
```

Verify the chain of [04](../../docs/04-security.md#release-signing): a root signs the signing-key
statement, the statement's signer signs the manifest, and the manifest names the artifact's
SHA-256 and size.

```sh
minisign -Vm signing-key.json -P '<root-1 public key>'   # or the root-2 key
cat signing-key.json                   # not_before and not_after must cover today
signer=$(sed -n 's/.*"signer": *"\([^"]*\)".*/\1/p' signing-key.json)
minisign -Vm manifest.json -P "$signer"
h=$(sha256sum rpmgr-$v-linux-$a | cut -d' ' -f1)
grep -q "\"sha256\": *\"$h\"" manifest.json && echo "the manifest lists the artifact"
```

On the workstation, after downloading the artifact:

```sh
gh attestation verify rpmgr-$v-linux-$a --repo felix-homelab/rpmgr \
  --signer-workflow felix-homelab/rpmgr/.github/workflows/release.yml
```

Record every verification's output. A failure ends the run: the release is not used.

## 2. Install the all-in-one

Follow the first installation of [10](../../docs/10-operations.md#supported-platforms), with
`all-in-one` as the role:

```sh
install -m 0755 rpmgr-$v-linux-$a /usr/local/bin/rpmgr
rpmgr version --verbose        # the key IDs must be the ones recorded at the ceremony
useradd --system --user-group --home-dir /var/lib/rpmgr --shell /usr/sbin/nologin rpmgr
install -d -m 0755 /etc/rpmgr
install -d -m 0750 -o rpmgr -g rpmgr /var/lib/rpmgr
rpmgr all-in-one init --public-url https://$name
```

`init` prints the trust domain, the CA pin and the first user's one-time link
`https://<name>/setup#…`. Keep the link for step 3.

**Before the first start**, give the controller a certificate from files. Without one, a controller
with a public DNS name orders its own certificate at once from the instance's ACME CA. That CA is
Let's Encrypt production until step 4 changes it
([10](../../docs/10-operations.md#boot-files)):

```sh
install -d -m 0755 /etc/rpmgr/tls
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/CN=$name" \
  -addext "subjectAltName=DNS:$name" -keyout /etc/rpmgr/tls/panel.key -out /etc/rpmgr/tls/panel.crt
chgrp rpmgr /etc/rpmgr/tls/panel.key && chmod 0640 /etc/rpmgr/tls/panel.key
printf 'tls:\n  cert_file: %s\n  key_file: %s\n' /etc/rpmgr/tls/panel.crt /etc/rpmgr/tls/panel.key \
  >>/etc/rpmgr/all-in-one.yaml
rpmgr systemd-unit all-in-one >/etc/systemd/system/rpmgr-all-in-one.service
systemctl daemon-reload
systemctl enable --now rpmgr-all-in-one
journalctl -u rpmgr-all-in-one -n 20
```

The commands on the VM reach the controller over loopback, also while a port is closed, through
`/etc/hosts`:

```sh
echo "127.0.0.1 $name app.$name" >>/etc/hosts
```

With this line, the controller's own fetch of the domain proof in step 5 goes to loopback, which
an HTTP proof never connects to ([04](../../docs/04-security.md#route-and-hostname-ownership)), so
step 5 marks the claim trusted. The CA's validations, which this run is about, still come from the
internet.

## 3. The first user and an API token

1. **The first user:** in a browser, open the setup link; the self-signed certificate needs an
   exception. Set a name, an address and a password; this account becomes the Owner and the
   Instance Admin.
2. **A token:** in Account → API tokens, create a token for one day with the scopes `org.read`,
   `routes.write`, `infrastructure.write` and `instance.admin`. The page shows the token once, and
   the `rpmgr login` command with the org ID.
3. **Log in:** on the VM, as the user who runs the commands below, run that command with the
   self-signed certificate as the CA file. It asks for the token:

   ```sh
   cp /etc/rpmgr/tls/panel.crt ~/vb19-ca.pem
   rpmgr login --controller https://$name --org <org ID> --ca-file ~/vb19-ca.pem
   ```

## 4. Point the instance at Let's Encrypt staging

```sh
rpmgr get --instance settings          # acme_directory_url and acme_email are listed
rpmgr update settings --instance \
  --set acme_directory_url=https://acme-staging-v02.api.letsencrypt.org/directory \
  --set acme_email=<email-1>
rpmgr get --instance settings          # check: the staging directory, never production
```

Then remove the certificate files from the boot file. The controller reads the ACME settings for
its own certificate at start ([10](../../docs/10-operations.md#boot-files)):

```sh
sed -i '/^tls:$/,/^  key_file:/d' /etc/rpmgr/all-in-one.yaml
systemctl restart rpmgr-all-in-one
journalctl -u rpmgr-all-in-one -f      # until "obtained the public URL's certificate"
```

**Check (phase a, the controller):** on the workstation, define the checks once and run the first:

```sh
served() { openssl s_client -connect $ip:443 -servername "$1" </dev/null 2>/dev/null |
  openssl x509 -noout -issuer -serial -enddate; }
serial() { served "$1" | sed -n 's/^serial=//p'; }
staging() { # staging <id> <host>: the leaf's issuer must say STAGING; prints it
  out=$(served "$2"); echo "$out"
  case $out in *STAGING*) pass "$1 $2 is issued by Let's Encrypt staging" ;; *) fail "$1 $2 is not from staging" ;; esac
}
staging a1 $name
```

Expected: an `issuer=` line that names Let's Encrypt staging, "(STAGING)" in it, a `serial=` and a
`notAfter=` three months ahead, and then `PASS a1 …`. On the VM, add the chain's
issuing certificates to the CA file, so that the command line trusts the new certificate:

```sh
openssl s_client -connect 127.0.0.1:443 -servername $name -showcerts </dev/null 2>/dev/null |
  awk '/BEGIN CERT/{n++} n>=2' | sed -n '/BEGIN CERT/,/END CERT/p' >>~/vb19-ca.pem
rpmgr list route                       # works again
```

## 5. The domain and the route

```sh
rpmgr create domain --fqdn $name --wildcard --method http
rpmgr verify domain <domain ID>        # says the name resolves to an address that is not public
rpmgr trust domain <domain ID>         # after a step-up, as an Instance Admin
rpmgr create route --name vb19 --group default --http --hostname app.$name --tls-mode acme
rpmgr list certificate                 # the certificate of app.<name> and its ID
```

The route needs no target for its certificate. A wildcard claim covers `app.<name>`; a claim of
`<name>` alone does not. The `/etc/hosts` line of step 2 sends the controller's proof to loopback,
which it refuses, so the Instance Admin marks the claim verified with `rpmgr trust domain`; record
that the proof was skipped.

**Check (phase a, the route):** on the workstation,

```sh
staging a2 app.$name
a=$(serial app.$name)
```

Expected: `PASS a2 …`. The serial is `a`.

## Phase b: TCP 443 closed: HTTP-01

1. **Close 443:** close TCP 443 at the provider's firewall. Without one, close it on the public
   interface only, so that loopback stays open:

   ```sh
   iptables -I INPUT -i <public interface> -p tcp --dport 443 -j REJECT
   ```

2. **Renew with a new account:**

   ```sh
   rpmgr update settings --instance --set acme_email=<email-2>
   rpmgr renew certificate <certificate ID>
   rpmgr get certificate <certificate ID> # repeat until NOTAFTER changes; an error shows in it
   ```

3. **Open 443 again.**
4. **Check:** on the workstation,

   ```sh
   staging b1 app.$name
   b=$(serial app.$name)
   [ "$b" != "$a" ] && pass "b2 the serial changed" || fail "b2 the serial did not change"
   ```

   Expected: two PASS lines. The CA reached nothing but port 80, so it validated HTTP-01.

## Phase c: TCP 80 closed: TLS-ALPN-01

The same with the other port:

1. **Close 80:** close TCP 80, or
   `iptables -I INPUT -i <public interface> -p tcp --dport 80 -j REJECT`.
2. **Renew with a new account:** set `--set acme_email=<email-3>`, run
   `rpmgr renew certificate <certificate ID>`, and repeat `rpmgr get certificate <certificate ID>`
   until NOTAFTER changes.
3. **Open 80 again.**
4. **Check:** on the workstation,

   ```sh
   staging c1 app.$name
   c=$(serial app.$name)
   [ "$c" != "$b" ] && [ "$c" != "$a" ] && pass "c2 a third serial" || fail "c2 the serial did not change"
   ```

   Expected: two PASS lines. The CA validated TLS-ALPN-01, answered by the gateway on 443.

A renewal under a new account works because the job orders again without naming the replaced
certificate when the CA refuses that ([04](../../docs/04-security.md#controller-certificates)).

## Phase d: DNS-01 through Cloudflare

The product with your zone: it connects Cloudflare, imports `zpxse.cc`, obtains a certificate for
`dns.<name>` and a wildcard certificate for `*.w.<name>` from Let's Encrypt staging by DNS-01,
publishes the route's address record after you approve the plan, and removes it again with the
route. The instance still uses the staging directory and the account of `<email-3>`. The names of
this phase are new, so the CA validates them afresh.

On the VM, define the helpers. `record` reads the zone's records **at Cloudflare**, live, through the
product, so it sees records that rpmgr does not own as well; it prints no token:

```sh
record() { rpmgr list dns-record --zone $zone --foreign -o json |
  jq -r --arg t "$1" --arg n "$2" '[.. | objects | select(.type? == $t and .name? == $n) | .content] | join(",")'; }
foreign() { rpmgr list dns-record --zone $zone --foreign -o json |
  jq -r '[.. | objects | select(has("type")) | select((.id // "") == "") | "\(.type) \(.name) \(.content)"] | sort | .[]'; }
cert_active() { rpmgr list -o json certificate | jq -e --arg h "$1" '[.. | objects | select(has("sans")) |
  select(.sans | index($h)) | select(.status == "CERTIFICATE_STATUS_ACTIVE")] | length > 0' >/dev/null; }
route_id() { rpmgr list -o json route | jq -r --arg n "$1" '[.. | objects | select(.name? == $n) | .id][0] // empty'; }
until_ok() { n=$1; shift; for _ in $(seq "$n"); do "$@" && return 0; sleep 5; done; return 1; }   # n tries, 5 s apart
```

Each step that changes the DNS asks for a step-up in the terminal: type your account password (an
account without a second factor).

### d1. Connect Cloudflare and import the zone

1. **Free the route's name:** at Cloudflare, delete the A record of `app.<name>`. Keep `<name>`.
2. **The token file:** on the workstation, `scp -p ./cf-token root@<vm-ip>:cf-token`; on the VM,
   `chmod 0600 ~/cf-token`.
3. **Connect:**

   ```sh
   rpmgr connect dns-provider --kind cloudflare --name cf --token-file ~/cf-token
   rpmgr list dns-provider
   rpmgr list provider-zone cf
   ```

   Expected: `Connected dns provider dnp_… (cf); its token is ok.`, the provider with
   `PROVIDER_STATUS_OK`, and the zone `zpxse.cc` with `active` and `full`. A token without Zone
   Read or without DNS Edit is the failure here.

   ```sh
   rpmgr list dns-provider -o json | jq -e '[.. | objects | select(.name? == "cf" and
     .status? == "PROVIDER_STATUS_OK")] | length == 1' >/dev/null && pass "d1 the provider is connected, its token is ok" ||
     fail "d1 the provider is not ok"
   ```
4. **Import the zone, held:**

   ```sh
   rpmgr import zone --provider cf $zone
   rpmgr get zone $zone -o json | jq -e '.syncState == "ZONE_SYNC_STATE_HELD"' >/dev/null &&
     pass "d2 the zone is imported and held" || fail "d2 the zone is not held"
   ```

   Expected: `Imported zone dnz_… (zpxse.cc); it is held (imported) and publishes nothing yet.`
   and a pending domain claim for the zone's name, which needs no action.
5. **Remember the records of others:** every record of the zone that rpmgr does not own, such as
   your mail records. Phase d must not change one.

   ```sh
   foreign | tee ~/vb19-foreign.before
   ```
6. **The group's DNS target:** where the published records point:

   ```sh
   rpmgr update gateway-group default --dns-address <vm-ip>
   ```

### d2. A route and a wildcard route, certificates by DNS-01

The zone is held: nothing is written for the routes yet, but the challenge of a certificate is.

```sh
rpmgr create route --name vb19d --group default --http --hostname dns.$name --tls-mode acme
rpmgr create route --name vb19w --group default --http --hostname "*.w.$name" --tls-mode acme
until_ok 60 cert_active dns.$name && until_ok 60 cert_active "*.w.$name" && echo both active
rpmgr list certificate
```

Expected: after one or two minutes `both active`, and two certificates with
`CERTIFICATE_STATUS_ACTIVE`. The orders write a `_acme-challenge` TXT at Cloudflare and wait for it
to be visible, which takes the longest. If one stays pending, `rpmgr get certificate <id>` shows
the error, and `journalctl -u rpmgr-all-in-one -n 50` the order.

**Check, from the workstation:** the certificates are from staging, the chain says so, and the
wildcard certificate names the wildcard:

```sh
staging d3 dns.$name
staging d4 x.w.$name
openssl s_client -connect $ip:443 -servername x.w.$name -showcerts </dev/null 2>/dev/null |
  grep -E '^ *(s|i):'                   # the chain: every issuer says (STAGING)
openssl s_client -connect $ip:443 -servername x.w.$name </dev/null 2>/dev/null |
  openssl x509 -noout -ext subjectAltName
```

Expected: `PASS d3 …`, `PASS d4 …`, a chain of two or three `s:`/`i:` pairs with "(STAGING)", and
`DNS:*.w.<name>`.

### d3. The TXT is gone, and nothing is published while the zone is held

On the VM, until both challenge records are gone, then the records of the zone as Cloudflare holds them:

```sh
txt_gone() { [ -z "$(record TXT _acme-challenge.dns.$name)" ] && [ -z "$(record TXT _acme-challenge.w.$name)" ]; }
until_ok 12 txt_gone && pass "d5 the challenge TXT records are removed" || fail "d5 a challenge TXT is left"
[ -z "$(record A dns.$name)" ] && pass "d6 a held zone has no record of the route" || fail "d6 the held zone has a record"
```

On the workstation, the same from the zone's authoritative name server, which does not go through
rpmgr:

```sh
ns=$(dig +short NS zpxse.cc | head -n 1)
dig +short TXT _acme-challenge.dns.$name @$ns     # no output
dig +short A dns.$name @$ns                       # no output yet
```

### d4. Approve the plan: the address record is published

```sh
rpmgr plan zone $zone                  # read it
rpmgr approve zone $zone --plan-hash "$(rpmgr plan zone $zone -o json | jq -r .hash)"
rpmgr get zone $zone -o json | jq -r .syncState      # ZONE_SYNC_STATE_ACTIVE
published() { [ "$(record A dns.$name)" = "<vm-ip>" ]; }
until_ok 24 published && pass "d7 the address record of dns.$name is published" || fail "d7 not published"
rpmgr list dns-record --zone $zone --foreign
```

Expected: the plan shows `+ A dns.<name> <vm-ip>` and `+ A app.<name> <vm-ip>`, plus the claim TXT
`_rpmgr-challenge.<zone>`; the plan holds no line for `<name>` itself (the controller's name is
never written) and none for `*.w.<name>` (wildcards are held until the zone allows them). The
approval is bound to the plan's hash, here read again from the same plan. Check the two absences:

```sh
rpmgr list dns-record --zone $zone --foreign -o json | jq -e --arg n "$name" --arg w "*.w.$name" '[.. | objects |
  select((.id // "") != "") | select(.name == $n or .name == $w)] | length == 0' >/dev/null &&
  pass "d8 the controller's name and the wildcard are not written" ||
  fail "d8 the controller's name or the wildcard is written"
```

The check counts only records rpmgr owns, so your manual A record of `<name>` stays out of it. On the
workstation, `dig +short A dns.$name @$ns` prints `<vm-ip>`.

### d5. Delete the route: the record goes

```sh
rpmgr delete route "$(route_id vb19d)"
rpmgr sync zone $zone
gone() { [ -z "$(record A dns.$name)" ]; }
until_ok 24 gone && pass "d9 the address record is removed with its route" || fail "d9 the record is still there"
foreign >~/vb19-foreign.after
diff ~/vb19-foreign.before ~/vb19-foreign.after && pass "d10 the records of others are unchanged" ||
  fail "d10 a record of someone else changed"
```

Expected: both PASS lines. Then, on the workstation, `dig +short A dns.$name @$ns` prints nothing.

## Record

Paste back **only the PASS and FAIL lines**, from the VM and from the workstation, and nothing else:

```sh
grep -E '^(PASS|FAIL) ' ~/vb19-results.txt
```

They carry no token, no address and no key. A complete run has these lines: `a1 a2 b1 b2 c1 c2`
and `d1` to `d11`; the lines `a1`, `a2`, `b1`, `b2`, `c1`, `c2`, `d3` and `d4` come from the
workstation, the others from the VM. Keep the rest, which you do not paste, in a text file: the
outputs of step 1 and `rpmgr version --verbose`; the journal lines `obtained the public URL's
certificate` and any warnings; per phase, the checks' issuer, serial and end date, and
`rpmgr get certificate` before and after; anything that failed, with its log lines. Remove every
token and key from it first.

After the run, a pull request `docs: record the VB-19 run` (labels `type:docs`, `area:acme`, the
current phase's, `no-changelog`) records the result:
- **Raw lines:** the PASS and FAIL lines as `test/vb19/results/<date>.txt`;
- **13:** marks VB-19 done, with the date, in
  [13](../../docs/13-roadmap.md#verification-backlog);
- **S6:** adds the outcome to [S6](../../docs/spikes/S6.md) and removes its "Not verified" item;
- **04, 05 and 08:** turns the `[V VB-19]` of the staging run in
  [04](../../docs/04-security.md#controller-certificates) and
  [08](../../docs/08-software-stack.md#networking) into a fact citing this run, for each challenge
  type that passed;
- **The release issue:** ticks its "fresh install" item, when the run tested a release candidate.

A failed phase is a defect: it gets an issue and a fix on `main`, and a release candidate under
test the next `rc` ([RELEASING](../../RELEASING.md#release-process)). v0.4.0 waits for the run
([D98](../../docs/14-open-decisions.md#project-and-process)).

## Clean up

Nothing is revoked automatically. In this order:

1. **The routes, the zone's records, the provider** (VM). The removal plan lists only records rpmgr
   owns: the claim's TXT, `app.<name>` and, if it is still there, `dns.<name>`:

   ```sh
   rpmgr delete route "$(route_id vb19w)"
   rpmgr delete route "$(route_id vb19)"
   rpmgr plan zone $zone --delete-records            # read it
   rpmgr remove zone $zone --delete-records --plan-hash "$(rpmgr plan zone $zone --delete-records -o json | jq -r .hash)"
   zone_gone() { ! rpmgr list zone -o json | grep -q "\"$zone\""; }
   until_ok 24 zone_gone
   rpmgr delete dns-provider "$(rpmgr list dns-provider -o json | jq -r '[.. | objects | select(.name? == "cf") | .id][0]')"
   rpmgr list dns-provider | grep -q cf && fail "d11 the provider is still listed" ||
     pass "d11 the zone is removed with its records, and the provider is deleted"
   rpmgr list domain                                  # the zone's pending claim: rpmgr delete domain <id>
   ```

   Then look at the zone in the Cloudflare dashboard: the records of others, such as your mail
   records, are as they were.
2. **The tokens:** revoke the rpmgr API token in the web UI, and delete the Cloudflare token in the
   Cloudflare dashboard. Delete `~/cf-token` on the VM and on the workstation.
3. **The VM:** stop the service and destroy the VM. Its database holds the staging accounts, the
   certificates and the sealed Cloudflare token, and nothing else.
4. **DNS:** at Cloudflare, remove the A records of `<name>` and `app.<name>` if still there, or
   point them elsewhere. Let's Encrypt's staging certificates need no revocation.

## How long it takes

About 45 minutes to prepare (the VM, the records, the token) and 2 hours for the run: steps 1 to 5
about 40 minutes, phases b and c about 10 minutes each if the CA answers at once, phase d about 40
minutes, of which the waits for the two orders are the most.

## Rehearsal

`./rehearse.sh [<log file>]` runs steps 2 to 5 and the phases a to d on this checkout, with Go and
Docker, in a container without a network. It builds rpmgr, Pebble at the version of `go.mod` and
the fakes of [`fakes`](fakes/main.go), and checks that each step succeeds. It prints PASS
lines numbered as the sheet's (`b` and `c` one line each, as it checks the issuer and the serial
together) and ends with one PASS line per part, or the first FAIL. It
needs no token and no account. Its differences from the real run:
- **The CA:** Pebble instead of Let's Encrypt.
- **The names:** the zone is `vz.test` and `<name>` is `vb19.vz.test`. They resolve, for the CA, to
  `127.0.0.2`, which plays the public address, through the DNS server of
  [`internal/acme/acmetest`](../../internal/acme/acmetest), which also answers a TXT record as the
  fake Cloudflare holds it. `iptables` closes the ports.
- **Cloudflare:** the fake API of [`internal/dns/cftest`](../../internal/dns/cftest). rpmgr, the
  release build with no test hook, finds its compiled-in address `api.cloudflare.com` through
  `/etc/hosts` and a NAT rule at the fake, whose certificate a CA in rpmgr's root file signs. The
  fake zone holds three records of others, which phase d must leave alone. Its DNS target is
  `192.0.2.10`, since the API refuses a loopback address.
- **The web UI steps:** the first user and the token are made with the API calls the web UI sends,
  and the step-up that the terminal asks for is made with the same call.
- **Authorisation reuse:** Pebble reuses every valid authorisation of an account. This shows that
  the new account per phase makes the CA validate again.
- **No systemd:** the KEK is a file, and the all-in-one runs as the user `rpmgr` with
  `CAP_NET_BIND_SERVICE` only, as its unit would run it; `rpmgr login` reads the token from a file.
- **Step 1:** the download and its verification are not rehearsed. Pebble needs no release.
- **What it cannot show:** that Cloudflare and Let's Encrypt behave as the fakes do, the multiple
  vantage points of the CA, real DNS propagation, and the permissions of a real token.
