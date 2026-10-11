# VB-19 run sheet: ACME against Let's Encrypt staging, and a first install of the rc

This sheet is the HTTP-01 and TLS-ALPN-01 part of VB-19, which
[D50](../../docs/14-open-decisions.md#project-and-process) requires before v0.1.0
([13](../../docs/13-roadmap.md#verification-backlog)). The same session is the "fresh install" of
the release candidate in the release checklist
([RELEASING](../../RELEASING.md#release-process)). The DNS-01 and Cloudflare part of VB-19 stays
with the run sheet of S6 on the tag `spike/s6`, before the first release with DNS-01 (Phase 2).

The real product runs on a throw-away VM: an all-in-one installed from the `v0.1.0-rc.1`
pre-release. It obtains the certificate of its public URL and of one route from Let's Encrypt
**staging**, then renews the route's certificate twice:
- **with TCP 443 closed,** which only HTTP-01 can pass;
- **with TCP 80 closed,** which only TLS-ALPN-01 can pass.

Each validation comes from the internet, from Let's Encrypt's several vantage points.

`rehearse.sh` runs the same commands locally against Pebble and checks the outcome
([Rehearsal](#rehearsal)). Never point the instance at Let's Encrypt's production directory
during this run.

## Prepare

- **VM:** a Linux of the supported list ([10](../../docs/10-operations.md#supported-platforms)),
  for example Debian 12, with a public IPv4 address and SSH. Install `openssl`, `curl` and
  `minisign`.
- **Firewall:** the provider's firewall in front of the VM allows TCP 80 and TCP 443 from
  anywhere. During the run you close one of them at a time, so find out beforehand how to change
  the rules quickly. A VM without such a firewall uses `iptables` on its public interface instead
  ([Phase b](#phase-b-tcp-443-closed-http-01)).
- **Names:** a domain you control, or a dynamic-DNS name, called `<name>` below. A records for
  `<name>`, the controller's public URL, and `app.<name>`, the route, point to the VM's address; a
  wildcard record `*.<name>` does as well. Use DNS only: no CDN or proxy in front.
- **E-mail:** three addresses that reach you, for three ACME accounts, one per phase, such as
  `you+vb19a@…`, `you+vb19b@…` and `you+vb19c@…`. An ACME account may reuse an authorisation it
  validated before, without a new validation. A new account per phase makes the CA validate
  again, through the one port left open.
- **Keys:** the public keys of the two interim roots from the key ceremony
  ([RELEASING](../../RELEASING.md#interim-signing-keys)), and the key IDs recorded on paper.
- **Workstation:** a second machine for the checks "from the internet". With `gh` and `cosign`, it
  also verifies the release's provenance and signatures.

Below, `<ip>` is the VM's public address, `v` the version and `a` the architecture:

```sh
v=0.1.0-rc.1
a=amd64        # or arm64
name=vb19.example.org
```

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

On the workstation, after downloading the artifact and its `.sigstore.json`:

```sh
gh attestation verify rpmgr-$v-linux-$a --repo felix-homelab/rpmgr
cosign verify-blob --bundle rpmgr-$v-linux-$a.sigstore.json \
  --certificate-identity https://github.com/felix-homelab/rpmgr/.github/workflows/release.yml@refs/tags/v$v \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com rpmgr-$v-linux-$a
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

With this line, the controller's own fetch of the domain proof in step 5 goes over loopback too.
The CA's validations, which this run is about, still come from the internet.

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
  --set acme_email=you+vb19a@example.org
rpmgr get --instance settings          # check: the staging directory, never production
```

Then remove the certificate files from the boot file. The controller reads the ACME settings for
its own certificate at start ([10](../../docs/10-operations.md#boot-files)):

```sh
sed -i '/^tls:$/,/^  key_file:/d' /etc/rpmgr/all-in-one.yaml
systemctl restart rpmgr-all-in-one
journalctl -u rpmgr-all-in-one -f      # until "obtained the public URL's certificate"
```

**Check (phase a, the controller):** on the workstation,

```sh
openssl s_client -connect <ip>:443 -servername <name> </dev/null 2>/dev/null |
  openssl x509 -noout -issuer -serial -enddate
```

shows an issuer from Let's Encrypt staging, whose name says "(STAGING)". On the VM, add the chain's
issuing certificates to the CA file, so that the command line trusts the new certificate:

```sh
openssl s_client -connect 127.0.0.1:443 -servername $name -showcerts </dev/null 2>/dev/null |
  awk '/BEGIN CERT/{n++} n>=2' | sed -n '/BEGIN CERT/,/END CERT/p' >>~/vb19-ca.pem
rpmgr list route                       # works again
```

## 5. The domain and the route

```sh
rpmgr create domain --fqdn $name --wildcard --method http
rpmgr verify domain <domain ID>        # repeat until it says VERIFIED
rpmgr create route --name vb19 --group default --http --hostname app.$name --tls-mode acme
rpmgr list certificate                 # the certificate of app.<name> and its ID
```

The route needs no target for its certificate. A wildcard claim covers `app.<name>`; a claim of
`<name>` alone does not. If the proof cannot pass, an Instance Admin marks the claim verified with
`rpmgr trust domain <domain ID>`, after a step-up. In that case, record that the proof was skipped.

**Check (phase a, the route):** on the workstation, the `openssl` command of step 4 with
`-servername app.<name>` shows a "(STAGING)" issuer. Record the serial.

## Phase b: TCP 443 closed: HTTP-01

1. **Close 443:** close TCP 443 at the provider's firewall. Without one, close it on the public
   interface only, so that loopback stays open:

   ```sh
   iptables -I INPUT -i <public interface> -p tcp --dport 443 -j REJECT
   ```

2. **Renew with a new account:**

   ```sh
   rpmgr update settings --instance --set acme_email=you+vb19b@example.org
   rpmgr renew certificate <certificate ID>
   rpmgr get certificate <certificate ID> # repeat until NOTAFTER changes; an error shows in it
   ```

3. **Open 443 again.**
4. **Check:** run the workstation check for `app.<name>`. The serial differs from phase a, and the
   issuer is still "(STAGING)". The CA reached nothing but port 80, so it validated HTTP-01.

## Phase c: TCP 80 closed: TLS-ALPN-01

The same with the other port:

1. **Close 80:** close TCP 80, or
   `iptables -I INPUT -i <public interface> -p tcp --dport 80 -j REJECT`.
2. **Renew with a new account:** set `--set acme_email=you+vb19c@example.org`, run
   `rpmgr renew certificate <certificate ID>`, and repeat `rpmgr get certificate <certificate ID>`
   until NOTAFTER changes.
3. **Open 80 again.**
4. **Check:** the workstation check shows a third serial. The CA validated TLS-ALPN-01, answered by
   the gateway on 443.

A renewal under a new account works because the job orders again without naming the replaced
certificate when the CA refuses that ([04](../../docs/04-security.md#controller-certificates)).

## Record

Collect, in a text file:
- the outputs of step 1 and `rpmgr version --verbose`;
- the journal lines `obtained the public URL's certificate` and any warnings;
- per phase, the workstation check (issuer, serial, end date), `rpmgr get certificate` before and
  after, and the time the renewal took;
- anything that failed, with its log lines.

Open a pull request `docs: record the VB-19 staging run` (labels `type:docs`, `area:acme`,
`phase:p1`, `no-changelog`) that:
- **Raw outputs:** adds the text file as `test/vb19/results/<date>.txt`;
- **S6:** adds the outcome of the HTTP-01 and TLS-ALPN-01 part to [S6](../../docs/spikes/S6.md),
  and narrows its "Not verified" item to the DNS-01 part;
- **13:** marks VB-19's D50 part done, with the date, in
  [13](../../docs/13-roadmap.md#verification-backlog);
- **04 and 08:** turns the `[V VB-19]` of the staging run in
  [04](../../docs/04-security.md#controller-certificates) and
  [08](../../docs/08-software-stack.md#networking) into a fact citing this run, for HTTP-01 and
  TLS-ALPN-01 only;
- **#170:** ticks the VB-19 and "fresh install" items.

A failed phase is a defect of the release candidate: it gets an issue, a fix on `main` and
`rc.2` ([RELEASING](../../RELEASING.md#release-process)).

## Clean up

- **The token:** revoke it in the web UI.
- **The VM:** stop the service and destroy the VM. Its database holds the staging accounts and
  certificates and nothing else.
- **DNS:** remove the A records of `<name>` and `app.<name>`, or point them elsewhere.

## Rehearsal

`./rehearse.sh [<log file>]` runs steps 2 to 5 and both phases on this checkout, with Go and Docker,
in a container without a network. It checks that each step succeeds and that each phase's
renewal is a new validation with a new serial. Its differences from the real run:
- **The CA:** Pebble at the version of `go.mod` instead of Let's Encrypt.
- **The names:** they resolve, for the CA, to `127.0.0.2`, which plays the public address.
  `iptables` closes its ports.
- **The web UI steps:** the first user and the token are made with the API calls the web UI sends.
- **Authorisation reuse:** Pebble reuses every valid authorisation of an account. This shows that
  the new account per phase makes the CA validate again.
- **No systemd:** the KEK is a file, and the all-in-one runs as the user `rpmgr` with
  `CAP_NET_BIND_SERVICE` only, as its unit would run it; `rpmgr login` reads the token from a file.
- **Step 1:** the download and its verification are not rehearsed. Pebble needs no release.
