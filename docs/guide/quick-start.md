# Quick start

This tutorial sets up rpmgr from nothing: an all-in-one on a public server, a connector on a
machine at home, a website published as `https://app.example.com`, and a game server published on a
TCP port. Each step says what you should see, so you know it worked before you go on. Follow it on
a fresh server to try rpmgr out, or as the first installation of a real one. Use your own names and
addresses wherever the examples have `example.com` and `192.168.1.x`.

## Before you start

- **A public server** with a public IPv4 address, running a Linux of the supported list: Debian 12
  or later, Ubuntu 22.04 or later, RHEL, Rocky or Alma Linux 9 or later, with systemd 249 or later
  ([10](../10-operations.md#supported-platforms)). A small VPS is enough. You need `sudo`.
- **A domain** whose DNS records you can set, here `example.com`.
- **A machine at home** running Linux with systemd that reaches your services. Here it reaches a web
  app at `192.168.1.20:8080` and a game server at `192.168.1.40:25565` (TCP). It needs outbound
  access on port 443 and nothing inbound.
- **On both Linux hosts:** `curl` and OpenSSL 3, which current distributions have.
- **On your workstation:** a browser, and an authenticator app on your phone.

## 1. Point the names at the server

At your DNS provider, create an A record (and an AAAA record if the server has IPv6) with the
server's public address for:

- `panel.example.com`, the web UI and the address the connectors dial;
- `app.example.com`, the website you will publish.

Create them first: the certificates are issued only for names that point at the server.

**Check:** on your workstation, both names resolve to the server.

```sh
dig +short panel.example.com
dig +short app.example.com
```

## 2. Open the server's ports

Visitors reach the gateway on 80/tcp, 443/tcp and 443/udp; connectors use 443 as well. Open them in
the provider's firewall in front of the server, and in the server's own firewall if it has one. With
`ufw`:

```sh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 443/udp
```

## 3. Install rpmgr on the server

```sh
curl -fsSLO https://github.com/felix-homelab/rpmgr/releases/latest/download/install.sh
sudo sh install.sh --no-setup
```

The script downloads the release, verifies its signatures, and only then installs the binary
`/usr/local/bin/rpmgr`, the system user `rpmgr` and the directories `/etc/rpmgr` and
`/var/lib/rpmgr` ([The install scripts](install/install-script.md)). It ends with (abbreviated):

```text
rpmgr install: verified rpmgr 0.2.0 (manifest …)
rpmgr 0.2.0 (commit …, go…, linux/amd64)
release root keys:
  …
rpmgr install: installed rpmgr 0.2.0 to /usr/local/bin/rpmgr
rpmgr install: next: set up this host's role with: sudo rpmgr setup
```

Without `--no-setup`, the script offers to run `rpmgr setup` at once, which asks the questions of
the next step in forms.

## 4. Set the server up as an all-in-one

```sh
sudo rpmgr setup --role all-in-one --public-url https://panel.example.com \
  --acme-email you@example.com --yes
```

Setup writes the boot file, creates the key-encryption key (KEK), the database and the internal CA,
creates the gateway group `default` with the built-in gateway `local` and the built-in connector
`local`, installs and starts the service `rpmgr-all-in-one`, and waits until it is ready
([Set up a host with rpmgr setup](install/setup.md)). To try rpmgr without using up Let's Encrypt's
limits, add `--acme-directory staging`; browsers do not trust its certificates.

What you see (abbreviated; `…` marks values that differ on your host):

```text
→ write the boot file /etc/rpmgr/all-in-one.yaml
→ initialise the all-in-one: KEK, database, trust domain and CA, and enroll its gateway and connector
→ set the instance's ACME directory and e-mail address
→ install the unit /etc/systemd/system/rpmgr-all-in-one.service and start it: systemctl daemon-reload, enable --now rpmgr-all-in-one
→ wait until 127.0.0.1:7381/readyz reports ready

rpmgr all-in-one is set up and runs as rpmgr-all-in-one.

  trust domain: rpmgr-…
  CA pin:       sha256:…
  gateway:      gw_…
  connector:    con_…
  KEK:          new systemd credential /etc/rpmgr/credstore/rpmgr-kek
Back up the KEK separately: without it the database cannot be read.

Create the first user, Instance Admin and Owner, with this one-time link (valid …):
  https://panel.example.com/setup#…
```

Keep the link for the next step. **Back up the KEK** now, apart from where your database backups
will go ([Backup and restore](operations/backup-and-restore.md#back-up-the-kek)).

**Check:** the service runs and is ready, and the web UI answers with a certificate from Let's
Encrypt.

```sh
systemctl is-active rpmgr-all-in-one          # active
curl -fsS http://127.0.0.1:7381/readyz        # ok
curl -sSI https://panel.example.com/ | head -n 1    # from your workstation: HTTP/2 200
```

The controller orders its certificate at the first start. Until it arrives, the web UI serves a
self-signed one and `curl` refuses it; try again a little later. If it does not arrive, see
`sudo journalctl -u rpmgr-all-in-one`.

## 5. Create your account

Open the link from step 4 in your browser. On **Create the first account**, enter your
**E-mail address**, **Your name** and a password twice, and choose **Create the account**. This
account becomes the Owner of your organisation and the Instance Admin, who administers the whole
installation.

The link works once and expires ([04](../04-security.md#human-authentication-and-sessions)). If you
lose it before the account exists, print a new one on the server:

```sh
sudo rpmgr user reset-password
```

Then open **Your account** from the user menu and choose **Set up an authenticator**: scan the code
with your authenticator app, enter the code it shows, choose **Turn on**, and keep the recovery
codes it shows you ([Sign-in and two-factor authentication](accounts/sign-in-and-mfa.md)).

**Check:** you are signed in and see the **Overview**. Under **Network → Connectors** the built-in
connector `local` is listed, and under **Network → Gateways** the group `default` with the gateway
`local`.

## 6. Claim your domain

A route may only use hostnames under a domain your organisation has proved is its own.

1. Under **Security → Domains & certificates**, choose **Claim a domain**.
2. As **Domain**, enter `example.com`, and tick **Also every name below it**: without it, the claim
   covers `example.com` alone.
3. Under **How to prove it is yours**, choose **A DNS TXT record**, then **Claim it**.
4. Create the TXT record the page shows, with its **TXT record name** and **Value**, at your DNS
   provider.
5. Choose **Check now**. DNS changes can take a few minutes to be visible; check again until the
   claim is **verified**.

As the Instance Admin, you may instead choose **Mark as trusted** to skip the proof. More in
[Domains and certificates](domains-and-certificates.md).

**Check:** the claim for `example.com` shows **verified**.

## 7. Connect the machine at home

1. In the web UI, under **Network → Connectors**, choose **Enroll a connector**.
2. Under **Targets the connector may reach**, enter `192.168.1.20:8080`, the web app. Leave the
   other fields as they are, and choose **Create the token**.
3. The dialog shows an **Install command** and an **Enrollment token**. Copy the command and run it
   on the machine at home. It looks like this:

   ```sh
   curl -fsSLO 'https://panel.example.com/install.sh' && sudo sh install.sh \
     --controller 'https://panel.example.com' --ca-pin 'sha256:…' \
     --allow-target '192.168.1.20:8080'
   ```

4. When the installer asks `Enrollment token:`, paste the token from the dialog. It is not shown as
   you type. The token is shown only once, is never part of a command line, and enrolls one
   connector before it expires ([Enrolling connectors](connectors/enroll.md)).

The installer verifies the release, writes the connector's boot file and its local policy
`/etc/rpmgr/policy.yaml` with your target, enrolls, and starts the service. It ends with:

```text
Enrolled connector con_… in trust domain rpmgr-…; identity written to /var/lib/rpmgr/identity.
…
rpmgr install: rpmgr 0.2.0 runs as rpmgr-connector; admin listener 127.0.0.1:7383
```

Once the connector has connected, the web UI opens its page. It is named after the machine's host
name.

**Check:** on the machine at home,

```sh
sudo rpmgr status
```

ends with a `Service:` line that says `running and ready`, and the connector shows as connected
in the web UI.

The connector reaches only the targets in its local policy. To allow another one later, run
`sudo rpmgr policy allow-target <target>` on that machine
([The local policy](connectors/local-policy.md)).

## 8. Publish the web app

1. Under **Network → Routes**, choose **Create a route**.
2. Choose the type **HTTP** and the **Gateway group** `default`.
3. Enter the **Name** `app` and, under **Hostnames**, `app.example.com`. Keep **TLS certificate**
   at **From ACME** and **Port 80** at **Redirect to HTTPS**. Choose **Create the route**.
4. Choose **Open app to add its targets**, then **Add a target**.
5. Choose your connector, enter the **Host** `192.168.1.20` and the **Port** `8080`, keep the
   **Protocol to the target** at **HTTP**, and choose **Add the target**.

The controller now orders a certificate for `app.example.com` from Let's Encrypt; the gateways
answer its challenge. Under **Security → Domains & certificates**, its certificate shows **being
obtained**, then **active** ([HTTP routes](routes/http.md)).

**Check:** the route shows `1/1 ready`, and from your workstation:

```sh
curl -sSI https://app.example.com/ | head -n 1     # the status line of your web app
```

The same with the command line, after `rpmgr login`
([API tokens and the command line](accounts/api-tokens-and-cli.md)):

```sh
rpmgr create route --name app --group default --http --hostname app.example.com
rpmgr create route-target --route app --connector <connector name> \
  --address 192.168.1.20:8080 --upstream http
```

## 9. Publish a game server on a TCP port

`tcp` and `udp` routes take public ports from a port pool of their gateway group. The group
`default` has none yet.

1. **A port pool.** Under **Network → Gateways**, open the group `default`. Under **Port pools**,
   choose **Add a port pool**, choose the **Protocol** TCP, enter the **First port** `20000` and the
   **Last port** `20099`, and choose **Add the pool** ([Gateways](gateways.md)).
2. **The firewall.** Open the pool's ports on the server, in the provider's firewall too:

   ```sh
   sudo ufw allow 20000:20099/tcp
   ```

3. **The local policy.** On the machine at home, allow the game server:

   ```sh
   sudo rpmgr policy allow-target 192.168.1.40:25565
   ```

   It prints `/etc/rpmgr/policy.yaml: updated` and reloads the connector.
4. **The route.** Under **Network → Routes**, **Create a route** of the type **TCP** on the group
   `default`, named `game`. Keep the **Public port** at `0`, which takes a free port from the pool.
   Choose **Create the route**, then **Add a target** with your connector, the **Host**
   `192.168.1.40` and the **Port** `25565`.

The route list shows the route's address: the group's public hostname, `panel.example.com`, and the
port the route got, such as `panel.example.com:20000`
([TCP and UDP routes](routes/tcp-and-udp.md)).

**Check:** from your workstation, the port answers:

```sh
nc -vz panel.example.com 20000      # use the route's port
```

The same with the command line:

```sh
rpmgr create port-pool --group default --protocol tcp --from 20000 --to 20099
rpmgr create route --name game --group default --tcp
rpmgr create route-target --route game --connector <connector name> --address 192.168.1.40:25565
```

## What happens next

- **Back up** the controller daily, and keep the KEK apart
  ([Backup and restore](operations/backup-and-restore.md)).
- **Restrict** who may reach a route with an access policy: IP lists or basic auth
  ([Access policies](access-policies.md)).
- **Services on the server itself,** such as containers next to rpmgr, go through the built-in
  connector `local`: allow them with `sudo rpmgr policy allow-target 127.0.0.1:8080` on the server.
- **More members:** invite them under **Organisation**
  ([Members and roles](accounts/members-and-roles.md)).
- **Upgrades:** [Upgrades](install/upgrades.md).

## If something does not work

| What you see | Where to look |
|---|---|
| Setup waits and fails at `wait until … /readyz reports ready` | `sudo journalctl -u rpmgr-all-in-one -n 50` |
| The web UI's certificate is not trusted | Is `panel.example.com` pointing at the server, and are ports 80 and 443 open? With `--acme-directory staging`, browsers never trust it |
| The domain claim stays pending | The TXT record's name and value, and time for DNS to update |
| The install command fails at `cannot download … /dl/…` | The controller cannot reach GitHub to fill its release mirror ([Air-gapped installations](install/air-gapped.md)) |
| A route shows **blocked by the connector's local policy** | Allow the target on the connector's host with `sudo rpmgr policy allow-target`; the route's page shows the command |
| The TCP port does not answer | The pool's ports in both firewalls, and the route's actual port |

The [Troubleshooting](operations/troubleshooting.md) page covers more.
