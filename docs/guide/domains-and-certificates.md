# Domains and certificates

Before a route may use a hostname, your organisation proves that the domain is its own. HTTP routes
then need certificates, which rpmgr obtains from an ACME CA such as Let's Encrypt or which you
upload, and HTTPS targets may need CA bundles to verify their certificates. This page is for the
Owners and Admins who set these up; all three live in the web UI under **Domains & certificates**.

## Before you start

- Claiming domains, uploading and renewing certificates and managing CA bundles need the role
  Owner or Admin ([Members and roles](accounts/members-and-roles.md)). Marking a domain trusted, and
  the ACME settings, need the Instance Admin.
- To prove a domain, you need access to its DNS records, or a gateway group whose gateways the
  name points at.
- For the command line, a stored API token
  ([API tokens and the command line](accounts/api-tokens-and-cli.md)).

## Domains

### What a claim covers

A route's hostnames must lie under a **verified** domain claim of your organisation. A claim is for
one name, such as `example.com`:

- **Exact:** the claim covers `example.com` alone.
- **Also every name below it** (`--wildcard`): the claim covers `example.com` and every name below
  it, at any depth: `www.example.com`, `a.b.example.com`. A route's wildcard hostname
  `*.example.com` needs such a claim.

Labels never match in part: `example.com` does not cover `badexample.com`. A name is claimed once
in the whole instance: while one organisation holds a claim on a name, in any status, another
cannot claim it ([04](../04-security.md#route-and-hostname-ownership)).

### How you prove it

| Method | Web UI | Command line | What you do |
|---|---|---|---|
| DNS TXT record | **A DNS TXT record** | `--method txt`, the default | Create a TXT record `_rpmgr-challenge.<domain>` with the value rpmgr shows |
| HTTP token | **An HTTP token, served by your gateways** | `--method http` | Point the name at a gateway of your organisation, which then serves the token |

- **TXT record.** The controller reads the record at the domain's authoritative nameservers, not
  through a resolver, so caches and split-horizon DNS cannot fake or delay the answer. It asks
  them only at public addresses: a zone whose nameservers have a loopback, private or other
  internal address fails with "a nameserver's address is not public"
  ([04](../04-security.md#route-and-hostname-ownership)); have the Instance Admin mark such a claim
  trusted.
- **HTTP token.** Every enabled gateway of your organisation answers
  `http://<domain>/.well-known/rpmgr-challenge/<claim ID>` on port 80 with the value. The
  controller fetches that URL; pointing the name at your gateways is the proof. Port 80 of the
  gateways must be reachable from the controller, directly or through the proxy that `HTTP_PROXY`,
  else `ALL_PROXY`, names ([Environment variables](reference/environment.md)). Without a proxy, the
  controller connects only to public addresses: a name that resolves to a loopback, private or
  other internal address fails with "the name resolves to an address that is not public"
  ([04](../04-security.md#route-and-hostname-ownership)). For a domain that resolves only on your
  own network, as in a homelab, use a TXT record in the domain's public zone, or have the Instance
  Admin mark the claim trusted (`rpmgr trust domain <claim ID>`).

The controller checks pending claims on its own, often at first and then less often, and marks a
claim **failed** that it could not prove for a while ([15](../15-dns.md#timers-and-limits)).
**Check now** checks at once. For a TXT claim, **Check now** still checks a failed claim. The
gateways serve an HTTP token only while its claim is pending, so remove a failed HTTP claim and
claim the name again ([15](../15-dns.md#domain-verification)).

### Claim a domain with the web UI

1. Open **Domains & certificates** and choose **Claim a domain**.
2. Enter the **Domain**, such as `example.com`.
3. Check **Also every name below it** if routes will use names below it.
4. Under **How to prove it is yours**, choose **A DNS TXT record** or **An HTTP token, served by
   your gateways**, and choose **Claim it**.
5. The claim shows what to do: for TXT, the **TXT record name** and the **Value** to create at your
   DNS provider; for HTTP, the URL the gateways serve and the token. Create the record, or point the
   name at your gateways.
6. Choose **Check now**. The claim shows **verified**, or stays **pending** with when it was checked
   and why the proof was not found.

### Claim a domain with the command line

```sh
rpmgr create domain --fqdn example.com --wildcard
```

The command prints the TXT record to create, and the claim's ID:

```text
To prove the claim, add this TXT record at the domain's DNS:
  _rpmgr-challenge.example.com  TXT  "…"
The controller checks it on its own; to check now: rpmgr verify domain dom_…
```

Then check, and list your claims with their status:

```sh
rpmgr verify domain dom_01JA2Z8Q6W7Y3V9K4M5N6P7Q8R
rpmgr list domain
```

`rpmgr verify domain` says why a claim is not verified yet, such as no authoritative answer or a
wrong value. The domain commands take the claim's ID, which `rpmgr list domain` shows.

### Statuses

| Status | Meaning |
|---|---|
| **pending** | Waiting for its proof; checked on a schedule and with **Check now** |
| **verified** | Proved, or trusted by the Instance Admin; routes may use names under it |
| **failed** | Not proved in time; **Check now** may still verify a TXT claim; claim an HTTP one again |
| **waiting for approval** | A claim that needs the Instance Admin's approval; such claims come with Phase 2 ([05](../05-features.md#tls-and-domains)) |

### Trusted domains

The Instance Admin can mark a claim verified without a proof, for a name that cannot be proved,
such as an internal domain without public DNS: **Mark as trusted** on the claim, or
`rpmgr trust domain <id>`. Both ask for a step-up first. The claim's method then reads **trusted by
the Instance Admin**. A trusted name is still claimed once in the instance: a later claim by another
organisation is refused, and the Instance Admin decides
([D13](../14-open-decisions.md#tenancy-and-data)).

### Remove a claim

**Remove…** on the claim, or `rpmgr delete domain <id>`. The removal is refused while a route's
hostname, or the hostname of a CONNECT listener, lies under the claim.

## Certificates

HTTP routes end TLS at the gateway with a certificate from ACME or one you uploaded; the route's
**TLS certificate** setting chooses ([HTTP routes](routes/http.md#certificates)). The
**Certificates** card under **Domains & certificates** lists both kinds with their names, status,
issuer, expiry and, for uploaded ones, the routes that use them. A certificate that expires within
21 days shows "expires soon", and the overview lists it under "Needs attention".

### ACME certificates

For each hostname of an enabled HTTP route whose certificate is **From ACME**, the controller
obtains a certificate of its own and renews it well before it expires
([04](../04-security.md#controller-certificates)). You do nothing but point the hostname at the
gateways.

1. The controller asks the instance's ACME CA for a certificate.
2. It hands the CA's challenge to every enabled gateway of the route's group: HTTP-01 on port 80,
   TLS-ALPN-01 on port 443. Only when all of them have it does it let the CA validate.
3. The CA connects to the hostname and finds the answer at whichever gateway it reaches.
4. The certificate goes to the gateways, which serve it from then on.

A new certificate shows **being obtained**, then **active**. One that could not be obtained shows
**failed** with the CA's error; one whose renewal failed stays **active**, keeps serving, and shows
the error. **Renew now** on an ACME certificate, or `rpmgr renew certificate <id>`, renews it at
once or obtains it after a failure. **Renew now** answers "Renewal started." or "A renewal is under
way already.", and the command says the same in its own words. The certificate shows the outcome
once it is known; `rpmgr get certificate <id>` shows it on the command line.

#### The ACME CA and account

The instance's ACME CA and account are instance settings, which only the Instance Admin sees and
changes: **Settings**, section **ACME certificates**, fields **ACME directory URL** and **ACME
account e-mail address** ([Settings](operations/settings.md)).

- **Directory.** Let's Encrypt's production directory by default. For tests, Let's Encrypt's
  staging directory, `https://acme-staging-v02.api.letsencrypt.org/directory`, issues certificates
  that no browser trusts but does not count against the production limits. Any other ACME CA works
  with its directory URL. `rpmgr setup` asks for it at installation, as `--acme-directory
  production`, `staging` or a URL ([rpmgr setup](install/setup.md)).
- **E-mail address.** The contact address of the ACME account, which the CA keeps with it. None by
  default.

On the command line:

```sh
rpmgr update settings --instance \
  --set acme_directory_url=https://acme-staging-v02.api.letsencrypt.org/directory \
  --set acme_email=ops@example.com
```

An empty value, such as `--set acme_email=`, restores the default. The controller's own certificate
for its public URL comes from the same CA and account, and takes a change at its next start.

#### What can block an ACME certificate

- **DNS.** The hostname's A and AAAA records must point at the public addresses of the route's
  gateway group. A name of a private address can never be validated: give its route an uploaded
  certificate.
- **Reachability.** Port 80 or port 443 of the gateways must be reachable from the internet, where
  the CA validates from.
- **A gateway that cannot take the challenge.** Every enabled gateway of the group must
  acknowledge the challenge before the CA validates. A gateway that is offline, or created but not
  enrolled yet, makes each attempt fail. Bring it online, or drain it ([Gateways](gateways.md)).
- **A wildcard hostname.** ACME wildcard certificates need DNS-01, which comes with DNS automation
  in Phase 2; until then such a route needs an uploaded certificate, and is refused with **From
  ACME** ([05](../05-features.md#tls-and-domains)).
- **The controller cannot reach the CA.** The controller dials the CA directly, or through the proxy
  that `HTTPS_PROXY`, else `ALL_PROXY`, names, unless `NO_PROXY` exempts the CA
  ([Environment variables](reference/environment.md)).
- **The CA's limits.** After a failure, the controller tries a hostname again only after waits
  that double with each failure ([03](../03-connections.md#timeouts-keepalive-and-backoff)). When
  the CA is Let's Encrypt's production directory, it first rehearses each retry at Let's Encrypt's
  staging directory, so that failed attempts do not use up the account's limits there. Another CA
  gets no rehearsal. Once you fixed the cause, **Renew now** tries at once.

A runbook walks through these steps
([10](../10-operations.md#a-route-certificate-is-not-obtained)).

### Uploaded certificates

Upload a certificate when ACME cannot give one: for wildcard hostnames, for names the CA cannot
validate, for many hostnames under one domain, which one wildcard certificate serves without asking
the CA for each ([10](../10-operations.md#many-hostnames-under-one-domain)), or for certificates of
your own CA.

The upload is the PEM chain, the server's certificate first and each certificate signed by the next,
and the server certificate's PEM private key. The controller checks the chain, the key and the
names, and keeps the key encrypted; it never shows it again. The key types and sizes it accepts and
the chain's limits are fixed ([04](../04-security.md#controller-certificates)).

**With the web UI:**

1. Open **Domains & certificates** and, in the **Certificates** card, choose **Upload a
   certificate**.
2. Paste the **Certificate chain (PEM, the certificate first)** and the **Private key (PEM)**, or
   read each from a file. The key stays in the page until you send it.
3. Choose **Upload**.

**With the command line:**

```sh
rpmgr upload certificate --chain fullchain.pem --key privkey.pem
```

```text
Uploaded certificate crt_… for [example.com *.example.com], valid until 2027-01-13.
```

The command warns when other users may read the key file.

**Use it on a route.** In the route's **Edit** form, set **TLS certificate** to **Uploaded** and
choose the certificate in **Uploaded certificate**; or:

```sh
rpmgr update route --tls-mode certificate --certificate crt_01JB4C7D2E9F3G5H6J8K1M2N3P wiki
```

The certificate must cover every hostname of the route; the form offers only those that do. The
command line takes the certificate's ID: the upload command prints it, the certificates list in the
web UI shows it with a **Copy** button, and `rpmgr list certificate` lists them.

**Renew it yourself.** rpmgr never renews an uploaded certificate. Before it expires, upload the
renewed one, move each route to it as above, then remove the old one: **Remove…** in the list, or
`rpmgr delete certificate <id>`. A certificate is not removed while a route uses it, and an ACME
certificate is never removed by hand: the controller keeps it while a route needs it.

## CA bundles

A CA bundle holds the CA certificates that an HTTPS target's certificate must chain to, when it is
not signed by a CA the gateway's host trusts, such as your own internal CA
([Targets](routes/targets.md#https-verified)). Each certificate in a bundle counts as a trust
anchor, so a bundle may also hold a target's self-signed certificate. The number of certificates a
bundle holds is limited ([04](../04-security.md#controller-certificates)).

**With the web UI:**

1. Open **Domains & certificates** and, in the **CA bundles** card, choose **Add a CA bundle**.
2. Enter a **Name** and paste the **CA certificates (PEM)**, or read them from a file.
3. Choose **Add the bundle**.

Each bundle lists its certificates with their subjects and expiry, and how many targets use it.
**Edit…** changes its name or certificates, and **Remove…** removes it, which is refused while a
target uses it.

**With the command line:**

```sh
rpmgr create ca-bundle --name home-ca --pem-file home-ca.pem
rpmgr update ca-bundle --pem-file home-ca-2027.pem home-ca
rpmgr delete ca-bundle home-ca
```

A target chooses its bundle in **CA bundle**, by name, or **None: the system's roots**; on the
command line it names it with `--ca-bundle <name or ID>`. The web UI's list of bundles shows each
bundle's ID with a **Copy** button, and `rpmgr list ca-bundle` lists them.
