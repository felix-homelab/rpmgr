# Enrolling connectors

A connector joins your organisation by **enrolling**: it trades a one-time enrollment token for a
certificate of its own, and from then on authenticates with that certificate alone. This page is
for whoever adds connectors: the Owners and Admins of an organisation, and its Operators if the
organisation lets them. It covers enrollment tokens, the web UI's enroll dialog, the command line,
and how to re-enroll a connector that lost its identity.

## How enrollment works

1. In the web UI or with the command line you make an **enrollment token** for the organisation.
   The controller shows it once and keeps only its hash.
2. On the connector's host, the **install command** installs rpmgr and runs `rpmgr enroll`, which
   asks for the token. The command holds the controller's URL and its **CA pin**, never the token.
3. The host downloads the controller's trust bundle and keeps only the root certificate whose key
   matches the pin, so nobody in between can make it trust another certificate authority
   ([PKI](../operations/pki.md#the-ca-pin)).
4. The host makes a key pair, which never leaves it, and sends the token with a certificate request
   over TLS that trusts only the pinned root. The controller uses up the token, gives the connector
   an ID and a name, and returns its certificate.
5. The connector opens its control session to the controller and gets its configuration.

The token decides what the connector becomes: its organisation, labels, gateway group and whether
it is ephemeral. The host chooses none of it ([03](../../03-connections.md#enrollment)).

## Enrollment tokens

| Kind | How you make it | Uses | What it enrolls |
|---|---|---|---|
| One-time | The default | One connector | A new connector |
| Reusable | Ephemeral, with more uses or `0` for any number | As many connectors as it allows | New ephemeral connectors, such as CI runners ([Connector lifecycle](lifecycle.md#ephemeral-connectors)) |
| Re-enrollment | Command line, `--connector` | One | The same connector again, with a new key ([Re-enroll a connector](#re-enroll-a-connector)) |
| Gateway | For one gateway an Admin created | One | That gateway ([Gateways](../gateways.md#add-a-gateway)) |

- **Lifetime.** Every token expires. Its default and longest lifetime are in
  [04](../../04-security.md#tokens); the web UI offers a choice of lifetimes, and the command line
  takes `--ttl`. A token that is used up, expired or revoked enrolls nothing more.
- **Scope.** A connector token belongs to the organisation and may name a gateway group and labels,
  which each connector it enrolls gets, and whether those connectors are ephemeral. Only an
  ephemeral token may enroll more than one connector.
- **Secret once.** The token, `rpmgr_enr_…`, is shown only when you make it. It never goes on a
  command line, into a unit file or a log: the installer asks for it, or reads it from a file or
  `RPMGR_ENROLL_TOKEN` ([Join command](../../04-security.md#join-command)). A one-time token that
  leaks after its use is worthless; revoke a token that leaks before, and a reusable one as soon as
  it is no longer needed.
- **Who.** Making a token needs the permission to enroll connectors (Owner and Admin, and Operator
  when the organisation's setting allows it, [Settings](../operations/settings.md)) and a step-up:
  you confirm it is you with your second factor, or your password if you have none.

## Before you start

- A controller that runs, and the gateways of the gateway group your routes use
  ([Gateways](../gateways.md)).
- A Linux host for the connector that can reach the controller's public URL and the gateways'
  tunnel endpoints over TCP 443, and UDP 443 for QUIC; it needs no inbound port
  ([Connector networking](network.md)).
- The addresses of the services the connector should reach. The connector reaches nothing until
  its local policy allows it ([The local policy](local-policy.md)).
- `sudo` on the host.

## Enroll with the web UI

1. Open **Connectors** and select **Enroll a connector**.
2. Fill in the dialog:
   - **Labels**: optional, one `key=value` per line; each connector the token enrolls gets them.
   - **Gateway group**: **Any gateway group**, or the one the token is for.
   - **Kind**: **Permanent**, or **Ephemeral** for connectors that are removed after they last
     disconnect ([Connector lifecycle](lifecycle.md#ephemeral-connectors)).
   - **The token is valid for**: how long the token lasts.
   - **Connectors it may enroll**: only for an ephemeral token; `0` for any number.
   - **Targets the connector may reach**: one per line, an address or subnet with an optional port
     or port range (`10.0.0.5:5432`, `10.0.0.0/16`, `127.0.0.1:200-500`), IPv6 in brackets, or a
     socket path. The installer writes them into the host's local policy.
   - **Targets the connector must not reach**: optional, in the same form; they win over the
     allowed ones.
3. Select **Create the token** and confirm it is you.
4. The dialog shows **1. On the host, run:** with the **Install command**, and **2. When the
   installer asks for it, paste this token.** with the **Enrollment token** behind **Show**. Copy
   both.
5. Run the command on the host and paste the token at the prompt. The dialog shows **Waiting for
   the connector to enroll and connect…**, and opens the new connector's page once it has.

The **Enrollment tokens** card on the Connectors page lists the tokens that can still enroll, with
their use count, expiry and last use. **Revoke…** ends one.

## Enroll with the command line

You need `rpmgr` logged in to the controller
([API tokens and the command line](../accounts/api-tokens-and-cli.md)).

1. Make the token. Without flags it is a one-time token with the default lifetime:

   ```sh
   rpmgr create enrollment-token --label site=home
   ```

   ```text
   This change needs a step-up. Your authenticator or recovery code, or your password if you have no second factor:
   Enrollment token enr_01M4ZEP6WAEFYARXR7AK81NQE9, valid until 2026-10-15T10:35:57Z; it is shown only now:
   rpmgr_enr_…
   ```

   Other flags: `--ttl 24h`, `--gateway-group <group>`, and for an ephemeral token `--ephemeral`
   with `--max-uses <n>` (`0` for any number). More than one use without `--ephemeral` is refused.

2. Print the install command, with the targets the connector may reach. Flags come before the
   argument:

   ```sh
   rpmgr get --allow-target 192.168.1.20:8080 --deny-target 192.168.1.1 install-command
   ```

   ```text
   curl -fsSLO 'https://panel.example.com/install.sh' && sudo sh install.sh \
     --controller 'https://panel.example.com' --ca-pin 'sha256:XOCDT8EkqMT2J5JWgt+BH8H82MFTr37JH+8l70Fe2vk=' \
     --allow-target '192.168.1.20:8080' \
     --deny-target '192.168.1.1'
   ```

3. Run that command on the host and give it the token.

`rpmgr list enrollment-token` shows the tokens that can still enroll, and
`rpmgr list --all enrollment-token` the used-up, expired and revoked ones too.
`rpmgr revoke enrollment-token <id>` ends one.

## On the host

The install command downloads the controller's install script and runs it with `sudo`. The script
installs the binary, writes the connector's boot file and local policy, enrolls, and starts
`rpmgr-connector.service`
([Install script](../install/install-script.md#the-controllers-install-script)). It saves the
script before it runs it rather than piping it into `sudo sh`, because some `sudo` versions pass
nothing typed at the terminal to a piped script.

The enrollment reads the token from, in this order:

1. `--token-file <file>`, for unattended installs; the file should be readable by root only, and
   you delete it afterwards;
2. `RPMGR_ENROLL_TOKEN`, if you pass it through `sudo` explicitly:
   `sudo --preserve-env=RPMGR_ENROLL_TOKEN sh install.sh …`;
3. otherwise a prompt on the terminal, `Enrollment token:`, which does not echo.

Instead of the install command you can use `rpmgr setup --role connector`, which asks for every
value in forms ([rpmgr setup](../install/setup.md)), or install by hand and run `rpmgr enroll`
yourself ([Manual installation](../install/manual.md)):

```sh
sudo rpmgr enroll --controller https://panel.example.com \
  --ca-pin sha256:XOCDT8EkqMT2J5JWgt+BH8H82MFTr37JH+8l70Fe2vk= --token-file /root/enroll-token
```

```text
Enrolled connector con_01M4ZEK2EXFBJRKFW4JB7DQVZ6 in trust domain rpmgr-ewl35s75; identity written to /var/lib/rpmgr/identity.
```

`rpmgr enroll` writes only the identity, into `--identity-dir` (default `/var/lib/rpmgr/identity`),
which must be closed to other users. It downloads the trust bundle from the public URL, so the
host must trust the controller's web certificate. For a controller with a self-signed one, fetch
the bundle yourself and pass it with `--trust-bundle <file>`; the pin still decides which root the
host keeps from it:

```sh
curl -fsSk -o rpmgr-bundle.pem https://panel.example.com/.well-known/rpmgr/trust-bundle
```

## What happens next

- The connector is named after the host, such as `nas`, or `nas-2` if the organisation has a
  connector of that name already. Rename it on its page under **Settings**, or with
  `rpmgr update connector --name <name> <connector>`.
- It opens its control session and data sessions to the gateways of the routes it serves. Its page
  shows **Control session up from …** and one row per data session
  ([Status and diagnostics](status-and-diagnostics.md)).
- It serves nothing until a route has a target on it ([Targets](../routes/targets.md)) and its
  local policy allows that target. A route whose target the policy blocks shows the command that
  allows it ([The local policy](local-policy.md)).

## Re-enroll a connector

Re-enroll a connector when its host lost the identity files, its certificate expired longer ago
than the grace period ([04](../../04-security.md#leaf-certificates)), or you rebuilt the host and
want it to keep its ID, name, labels and targets. Re-enrollment gives it a new key; the
certificates it had before are revoked as soon as the new one is issued
([Re-enroll a connector](../../10-operations.md#re-enroll-a-connector)).

1. Make a re-enrollment token, bound to that one connector. The host cannot choose which connector
   it replaces:

   ```sh
   rpmgr create enrollment-token --connector nas
   ```

   It is always a one-time token, not ephemeral and without labels. The web UI does not make such
   tokens.

2. On the host, enroll with `--replace`, give the identity to the service user, and restart the
   connector:

   ```sh
   sudo rpmgr enroll --replace --controller https://panel.example.com \
     --ca-pin sha256:XOCDT8EkqMT2J5JWgt+BH8H82MFTr37JH+8l70Fe2vk= --token-file /root/enroll-token
   sudo chown -R rpmgr:rpmgr /var/lib/rpmgr/identity
   sudo systemctl restart rpmgr-connector.service
   ```

   Or run `rpmgr setup --role connector --force`, which does all three
   ([rpmgr setup](../install/setup.md)).

Without `--replace`, `rpmgr enroll` refuses a host that has an identity: `this host is already
enrolled; use --replace to enroll it again`. The install script skips the enrollment on such a host
and says so.

There is no re-enrollment for:

- **a decommissioned connector**: its identity is revoked for good. Enroll the host as a new
  connector with an ordinary token;
- **an ephemeral connector**: enroll a new one;
- **the all-in-one's built-in connector**: `rpmgr all-in-one` enrolls it at start when its identity
  is missing.

## Troubleshooting

| Message | Cause | Fix |
|---|---|---|
| `the enrollment token is malformed or mistyped (rpmgr_enr_…)` | The token was not copied whole; `rpmgr enroll` checks it before it contacts the controller | Copy the token again |
| `rpc error: code = Unauthenticated desc = invalid token` | The token is used up, expired or revoked | Make a new token |
| `pki: no root in the bundle matches the pin` | The `--ca-pin` is not this controller's | Copy the pin from the install command or Settings → PKI |
| `download the trust bundle: … certificate signed by unknown authority` | The host does not trust the controller's web certificate | Give the controller a trusted certificate, or pass `--trust-bundle` |
| `this host is already enrolled; use --replace to enroll it again` | The host has an identity | Re-enroll with a re-enrollment token, or `rpmgr leave` first |
| `identity directory … has mode 0755; it must be closed to the group and other users (0700)` | The identity directory is open to others | `sudo chmod 700 <dir>` |
| `too many enrollments from this address` | The controller limits enrollments per address ([04](../../04-security.md#human-authentication-and-sessions)) | Wait, then try again |
| `the gateway or connector is decommissioned`, when you make the token | A re-enrollment token for a decommissioned connector | Enroll it as a new connector |
| `the token's connector is decommissioned or gone`, when the host enrolls | The connector was decommissioned after its re-enrollment token was made | Enroll it as a new connector |

More symptoms are in [Troubleshooting](../operations/troubleshooting.md#enrollment-fails).
