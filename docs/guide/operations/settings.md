# Settings

Most of rpmgr's configuration lives in its database as settings, changed in the web UI or with the
command line, without a restart. This page is for an organisation's Owners and for the Instance
Admin: it lists every setting of the organisation and of the instance, what it does and how to
change it. What a host needs before it starts is in its boot file instead
([Boot files](../reference/boot-files.md)).

## Two levels

| Level | Who changes it | Who sees it | Web UI |
|---|---|---|---|
| Organisation settings | Its Owners (the permission `org.write`) | Every member | **Settings**, **Organisation settings** |
| Instance settings | The Instance Admin | The Instance Admin | **Settings**, **Instance settings**, and the **PKI** and **Updates** tabs |

Other settings belong to the things they configure: a gateway group's public hostnames, trusted
proxies, port pools and quotas ([Gateways](../gateways.md)), a connector's transport
([Connector networking](../connectors/network.md#choose-a-transport)), and on each connector's host
its local policy ([The local policy](../connectors/local-policy.md)).

## Change settings

### With the web UI

Open **Settings**, change the fields and select **Save**. A field you empty goes back to its
default. If someone else saved the settings since the page loaded them, the save is refused with
**The settings changed since this page loaded them. The page shows them as they are now; try
again.** Changes that concern agents, such as the default transport, reach them as a new revision,
like any change of the configuration.

### With the command line

```sh
rpmgr get settings                          # the organisation's settings
rpmgr get --instance settings               # the instance's, for the Instance Admin
rpmgr update settings --set operators_may_enroll=true
rpmgr update settings --instance --set default_transport=h2 --set audit_retention=730d
rpmgr update settings --instance --set default_transport=   # back to the default
```

`get settings` lists every setting by the name `update settings` takes, with the defaults filled
in. Values are written as:

- a switch as `true` or `false`;
- a duration in days or hours, such as `30d` or `12h`;
- a choice by its name: `auto`, `quic` or `h2`; `default` or `low-memory`; `stable` or
  `prerelease`; `starttls` or `tls`;
- a list separated by commas:
  `--set public_url_aliases=https://rpmgr.example.com,https://panel.example.net`;
- a part of the mail relay by its path: `--set smtp.server=mail.example.com:587`;
- an empty value restores the default.

`update settings` sends the version it read, like every update, and `--force` skips that check.
The API's methods are in [settings.proto](../../../proto/rpmgr/v1/settings.proto).

## Organisation settings

| Web UI | Name | What it does |
|---|---|---|
| **Every member must sign in with a second factor** | `require_mfa` | Members who signed in without a second factor are refused in the organisation (`MFA_REQUIRED`), and so are API tokens made from such sessions. Members can always set up an authenticator. Changing it needs a step-up |
| **Operators may enroll and revoke connectors** | `operators_may_enroll` | Gives Operators the permission to enroll, change and decommission connectors ([Members and roles](../accounts/members-and-roles.md)) |
| **Gateway group preselected for new routes** | `default_gateway_group_id` | The group the route form offers first; **None** offers none. The command line takes the group's name or ID |

Before you turn on **Every member must sign in with a second factor**, set up your own
authenticator and sign in with it, and make new API tokens from that session: from then on, a token
made from a session without a second factor is refused in the organisation, yours included
([Sign-in and two-factor authentication](../accounts/sign-in-and-mfa.md)).

## Instance settings

The Instance Admin's **Settings** page has the sections below; **PKI** and **Updates** are tabs of
their own.

### Agents and transport

| Web UI | Name | What it does |
|---|---|---|
| **Default transport** | `default_transport` | The data-session transport of every connector and route without one of its own: **QUIC, falling back to TLS and HTTP/2** (`auto`, the default), **QUIC only** or **TLS and HTTP/2 only** ([Connector networking](../connectors/network.md)) |

### Web UI and controller endpoints

| Web UI | Name | What it does |
|---|---|---|
| **Further public URLs of the web UI** | `public_url_aliases` | Other URLs under which browsers reach the web UI, one per line, such as `https://rpmgr.example.net`. The API accepts calls from these origins as from the public URL |
| **Controller endpoints for agents** | `controller_endpoints` | The URLs agents try for their control session, in order, one per line, each `https://<host>[:<port>]`; empty means the public URL. The list replaces the public URL, so name it too if agents should still try it. List here a gateway that publishes a private controller, or a second address of the controller ([Gateways](../gateways.md#reaching-a-private-controller-through-a-gateway)) |

Agents get the list when they enroll. A change reaches every connected agent with its next
configuration, which the change itself sends, and the agent uses it from its next connection
attempt on. A list in which no endpoint works cuts agents off from the controller, and only a
connector has a last resort
([Connector networking](../connectors/network.md#when-the-controller-is-out-of-reach)), so add
new endpoints before you remove old ones.

### Traffic statistics

| Web UI | Name | What it does |
|---|---|---|
| **Keep hourly statistics (days)** | `hourly_rollup_retention` | How long the hourly traffic of routes is kept for their charts |
| **Keep daily statistics (days)** | `daily_rollup_retention` | How long the daily traffic is kept |

The form names the range each takes.

### ACME certificates

| Web UI | Name | What it does |
|---|---|---|
| **ACME directory URL** | `acme_directory_url` | The ACME CA for route certificates and the controller's own: Let's Encrypt's production directory by default, or another CA's, such as Let's Encrypt's staging directory for tests |
| **ACME account e-mail address** | `acme_email` | The contact address of the ACME account, at which the CA may write about expiring certificates; none by default |

`rpmgr setup` sets both before the controller first starts (`--acme-directory production`,
`staging` or a URL, and `--acme-email`). A change reaches route certificates with their next order,
and the controller's own certificate at its next start
([Domains and certificates](../domains-and-certificates.md#the-acme-ca-and-account)).

### Mail relay

Without a mail relay, the controller sends no e-mail: Owners and Admins pass invitation and
password-reset links on themselves, and **Forgot your password?** on the sign-in page tells users
to ask for a link. With one, those links are also e-mailed, and users can ask for a password reset
themselves ([04](../../04-security.md#human-authentication-and-sessions)).

| Web UI | Name | What it does |
|---|---|---|
| **Relay host:port** | `smtp.server` | The relay, such as `mail.example.com:587`; empty: no mail |
| **Sender address** | `smtp.from` | The address the mails come from; needed with a relay |
| **User name** | `smtp.username` | The user name to log in with; empty for a relay that needs none |
| **Encryption** | `smtp.security` | **STARTTLS, usually port 587** (`starttls`) or **TLS, usually port 465** (`tls`). The controller never sends mail in plain text |
| **Relay password** | — | Write-only: the form says whether one is **set**, and **Remove the password** removes it |

With the command line, the password comes from a file or the terminal, never from the command line:

```sh
rpmgr update settings --instance --set smtp.server=mail.example.com:587 \
  --set smtp.from=rpmgr@example.com --set smtp.username=rpmgr --set smtp.security=starttls
rpmgr set smtp-password --password-file /root/smtp-password
rpmgr set smtp-password --remove
rpmgr update settings --instance --set smtp=        # no relay
```

There is no test mail: invite yourself, or ask for a password reset, to see that mail arrives. Why a
relay refused a mail is in the controller's log ([Monitoring](monitoring.md#logs)).

### Audit log

| Web UI | Name | What it does |
|---|---|---|
| **Keep audit entries (days)** | `audit_retention` | How long audit entries are kept; older ones go, up to a signed checkpoint ([Audit log](audit-log.md#how-long-entries-are-kept)) |

### PKI tab

| Web UI | Name | What it does |
|---|---|---|
| **Agent certificate lifetime (days)** | `leaf_certificate_lifetime` | How long agents' certificates last |
| **Grace after expiry (days, 0 for none)** | `expired_certificate_grace` | How long an agent that was offline past its certificate's expiry may still renew it |
| **Password hashing** | `password_hash_profile` | **Default**, or **Low memory (below 1 GiB)** (`low-memory`) for small controller hosts |

The tab also shows the CA and rotates its intermediate ([PKI](pki.md)). The ranges and defaults
of the certificate settings are in [04](../../04-security.md#leaf-certificates).

### Updates tab

| Web UI | Name | What it does |
|---|---|---|
| **Check for releases once a day** | `release_check` | On by default. The controller fetches the signed release manifest from GitHub, sending nothing about the installation, and mirrors the release files of its own version under `/dl/` for the install scripts ([10](../../10-operations.md#ports)) |
| **Release channel** | `update_channel` | **Stable**, or **Pre-releases too** |

Turn the release check off for a controller without internet access, and import releases by hand
instead ([Air-gapped installations](../install/air-gapped.md)). Updates rolled out to agents by the
controller are planned for Phase 2 ([13](../../13-roadmap.md#phase-2--production)).

## Warnings on the Settings page

The Instance Admin's **Settings** page shows two warnings about the revocation log, the record of
revocations that a restore needs ([Backup and restore](backup-and-restore.md)):

- **The revocation log has no copy off this host. …**: the controller keeps the log on its own host
  only, and every backup includes it. A sink on a share, `revocation_log.sink` in the controller's
  boot file, keeps a copy should the host be lost. After setting it, write the unit again with
  `rpmgr systemd-unit`, which makes the sink writable for the service
  ([Backup and restore](backup-and-restore.md#the-revocation-log-sink)).
- **The revocation log is not yet off-host: … entries have waited since … to reach the sink.
  Revocations are still enforced.**: a sink is set, but an entry has waited too long to reach it
  ([10](../../10-operations.md#suggested-alerts)). Check that the directory exists, that the share
  is mounted, that the user `rpmgr` may write to it and that the unit names it in
  `ReadWritePaths=` ([Backup and restore](backup-and-restore.md#the-revocation-log-sink)). The
  controller's log says why it failed, and the controller keeps trying.
