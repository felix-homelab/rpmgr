# API tokens and the command line

A personal API token lets the `rpmgr` command line, a script or another program act for you on
the controller's API. This page is for anyone who manages rpmgr from a terminal or automates it:
it explains what a token may do, how to make one in the web UI, how `rpmgr login` stores it for
the command line, how a token confirms your identity for sensitive changes, and how to revoke it.
Calling the API directly is described in [API](../reference/api.md).

## What a token is

- **Personal:** a token belongs to you and to one organisation. Its owner's name is in the audit
  log for everything it does.
- **Scoped:** it carries one or more scopes, each one permission. It can do only what its scopes
  allow, and never more than your role in the organisation allows now: lowering your role or
  removing you from the organisation limits your tokens at once
  ([Members and roles](members-and-roles.md#roles-and-api-tokens)).
- **Expiring:** every token has an expiry, which you choose when you make it, up to a maximum
  ([04](../../04-security.md#human-authentication-and-sessions)). The overview lists your tokens
  that expire soon ([Overview](../web-ui/overview.md#needs-attention)).
- **Shown once:** the controller keeps only a hash of the token. It starts with `rpmgr_pat_`; the
  web UI shows its start, the prefix, which is `rpmgr_pat_` and the next four characters, so that
  you can tell tokens apart.
- **Made in the web UI only**, from a signed-in session after a step-up, so that a token never
  makes another token.

Service accounts, whose tokens belong to no person, come with Phase 2
([05](../../05-features.md#identity-and-access)).

### Scopes

| Scope | Allows |
|---|---|
| `org.read` | Viewing resources, status and metrics; every command needs it |
| `routes.write` | Routes, their targets and access policies |
| `connectors.write` | Enrolling connectors, changing, switching off and decommissioning them, and revoking enrollment tokens |
| `infrastructure.write` | Gateways and their enrollment tokens, gateway groups, port pools and quotas, domains, certificates and CA bundles |
| `members.write` | Members and invitations, and the restore review, which only an Owner confirms |
| `audit.read` | Reading the audit log |
| `org.write` | Renaming the organisation, its settings and its second-factor requirement |
| `instance.admin` | The instance: the CA's intermediate, the instance's settings and the mail relay's password, the instance's audit log, trusted domains and the list of users; offered to the Instance Admin only |

A scope your role does not have is refused when you make the token. Give a token only the scopes
its job needs: a backup script that reads, `org.read` alone; a deployment that changes routes,
`org.read` and `routes.write`.

## Make a token

### Before you start

- You can sign in to the web UI.
- If your organisation requires a second factor, sign in with it: the requirement accepts only
  tokens made from a session that used one ([Sign-in and two-factor
  authentication](sign-in-and-mfa.md#when-your-organisation-requires-it)).

### Steps

1. Open **Your account** from the user menu in the top bar.
2. In **API tokens**, press **New token…**.
3. Enter a **Name** that says where the token is used, such as `laptop-cli`.
4. Enter **Valid for (days)**. It starts with the default lifetime.
5. Tick the **Scopes**. `org.read` is ticked to start with.
6. Press **Create the token**, and confirm your identity if the step-up dialog asks.
7. The card shows the token: `Copy the token now. It is shown only once.` Press **Copy** and keep
   the token where you need it, such as a password manager.
8. Under the token, the card shows the `rpmgr login` command for this controller and
   organisation. Copy it too, then press **I have copied it**.

The token is now listed with its name, prefix, expiry and scopes
([Account](../web-ui/account.md#api-tokens)).

## Log in on the command line

`rpmgr login` checks the token against the controller and stores it for every command of the
public API, such as `rpmgr list route` or `rpmgr create route`. Flags come before the name, the ID
or the kind, as in `rpmgr get -o yaml route web`: a command reads no flag after its first argument
that is not a flag.

```sh
rpmgr login --controller https://panel.example.com --org org_01M4ZEXGQAF0P9DZXJYKCMBTGG
```

- `--controller` is the controller's public URL, and `--org` the organisation's ID; the command
  the web UI shows has both.
- The command asks for the token on the terminal, without echoing it. It never takes the token on
  the command line, where the shell's history and the process list would keep it. Instead of the
  prompt, `--token-file <file>` reads it from a file, or the variable `RPMGR_TOKEN` holds it
  ([Environment variables](../reference/environment.md)).
- `--ca-file <file>` verifies the controller with the CA certificates in that PEM file instead of
  the system's roots, for a controller whose certificate the system does not trust.

On success it prints the controller, the organisation's name and ID, and where it stored the
token:

```text
Logged in to https://panel.example.com, org Example Lab (org_01M4ZEXGQAF0P9DZXJYKCMBTGG); the token is in /home/ada/.config/rpmgr/credentials.yaml.
```

The file is `rpmgr/credentials.yaml` in your configuration directory (`~/.config` on Linux, unless
`XDG_CONFIG_HOME` says otherwise), or wherever `RPMGR_CREDENTIALS` points. It is readable by you
only; the command line refuses a credentials file that other users may read or write.

What `rpmgr login` says when it refuses:

| Message | Cause |
|---|---|
| `that is not a personal API token; create one in the web UI under Account` | The text does not start with `rpmgr_pat_` |
| `the controller does not accept the token: it is unknown, expired or revoked` | Make a new token |
| `the token lacks the org.read scope, which every command needs` | Make a token with `org.read`. The same message comes when the organisation requires a second factor and the token was made from a session without one: sign in with your authenticator and make a new token |
| `the token does not belong to the org …` | `--org` names another organisation than the token's |

Any later command that the controller refuses for an invalid token says to log in again with a
valid token. A command run before any login says `not logged in: run rpmgr login`.

## Step-up with a token

Some changes need a fresh confirmation of your identity: making an enrollment or gateway token,
granting the Admin or Owner role, changing the organisation's second-factor requirement, marking a
domain as trusted, and others ([Step-up](sign-in-and-mfa.md#step-up-confirming-it-is-you)). On
the command line, such a command asks on the terminal:

```text
This change needs a step-up. Your authenticator or recovery code, or your password if you have no second factor:
```

Enter a code from your authenticator, a recovery code, or, without an authenticator, your password.
The command then steps the token up and runs the change. The confirmation covers this token only,
for a few minutes ([D63](../../14-open-decisions.md#engineering);
[04](../../04-security.md#human-authentication-and-sessions)); your sessions in the browser and your
other tokens keep their own. A stolen token alone therefore still makes no such change. Without a
terminal, such a command fails with `the change needs a step-up, which needs a terminal`.

## List and revoke tokens

- **With the web UI:** **Your account**, **API tokens**: each token shows when it was last used and
  from which address; **Revoke…** and **Revoke it** revoke it at once.
- **With the command line:**

  ```sh
  rpmgr list token
  rpmgr revoke token <id>
  ```

Revoke a token you no longer need, and at once a token that may have leaked. You can revoke only
your own tokens. A new password, authenticator or set of recovery codes ends your other sessions
but no token: if someone else may have used your account, check this list as well
([Sign-in](sign-in-and-mfa.md#sessions)).

## Log out

```sh
rpmgr logout
```

It removes the stored credentials from this machine. The token itself stays valid until it
expires; revoke it if no one needs it any more.

## Use a token from a script

A program sends the token in the `Authorization: Bearer` header of each API call; the API never
accepts it in a URL. [API](../reference/api.md) shows a first call and the errors to expect.

## Tokens after a restore

A restore that puts the organisation into a restore review suspends its API tokens. The Owner
resumes those they trust, one by one, on the **Organisation** page
([Organisation](../web-ui/organisation.md#restore-review)).

## Troubleshooting

- **`the permission … is missing`:** the token lacks that scope, or your role lacks that
  permission. Make a token with the scope, or ask an Owner or an Admin for the role.
- **`not found` for something that exists:** the token belongs to another organisation; log in with
  a token of the right one.
- **More:** [Troubleshooting](../operations/troubleshooting.md).
