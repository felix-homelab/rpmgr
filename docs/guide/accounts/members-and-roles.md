# Members and roles

An organisation's members each have one role, which decides what they may do in it. This page is
for Owners and Admins who invite people and give them roles, and for anyone who wants to know what
their role allows. It covers the four roles and the Instance Admin, who may grant which role,
invitations, changing and removing members, and how roles limit API tokens.

## The roles

| What the role may do | Permission | Owner | Admin | Operator | Viewer |
|---|---|:-:|:-:|:-:|:-:|
| See every resource, its status and metrics | `org.read` | ✓ | ✓ | ✓ | ✓ |
| Create and change routes, their targets and access policies | `routes.write` | ✓ | ✓ | ✓ | |
| Enroll, change, switch off and decommission connectors; revoke enrollment tokens | `connectors.write` | ✓ | ✓ | If the organisation allows it | |
| Manage gateway groups, gateways, port pools and quotas, domains, certificates and CA bundles | `infrastructure.write` | ✓ | ✓ | | |
| Invite members, change their roles, remove them | `members.write` | ✓ | ✓ | | |
| Read the audit log | `audit.read` | ✓ | ✓ | | |
| Rename the organisation, require a second factor, change the organisation's settings | `org.write` | ✓ | | | |

- **Operators and connectors:** the Operator role gets `connectors.write` when the Owner turns on
  **Operators may enroll and revoke connectors** in the organisation's settings
  ([Settings](../web-ui/settings.md#organisation-settings)).
- **Decommissioning reaches routes:** decommissioning a connector deletes each route left without
  a target, so whoever may decommission connectors can remove those routes too
  ([04](../../04-security.md#roles)).
- **Every member sees every page.** A change your role does not allow fails with an error that
  names the missing permission, such as `the permission routes.write is missing`.

The full table, with the permissions of later phases, is in the design documents
([04](../../04-security.md#roles)).

### The Instance Admin

The Instance Admin is a role of the whole installation, beside the organisation's roles: it
manages the CA, the instance's settings, the PKI and updates pages, the instance's audit log, and
trusted domains. The first user of an installation is the Owner of the first organisation and the
Instance Admin ([The first user](sign-in-and-mfa.md#the-first-user)). In this version the API has
no call that makes another user Instance Admin.

Administrative commands on the controller host, such as `rpmgr backup`, `rpmgr ca` and
`rpmgr user reset-password`, need no role at all: they are allowed to whoever may run them as root
or as the rpmgr service user there, and are audited ([04](../../04-security.md#roles)).

## Who may grant which role

- **Owner** is made, changed and removed only by an Owner. An organisation always keeps at least
  one Owner.
- **Admin, Operator and Viewer** are granted by Owners and Admins. An Admin cannot change or remove
  an Owner.
- **Granting Admin or Owner**, by a role change or an invitation, needs a step-up
  ([D66](../../14-open-decisions.md#security-defaults);
  [Step-up](sign-in-and-mfa.md#step-up-confirming-it-is-you)).

## Invite someone

An invitation is a one-time link for one e-mail address and one role.

### Before you start

- You are an Owner or Admin of the organisation.
- To e-mail the link, the controller needs a mail relay
  ([Settings](../web-ui/settings.md#instance-settings)); without one you pass the link on yourself.

### With the web UI

1. Open **Organisation** in the sidebar.
2. Under **Invite someone**, enter the **E-mail address**, choose the **Role** and press **Make
   the invitation**. For Admin or Owner, confirm your identity when asked.
3. The card shows the **Invitation link** and until when it works, and says whether the controller
   e-mailed it. If not, copy the link with **Copy** and send it yourself.

### With the command line

```sh
rpmgr create invitation --email grace@example.com --role admin
```

It prints the one-time link; when the invited role is Admin or Owner, it asks for a step-up first.
The token you logged in with needs the `members.write` scope
([API tokens and the command line](api-tokens-and-cli.md)).

### What happens next

The person opens the link, which shows **Join an organisation**
([Public pages](../web-ui/public-pages.md#accept-an-invitation)):

- **A new address:** they enter their name and a password and press **Join**; the account is
  created, and they sign in with the invited address.
- **An address with an account:** they sign in first, open the link again and press **Join**.

The link works once and expires ([04](../../04-security.md#roles)); make a new invitation if it
did. The web UI does not list open invitations.

## Change a member's role

- **With the web UI:** **Organisation**, **Members**: choose the new role in the member's
  **Role** list. It takes effect at once; for Admin or Owner, confirm your identity when asked.
- **With the command line:**

  ```sh
  rpmgr update member --role operator alan@example.com
  ```

  The member is named by e-mail address or user ID.

A lower role applies from the member's next request, to their sessions and their API tokens alike.

## Remove a member

- **With the web UI:** **Organisation**, **Members**, **Remove…** in the member's row, then
  **Remove it**.
- **With the command line:**

  ```sh
  rpmgr remove member margaret@example.com
  ```

The membership ends at once; the user's API tokens lose their access to the organisation. The
account itself stays, with its other memberships. `rpmgr list member` lists the members with their
roles.

## Roles and API tokens

A personal API token can do only what its scopes allow, and never more than its owner's role
allows now: the controller checks both on every request. Lowering a member's role therefore limits
their tokens at once, and removing a member makes their tokens useless in the organisation
([API tokens and the command line](api-tokens-and-cli.md)).

## After a restore

A restore that cannot prove that every revocation since the backup was applied again puts each
organisation into a restore review: it stays read-only until its Owner checks its members and
roles and confirms them on the **Organisation** page, or until the Instance Admin confirms it on
the controller host. Suspended API tokens are resumed one by one
([Organisation](../web-ui/organisation.md#restore-review);
[Backup and restore](../operations/backup-and-restore.md)).

## Several organisations

In this version an installation has one organisation, which initialisation creates as "Default";
rename it on the **Organisation** page. More organisations, and switching between them in the web
UI, come with Phase 2 ([05](../../05-features.md#identity-and-access)).
