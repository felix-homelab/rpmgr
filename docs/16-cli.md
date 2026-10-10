# 16 — Command line

> Status: Phase 1, being implemented. Tags: [F] fact · [R] recommendation · [T] target · [V] verify
> at implementation ([README](../README.md#how-to-read-these-documents)).
>
> This document lists every `rpmgr` command, its flags and its exit codes. It is written from the
> commands' `--help` output and changes in the same PR as the command. Configuration keys are in
> [10](10-operations.md#configuration); the API behind the resource commands is in [07](07-api.md).

## Conventions

- One binary, `rpmgr`, for every role and every administration task
  ([ADR-0002](adr/0002-one-binary-three-roles.md)). Commands form a tree:
  `rpmgr <command> [<sub-command>] [flags] [arguments]`.
- Flags come before positional arguments. `-h` or `--help` prints the help of any command;
  `rpmgr help <command> …` does the same.
- No secret is ever accepted as a command-line argument: tokens and passwords come from a file, an
  explicitly passed environment variable or a terminal prompt
  ([04](04-security.md#secrets-at-rest-and-in-logs)).
- Commands of the public API put the verb first, `rpmgr <verb> <kind>` (`get`, `list`, `create`,
  `update`, `delete`, …), so they never collide with the role commands or with the host's
  `rpmgr policy` ([D51](14-open-decisions.md#engineering)). They arrive with the resource API.
- A change that needs a step-up ([04](04-security.md#human-authentication-and-sessions)) asks for it
  on the terminal when the API answers `STEP_UP_REQUIRED`: the authenticator or a recovery code, or
  the password of a user without a second factor. The stored token then steps up for 10 minutes
  ([D63](14-open-decisions.md#engineering)) and the change runs again.

| Exit code | Meaning |
|---|---|
| 0 | Success, or help was requested |
| 1 | The command ran and failed |
| 2 | Invalid command line (unknown command or flag, missing or unexpected argument), or the command is not available in this build |

## Commands

A command marked *not yet* exists in the command tree and prints "not available in this build"
with exit code 2 until its implementation lands.

| Command | What it does | Runs on | State |
|---|---|---|---|
| `rpmgr controller [--config <file>]` | Run the controller: web UI, API, CA and configuration, until `SIGINT` or `SIGTERM`, then drain the agents' control sessions ([10](10-operations.md#boot-files)). The web UI and the API follow in later versions | controller host | available |
| `rpmgr controller init [--config <file>] [--public-url <url>] [--kek-source <source>] [--kek-path <file>]` | Initialise a controller: boot file, KEK, database, trust domain and CA; without `--kek-source`, a new boot file takes the systemd credential from systemd 250 and a KEK file below it; prints the trust domain, the CA pin and the one-time link that creates the first user ([10](10-operations.md#install)) | controller host | available |
| `rpmgr gateway [--config <file>]` | Run a gateway until `SIGINT` or `SIGTERM`, then drain: no new public connections or data sessions, open streams kept for the gateway drain period ([03](03-connections.md#multiple-gateways)) | gateway host | available |
| `rpmgr connector [--config <file>]` | Run a connector until `SIGINT` or `SIGTERM`; `SIGHUP` reloads the local policy | connector host | available |
| `rpmgr all-in-one [--config <file>]` | Run a controller and a gateway in one process until `SIGINT` or `SIGTERM`; the gateway drains first ([02](02-architecture.md#all-in-one-homelab-default)) | controller host | available |
| `rpmgr all-in-one init [--config <file>] [--public-url <url>] [--kek-source <source>] [--kek-path <file>]` | Initialise an all-in-one installation as `rpmgr controller init` does, then create the gateway group `default` with the gateway `local` and enroll it through the in-process controller | controller host | available |
| `rpmgr enroll --controller <url> --ca-pin <pin> [--token-file <file>] [--replace] [--identity-dir <dir>] [--trust-bundle <file>]` | Enroll this host as an agent with a single-use token, read from `--token-file`, else `$RPMGR_ENROLL_TOKEN`, else the terminal; never from the command line ([04](04-security.md#join-command)). `--trust-bundle` replaces the download, for a controller whose web certificate the system does not trust | agent host | available |
| `rpmgr login --controller <url> --org <org ID> [--token-file <file>] [--ca-file <file>]` | Check a personal API token of the org against the controller and store it, with the controller, the org and the CA file, for the commands of the public API. The token comes from `--token-file`, else `$RPMGR_TOKEN`, else the terminal, and needs the `org.read` scope. `--ca-file` verifies the controller instead of the system's roots. The credentials go to `rpmgr/credentials.yaml` in the user's configuration directory, or `$RPMGR_CREDENTIALS`, readable by the user only; a credentials file other users can read is refused | any | available |
| `rpmgr logout` | Remove the stored credentials. The token stays valid until it expires or is revoked in the web UI | any | available |
| `rpmgr get [-o table\|yaml\|json] <kind> <id>` | Show a resource of the logged-in org. `table` shows its ID, name and a few fields of its kind; `yaml` the manifest the controller exports ([07](07-api.md#declarative-manifests)), or for a certificate the resource itself; `json` the resource in the protobuf JSON mapping. The kinds are `route`, `connector`, `gateway`, `gateway-group`, `port-pool`, `domain`, `certificate`, `ca-bundle`, `route-target` and `access-policy`. `rpmgr get [--role connector\|gateway] [--allow-target <target>]… install-command` prints the command that installs an agent of the org, without its token | any | available |
| `rpmgr list [--all] [-o table\|yaml\|json] <kind>` | List the resources of a kind in the logged-in org, every page of them, in the same outputs; a route's targets are shown with the route. `--all` adds decommissioned agents and used-up, expired and revoked enrollment tokens (`enrollment-token`, which is only listed) | any | available |
| `rpmgr delete [--force] [--wait <duration>] <kind> <id>` | Delete a route, route target, gateway group, port pool, domain, certificate, CA bundle or access policy. It reads the resource first and sends its etag, so a change since then is refused and the resource is shown as it is now; `--force` sends none. `--wait` waits up to that long, at most 30 s, for the agents to apply the change, and the answer says how far they are | any | available |
| `rpmgr create route --name <name> --group <group> --http\|--tcp\|--udp\|--tls-passthrough [flags]` | Create a route of the logged-in org. The group and `--policy` take a name or an ID. http: `--hostname` (repeat), `--path-prefix`, `--tls-mode acme\|certificate`, `--certificate`, `--port80 redirect\|serve\|off`, `--hsts`, `--host-header`, `--set-request-header Name=value`, `--set-response-header`, `--websocket`, `--max-body`; tcp and udp: `--port` (0 picks a free one), `--idle-timeout`; tls-passthrough: `--hostname`. For all: `--description`, `--label key=value`, `--transport auto\|quic\|h2`, `--policy` (repeat, in order), `--disabled`, `--wait`, `-o`. A flag of another route type, and a value the API's rules refuse, are refused before anything is sent | any | available |
| `rpmgr update route [--force] [flags] <id>` | Change the fields of a route that the flags name, and only those, under the etag of the route as this command read it (`--force` sends none). The type and the group do not change | any | available |
| `rpmgr enable route`, `disable route [--force] [--wait <duration>] <id>` | Serve a route again, or stop serving it while keeping its configuration | any | available |
| `rpmgr preview route [--route <id>] [flags]` | Show what `create route`, or with `--route` what `update route`, would do with the same flags, saving nothing: the route as it would be stored, the gateways that would serve it, the connectors it would reach, and the problems the gateways' own checks find | any | available |
| `rpmgr create route-target --route <route> --connector <connector> --address <host:port>\|--unix <path> [flags]` | Add a target to a route; the route, the connector and `--ca-bundle` take a name or an ID. `--upstream tcp\|http\|https\|h2c`, `--server-name`, `--ca-bundle` and `--spki` (https), `--proxy-protocol none\|v1\|v2`, `--weight`, `--priority`, `--disabled`, `--wait`, `-o` | any | available |
| `rpmgr update route-target [--force] [flags] <id>` | Change the fields of a target that the flags name, under its etag; its connector stays | any | available |
| `rpmgr update connector [--force] [--name <name>] [--label key=value]… [--transport auto\|quic\|h2] <id>` | Change a connector's name, labels (they replace the old ones) or transport, under its etag | any | available |
| `rpmgr decommission connector [--force] [--wait <duration>] <id>` | Take a connector out of service for good: its identity is revoked and its sessions closed ([04](04-security.md#revocation)) | any | available |
| `rpmgr create enrollment-token [--ttl <duration>] [--max-uses <n>] [--ephemeral] [--label key=value]… [--connector <connector>] [--gateway-group <group>]` | Make a token that enrolls connectors, with a step-up, and print it once. `--connector` makes a single-use token that re-enrolls that connector with a new key | any | available |
| `rpmgr create gateway-group --name <name> [--region] [--public-hostname]… [--trusted-proxy <cidr>]…`, `update gateway-group [--force] [flags] <id>` | Create a gateway group, or change the fields its flags name | any | available |
| `rpmgr create gateway --group <group> --name <name> --tunnel-endpoint <host:port>…`, `update gateway [--force] [--name] [--tunnel-endpoint]… <id>` | Create a gateway in a group (at most four), or change its name or tunnel endpoints | any | available |
| `rpmgr drain gateway`, `enable gateway [--force] [--wait <duration>] <id>` | Stop a gateway taking new connections while the open ones drain ([03](03-connections.md#multiple-gateways)), or let it take them again | any | available |
| `rpmgr decommission gateway [--force] <id>` | Take a gateway out of service for good: its identity is revoked and its slot is free | any | available |
| `rpmgr create gateway-token --gateway <gateway> [--ttl <duration>]` | Make the token that enrolls that gateway, with a step-up, and print it once | any | available |
| `rpmgr create port-pool --group <group> --protocol tcp\|udp --from <port> --to <port>`, `update port-pool [--force] [--from] [--to] <id>` | Create a pool of public ports of a group, or resize it | any | available |
| `rpmgr set port-quota --group <group> --protocol tcp\|udp --max <n>` | Set how many ports of a group's pools the org may hold; `list port-quota` and `delete port-quota <id>` show and remove them | any | available |
| `rpmgr create domain --fqdn <name> [--wildcard] [--method txt\|http]` | Claim a domain for the org and print how to prove it: the TXT record to add, or the HTTP token the org's gateways serve ([15](15-dns.md)) | any | available |
| `rpmgr verify domain <id>`, `trust domain <id>` | Check a claim's proof now, and say why it is not verified yet; or, for an Instance Admin with a step-up, mark it verified without a proof | any | available |
| `rpmgr upload certificate --chain <file> --key <file>` | Upload a certificate chain, leaf first, and its key for http routes; a key file other users can read is warned about | any | available |
| `rpmgr renew certificate <id>` | Renew an ACME certificate now, or obtain it if it failed; `get certificate` then shows the outcome | any | available |
| `rpmgr create ca-bundle --name <name> --pem-file <file>`, `update ca-bundle [--force] [--name] [--pem-file] <id>` | Create or change a CA bundle that verifies HTTPS upstreams | any | available |
| `rpmgr create access-policy --name <name> [--description <text>] --rule <rule>… [--passwords-file <file>]`, `update access-policy [--force] [--name] [--description] [--rule <rule>…] [--passwords-file <file>] <id>` | Create or change an access policy ([07](07-api.md#services)). Each `--rule` is `allow:<cidr>,…`, `deny:<cidr>,…` or `basic-auth:<user>,…`, applied in the order given; in an update the rules given replace the old ones. A basic-auth password comes from `--passwords-file` (lines `user:password`; a file other users can read is warned about), else from the terminal; in an update an empty answer keeps the password the user has. `--wait`, `-o` | any | available |
| `rpmgr update member --role owner\|admin\|operator\|viewer <member>`, `remove member <member>` | Change a member's role, or end a membership; the member is named by user ID or e-mail address, and `list member` shows them. Granting Admin or Owner takes a step-up, only an Owner makes or changes an Owner, and an org keeps one Owner ([04](04-security.md#roles)) | any | available |
| `rpmgr create invitation --email <address> [--role <role>]` | Make a one-time link that makes its holder a member with the role, `viewer` by default, and print it once, saying whether it was also e-mailed. An invitation as Admin or Owner takes a step-up | any | available |
| `rpmgr revoke token <id>` | Revoke one of your personal API tokens; `list token` shows them. A token is made in the web UI only: only a signed-in session makes one, so that a token never makes another | any | available |
| `rpmgr get [--instance] [-o table\|yaml\|json] settings` | Show the org's settings, or with `--instance` the instance's, for an Instance Admin, by the names `update settings` takes, with the defaults filled in ([10](10-operations.md#runtime-settings-ui--settings)) | any | available |
| `rpmgr update settings [--instance] [--force] --set <setting>=<value>…` | Change settings. A bool is `true` or `false`, a duration `30d` or `12h`, a choice its name such as `quic` or `low-memory`, a list comma-separated; a part of `smtp` is set as `smtp.server=<host:port>`, and an empty value restores the default. `default_gateway_group_id` takes a group's name or ID. Only an Owner changes the org's settings, and changing `require_mfa` takes a step-up. `--wait`, `-o` | any | available |
| `rpmgr set smtp-password [--password-file <file>] [--remove]` | Set the mail relay's password from the first line of the file, else from the terminal, or remove it; for an Instance Admin. A file other users can read is warned about | any | available |
| `rpmgr revoke enrollment-token <id>` | Revoke an enrollment token, so that it enrolls nothing more | any | available |
| `rpmgr leave` | Revoke this agent's identity and remove it from the host | agent host | not yet |
| `rpmgr status` | Show the state of the agent on this host | agent host | not yet |
| `rpmgr diag transport`, `diag clock` | Test the data-session transports to a gateway; compare clocks | agent host | not yet |
| `rpmgr policy show [--file <file>]` | Print the effective connector-local policy: the allowed targets and the update keys, or that the file is missing (the defaults apply) or invalid (nothing is allowed) ([04](04-security.md#connector-local-policy)) | connector host | available |
| `rpmgr policy allow-target [--file <file>] [--no-reload] <ip>:<port> \| <socket path>`, `… remove-target …` | Allow, or stop allowing, one target in the policy file (default `/etc/rpmgr/policy.yaml`), keeping its comments and other keys; a missing file is created with the update keys written explicitly. Then `systemctl reload rpmgr-connector.service`, unless `--no-reload`; the connector also notices the change within 2 s. A port that only a port range allows is not split | connector host, as root | available |
| `rpmgr backup --out <file> [--config <file>]` | Write a consistent backup of the controller while it runs: its database, revocation log and audit checkpoints in one tar archive, mode 0600, never overwriting a file. The KEK is backed up separately ([10](10-operations.md#backup-and-restore)) | controller host | available |
| `rpmgr restore --in <file> [--revocation-log <sink directory or log file>]… [--config <file>]` | Restore the controller with every controller stopped: a new `db_epoch`, sessions and one-time credentials of the backup invalidated, and the revocations since the backup applied again from the sink and the replicas' logs, by default this host's `revocations.log`; when they may be incomplete it fails closed into restore review ([10](10-operations.md#backup-and-restore)) | controller host | available |
| `rpmgr restore confirm [--org <org>] [--config <file>]` | End the instance-wide restore review, or confirm one org's members and roles for it; beside the running controller ([10](10-operations.md#backup-and-restore)) | controller host | available |
| `rpmgr migrate [--config <file>]` | Apply the migrations of this binary to the database, with the controller stopped, after a `VACUUM INTO` copy of it next to it, `<database>.before-migrate-<time>`; a single node also migrates when it starts ([06](06-data-model.md#migrations)) | controller host | available |
| `rpmgr ca status [--config <file>]` | Show the trust domain, the root pin and the CA's keys that have not expired: kind, state, validity and when the schedule rotates them, as Settings → PKI does. Needs no KEK ([04](04-security.md#ca-rotation)) | controller host | available |
| `rpmgr ca rotate-intermediate [--config <file>]` | Make a new issuing intermediate now and retire the old one, which keeps verifying what it issued; running controllers load it within a minute. Needs the KEK ([04](04-security.md#ca-rotation)) | controller host | available |
| `rpmgr kek status [--config <file>]` | Count the stored secrets by the KEK version that wraps them, from `secrets_meta`, and list those under another KEK than the boot file's; it says when the boot file's KEK wraps none of them ([10](10-operations.md#rotate-the-kek)) | controller host | available |
| `rpmgr kek rotate --previous-file <file> [--config <file>]` | With every controller stopped, re-wrap every stored secret under the boot file's KEK, opening it with that KEK or the previous one, in one transaction: a secret that opens with neither changes nothing ([04](04-security.md#secrets-at-rest-and-in-logs)) | controller host | available |
| `rpmgr user reset-password [--config <file>] [--email <address>]` | Create a one-time link that sets the password of the user with that address (valid 24 h); before the first user exists, without `--email`, a first-user link (7 days). Reads the controller's or all-in-one's boot file and needs no KEK; audited as `local-cli` ([04](04-security.md#human-authentication-and-sessions)) | controller host | available |
| `rpmgr systemd-unit [--bin <path>] [--config <file>] <role>` | Print the hardened systemd unit of `controller`, `gateway`, `connector` or `all-in-one` for `/etc/systemd/system/rpmgr-<role>.service`; `--bin` defaults to `/usr/local/bin/rpmgr`. A controller's or all-in-one's unit loads the KEK credential its boot file names ([10](10-operations.md#hardened-systemd-units)) | any Linux host | available |
| `rpmgr release import [--config <file>] <dir>` | Import the signed release of this binary's version from a directory, for air-gapped installations: the files of a GitHub release (`signing-key.json`, `manifest.json`, their `.minisig` files, the Linux artifacts), verified like the daily release check before the controller serves them under `/dl/`. Audited as `local-cli` ([D59](14-open-decisions.md#security-defaults), [04](04-security.md#over-the-air-updates)) | controller host | available |
| `rpmgr version [--verbose]` | Print the version, commit, Go version and platform of this binary; with `--verbose` also the release root keys compiled into it, by minisign key ID and SHA-256 fingerprint, or that it has none ([04](04-security.md#release-signing)) | any | available |

The role commands read their boot file from `--config`, else from `$RPMGR_CONFIG`, else from
`/etc/rpmgr/<role>.yaml` ([10](10-operations.md#boot-files)). Administration commands on the
controller host are authorised by host access and audited as `local-cli`
([04](04-security.md#roles)).
