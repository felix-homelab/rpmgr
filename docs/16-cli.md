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
| `rpmgr controller init [--config <file>] [--public-url <url>] [--kek-source <source>] [--kek-path <file>]` | Initialise a controller: boot file, KEK, database, trust domain and CA; prints the trust domain, the CA pin and the one-time link that creates the first user ([10](10-operations.md#install)) | controller host | available |
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
| `rpmgr create port-pool --group <group> --protocol tcp\|udp --from <port> --to <port>`, `update port-pool [--force] [--from] [--to] <id>` | Create a pool of public ports of a group, or resize it | any | available |
| `rpmgr revoke enrollment-token <id>` | Revoke an enrollment token, so that it enrolls nothing more | any | available |
| `rpmgr leave` | Revoke this agent's identity and remove it from the host | agent host | not yet |
| `rpmgr status` | Show the state of the agent on this host | agent host | not yet |
| `rpmgr diag transport`, `diag clock` | Test the data-session transports to a gateway; compare clocks | agent host | not yet |
| `rpmgr policy show [--file <file>]` | Print the effective connector-local policy: the allowed targets and the update keys, or that the file is missing (the defaults apply) or invalid (nothing is allowed) ([04](04-security.md#connector-local-policy)) | connector host | available |
| `rpmgr policy allow-target [--file <file>] [--no-reload] <ip>:<port> \| <socket path>`, `… remove-target …` | Allow, or stop allowing, one target in the policy file (default `/etc/rpmgr/policy.yaml`), keeping its comments and other keys; a missing file is created with the update keys written explicitly. Then `systemctl reload rpmgr-connector.service`, unless `--no-reload`; the connector also notices the change within 2 s. A port that only a port range allows is not split | connector host, as root | available |
| `rpmgr backup`, `restore`, `restore confirm` | Back up or restore the controller; end the restore review ([10](10-operations.md#backup-and-restore)) | controller host | not yet |
| `rpmgr migrate` | Apply database migrations | controller host | not yet |
| `rpmgr ca status`, `ca rotate-intermediate` | Administer the internal CA ([04](04-security.md#ca-rotation)) | controller host | not yet |
| `rpmgr kek status`, `kek rotate` | Administer the key-encryption key ([04](04-security.md#secrets-at-rest-and-in-logs)) | controller host | not yet |
| `rpmgr user reset-password [--config <file>] [--email <address>]` | Create a one-time link that sets the password of the user with that address (valid 24 h); before the first user exists, without `--email`, a first-user link (7 days). Reads the controller's or all-in-one's boot file and needs no KEK; audited as `local-cli` ([04](04-security.md#human-authentication-and-sessions)) | controller host | available |
| `rpmgr release import` | Import a signed release for air-gapped installations ([D59](14-open-decisions.md#security-defaults)) | controller host | not yet |
| `rpmgr version` | Print the version, commit, Go version and platform of this binary | any | available |

The role commands read their boot file from `--config`, else from `$RPMGR_CONFIG`, else from
`/etc/rpmgr/<role>.yaml` ([10](10-operations.md#boot-files)). Administration commands on the
controller host are authorised by host access and audited as `local-cli`
([04](04-security.md#roles)).
