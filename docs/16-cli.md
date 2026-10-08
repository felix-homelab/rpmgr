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
