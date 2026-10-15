# Troubleshooting

This page goes from what you see to its cause and the fix. It is for everyone who runs or uses
rpmgr: start with the symptom, follow the table, and use the runbooks of the design documents for
the larger operations ([10](../../10-operations.md#runbooks)).

## Where to look first

| Where | What it tells |
|---|---|
| **Overview**, **Needs attention** | Agents without a control session, routes that do not serve fully or were rejected, certificates that failed or expire soon, unverified domains |
| A route's page | Its state, each target's and gateway's reason for not serving, and the agents that rejected it ([Preview and apply](../routes/preview-and-apply.md#route-states)) |
| A connector's page | Its control session, its data sessions, and the routes it reports not ready, with the command that fixes a local policy block ([Status and diagnostics](../connectors/status-and-diagnostics.md#in-the-web-ui)) |
| `sudo rpmgr status` on an agent host | Identity, certificate, stored configuration, and whether the service is ready |
| `sudo journalctl -u rpmgr-<role>.service` | The role's log ([Monitoring](monitoring.md#logs)) |
| `curl http://127.0.0.1:<admin port>/readyz` | Whether the role is ready, and why not ([Monitoring](monitoring.md#health-checks)) |
| **Audit log** | Who changed what, and which requests were refused ([Audit log](audit-log.md)) |

## A route is not ready

A route's state comes from what its gateways and connectors report
([Preview and apply](../routes/preview-and-apply.md#route-states)):

| State | Cause | Fix |
|---|---|---|
| **pending** | An online agent has not applied the latest change yet | Wait a moment; if it stays, see [A change is rejected or not applied](#a-change-is-rejected-or-not-applied) |
| **error** | An agent rejected the configuration with the latest change; **Rejected by** names it and its reasons | See [A change is rejected or not applied](#a-change-is-rejected-or-not-applied) |
| **unavailable** | No target is ready, or no gateway serves it | Read each target's and gateway's reason, below |
| **degraded** | It serves, but not every target is ready or not every gateway serves it | Read the reasons, below |
| **maintenance** | The route is in maintenance and shows the maintenance page | Switch **Maintenance** off ([Maintenance and error pages](../routes/maintenance-and-pages.md)) |
| **disabled** | The route is switched off | Switch **Enabled** on, or `rpmgr enable route <route>` |

The route's page gives, for each target that is not ready and each gateway that does not serve, one
of these reasons:

| Reason in the web UI | Cause | Fix |
|---|---|---|
| **offline** | The target's connector, or the gateway, has no control session | See [An agent is offline](#an-agent-is-offline) |
| **disabled** | The target, or its connector, is switched off, or the gateway is drained | Switch it on, or **Resume** the gateway ([Connector lifecycle](../connectors/lifecycle.md), [Gateways](../gateways.md#drain-and-resume-a-gateway)) |
| **no data session to the connector** | The gateway has no data session to the connector of a ready target | The connector cannot reach that gateway's tunnel endpoints: run `sudo rpmgr diag transport` on its host, and check firewalls and proxies ([Connector networking](../connectors/network.md)) |
| **blocked by the connector's local policy** | The connector's local policy does not allow the target's address, or a deny entry refuses it | Run the command the page shows on the connector's host, such as `sudo rpmgr policy allow-target 192.168.1.20:8080`, or `remove-deny-target` for a deny entry ([The local policy](../connectors/local-policy.md)) |
| **… is one of rpmgr's own ports** | On an all-in-one, the target is the host's own port 443, 80, admin port or a route's port, which the built-in connector never dials | Point the target at the service itself, such as its own port |
| **the connector's local policy does not load** | `/etc/rpmgr/policy.yaml` is invalid, so the connector allows nothing | `sudo rpmgr policy show` names the error; fix the file ([Local policy file](../reference/policy-file.md)) |
| **the port is in use on the gateway** | Another process on the gateway host holds the route's port | Find it with `sudo ss -ltnup 'sport = :<port>'` and stop it, or give the route another port. The gateway tries the port again on its own ([03](../../03-connections.md#timeouts-keepalive-and-backoff)) |
| **no data session over the route's transport** | The route, or its connector, is pinned to a transport that cannot be established, such as `quic` where UDP is blocked | Set the transport to `auto`, or to the one that works ([Connector networking](../connectors/network.md#choose-a-transport)) |
| **the host cannot serve it** | Something on the host failed, such as fetching a certificate; the detail says what | The agent retries on its own; read the detail and the agent's log |

A target that is ready but refuses connections, because its service is down, does not make the
route unready: the gateway tries the route's other targets, and visitors of an HTTP route get the
**Service unavailable** page when none answers
([Maintenance and error pages](../routes/maintenance-and-pages.md)).

## A change is rejected or not applied

| Symptom | Cause | Fix |
|---|---|---|
| Apply status **rejected**; route state **error** | An agent refused the whole configuration: it did not validate there. This is a version mismatch or a fault, never a host setting. The agent keeps running its last good configuration, so nothing broke | Read the reasons under **Rejected by**. Check that the agent runs a version the controller supports, and upgrade it ([Upgrades](../install/upgrades.md)); otherwise report the reasons as a bug |
| Apply status **an agent did not answer in time** | The agent neither applied nor rejected the configuration in time ([03](../../03-connections.md#timeouts-keepalive-and-backoff)) | Look at the agent's log; restart its service if it hangs |
| Apply status stays **pending** for one agent | That agent has a session but has not answered yet | As above |
| An agent is listed as offline in the apply status | It has no control session; it gets the change when it connects | See [An agent is offline](#an-agent-is-offline) |

The metric `rpmgr_agent_apply_status` shows each agent's state for alerts
([Monitoring](monitoring.md#metrics)).

## An agent is offline

The Overview lists it under **Needs attention** with when it was **last seen**, or **never
connected**; a gateway that was created but not enrolled shows **not enrolled yet**. On its host:

1. `sudo systemctl status rpmgr-<role>.service`: does it run?
2. `sudo rpmgr status`: the **Service** line, and the certificate.
3. `sudo journalctl -u rpmgr-<role>.service -n 50`: the last lines.

| What you find | Cause | Fix |
|---|---|---|
| `agent: the controller revoked this agent; enroll it again` | The agent was decommissioned, or left | Enroll the host again as a new agent ([Enrolling connectors](../connectors/enroll.md)) |
| `no identity in … (run rpmgr enroll)` | The host has no identity, or it was removed | Enroll it, or re-enroll it to keep its ID ([Re-enroll a connector](../connectors/enroll.md#re-enroll-a-connector)) |
| `control session ended` with a connection error | The controller is unreachable from here | Check DNS, the firewall, the proxy and the controller's `/readyz`; see the runbook [Controller down](../../10-operations.md#controller-down). A connector carries its control session through a data session if it can reach a gateway ([Connector networking](../connectors/network.md#when-the-controller-is-out-of-reach)) |
| `controller said goodbye` with `GOODBYE_REASON_UPGRADE_REQUIRED` | The agent is older than the controller accepts | Upgrade the agent ([Upgrades](../install/upgrades.md)) |
| A TLS error about an expired certificate | The certificate expired while the agent was offline, longer ago than the grace period, or the clock is off | See [Clocks and certificates](#clocks-and-certificates) |
| The connector runs but routes are not ready | Its control session is fine, but something else is not | See [A route is not ready](#a-route-is-not-ready) |

A controller that is down does not stop traffic: agents keep running their last configuration, and
reconnect when it is back ([03](../../03-connections.md#failure-modes)).

## Enrollment fails

| Message or symptom | Cause | Fix |
|---|---|---|
| `invalid token` | The token is mistyped, used up, expired or revoked | Make a new token |
| `pki: no root in the bundle matches the pin` | The `--ca-pin` belongs to another installation | Copy the pin again ([PKI](pki.md#the-ca-pin)) |
| `download the trust bundle: … certificate signed by unknown authority` | The host does not trust the controller's web certificate, such as a self-signed one | Give the controller a trusted certificate ([Domains and certificates](../domains-and-certificates.md)), or pass `--trust-bundle` to `rpmgr enroll` |
| `this host is enrolled already; use --replace to enroll it again` | The host has an identity | Re-enroll it, or `sudo rpmgr leave` first |
| `too many enrollments from this address` | The controller limits enrollments per address ([04](../../04-security.md#human-authentication-and-sessions)) | Wait, then try again |
| `the gateway or connector is decommissioned` | A re-enrollment token for a decommissioned agent | Enroll the host as a new agent |
| `only an ephemeral connector token with a set lifetime may enroll more than one connector` | A token with several uses that is not ephemeral | Use `--ephemeral`, or one-time tokens |
| The install script waits at the token prompt and takes nothing you type | The script was piped into `sudo sh`, and this `sudo` passes no terminal input to it | Stop it with Ctrl-C, and run the install command as the web UI shows it: download, then `sudo sh install.sh …` ([Install script](../install/install-script.md)) |
| `no enrollment token: use --token-file or RPMGR_ENROLL_TOKEN, or run on a terminal` | No terminal and no token given | Pass `--token-file`, or `sudo --preserve-env=RPMGR_ENROLL_TOKEN` |

A failed enrollment is in the instance's audit log as `agent.enroll` with its reason, for the
Instance Admin ([Audit log](audit-log.md)). More on tokens is in
[Enrolling connectors](../connectors/enroll.md#troubleshooting).

## Clocks and certificates

| Symptom | Cause | Fix |
|---|---|---|
| `clock skew to the controller; TLS and certificate checks may fail` in an agent's log | The host's clock differs from the controller's by more than agents accept ([03](../../03-connections.md#failure-modes)) | `sudo rpmgr diag clock` measures it; run NTP or chrony on every host ([Certificate expiry or clock skew](../../10-operations.md#certificate-expiry-or-clock-skew)) |
| TLS errors with "expired" or "not yet valid" on fresh certificates | The clock is far off | As above |
| `rpmgr status` says the certificate `expired` | The agent was offline past its certificate's expiry | It renews within the grace period on its own once it connects; after that, re-enroll ([PKI](pki.md#agent-certificates-and-passwords)) |
| An HTTPS route's certificate is **failed** under **Domains & certificates** | The ACME CA could not validate the name: DNS does not point at the gateways, or ports 80 and 443 are not reachable from the internet | Fix DNS or the firewall, then **Renew now** or `rpmgr renew certificate <id>` ([Domains and certificates](../domains-and-certificates.md#what-can-block-an-acme-certificate); [A route certificate is not obtained](../../10-operations.md#a-route-certificate-is-not-obtained)) |
| A browser warns about the controller's certificate | The controller serves a self-signed certificate: its public URL is not a public name, or ACME has not succeeded yet | Use a public name for ACME, or give it a certificate from files ([Domains and certificates](../domains-and-certificates.md)) |

## QUIC, UDP and proxies

| Symptom | Cause | Fix |
|---|---|---|
| A connector on `auto` uses **TLS and HTTP/2** instead of **QUIC** | UDP to the gateway is blocked or lossy | Allow UDP 443 to the gateways' tunnel endpoints, both ways; `sudo rpmgr diag transport` shows the QUIC handshake ([UDP blocked or degraded](../../10-operations.md#udp-blocked-or-degraded)) |
| A UDP route's target shows **served over TLS and HTTP/2, the fallback for QUIC** | As above; UDP then travels in a TCP stream, where loss delays every flow | As above, or accept it |
| `The UDP buffers are below what QUIC asks for` | The host's UDP buffers were not raised | Apply `/etc/sysctl.d/60-rpmgr.conf` as the installer writes it ([Connector networking](../connectors/network.md#check-the-network)) |
| The connector does not start: `HTTPS_PROXY is not an http://, socks5:// or socks5h:// URL with a host` | The proxy variable holds something the connector cannot use | Fix the variable in the service's drop-in ([Environment variables](../reference/environment.md#proxies)) |
| Sessions fail behind a proxy that inspects TLS | The proxy replaces rpmgr's certificates | Exempt the gateways and the controller from inspection ([Connector networking](../connectors/network.md#proxies)) |

## The API or the command line refuses

| Message | Cause | Fix |
|---|---|---|
| `the change needs a step-up, which needs a terminal` | A change needs a step-up, and the command runs without a terminal | Run it once on a terminal and answer the prompt; the token then stays stepped up for a while ([04](../../04-security.md#human-authentication-and-sessions)). A script can call `AuthService.StepUp` ([API](../reference/api.md#step-up-for-sensitive-methods)) |
| `permission denied: … the permission … is missing (PERMISSION_MISSING)` | Your role, or the token's scopes, lack the permission | Make a token with that scope, or ask an Owner for the role ([Members and roles](../accounts/members-and-roles.md)) |
| `permission denied: api: the org requires signing in with a second factor (MFA_REQUIRED)` | The organisation requires a second factor, and you signed in without one, or the token was made from such a session | Set up an authenticator, sign in with it, and make a new token ([Sign-in and two-factor authentication](../accounts/sign-in-and-mfa.md)) |
| `not found` for something you can see in the web UI | The command is logged in to another organisation, or the ID is wrong | `rpmgr login` again with the right `--org` ([API tokens and the command line](../accounts/api-tokens-and-cli.md)) |
| `the resource changed since it was read` (`ETAG_MISMATCH`) | Someone changed it between your read and your write | Run the command again; `--force` overwrites without the check |
| `read-only until the restore review is confirmed` (`RESTORE_REVIEW`) | The controller was restored and could not prove every revocation since the backup | The organisation's Owner confirms its members and roles ([Backup and restore](backup-and-restore.md)) |
| `expected 1 arguments, got 2`, with the usage | A flag came after a positional argument | Put flags first: `rpmgr list --all connector` ([Command-line reference](../reference/cli.md)) |
| HTTP 415 `api: unsupported content type`, or 403 for a cross-origin request | A script sent a form content type, or a foreign `Origin` | Send `Content-Type: application/json` and no `Origin` ([API](../reference/api.md#browser-sessions)) |

Every error code and reason of the API is listed in [API](../reference/api.md#errors).

## Visitors see an error page

| Page | Cause | Fix |
|---|---|---|
| **Site not available** (404) | No route serves the name or path, or the route is disabled | Check the route's hostnames, path prefix and **Enabled** switch ([HTTP routes](../routes/http.md)) |
| **Service unavailable** (503, 502 or 504) | No target is ready, or the targets refused, reset or did not answer | Check the route's state and the service ([A route is not ready](#a-route-is-not-ready)) |
| **Down for maintenance** (503) | The route is in maintenance | Switch maintenance off when the work is done ([Maintenance and error pages](../routes/maintenance-and-pages.md)) |
| A certificate warning for a route's name | The name has no valid certificate yet | See [Clocks and certificates](#clocks-and-certificates) |

## Runbooks

The design documents hold step-by-step runbooks for larger operations
([10](../../10-operations.md#runbooks)): [Controller down](../../10-operations.md#controller-down),
[Replace a gateway](../../10-operations.md#replace-a-gateway),
[Re-enroll a connector](../../10-operations.md#re-enroll-a-connector),
[Revoke a compromised connector](../../10-operations.md#revoke-a-compromised-connector),
[Rotate the issuing intermediate](../../10-operations.md#rotate-the-issuing-intermediate),
[Root compromise](../../10-operations.md#root-compromise),
[Rotate the KEK](../../10-operations.md#rotate-the-kek),
[Restore from backup](../../10-operations.md#restore-from-backup),
[Certificate expiry or clock skew](../../10-operations.md#certificate-expiry-or-clock-skew),
[A route certificate is not obtained](../../10-operations.md#a-route-certificate-is-not-obtained),
[Many hostnames under one domain](../../10-operations.md#many-hostnames-under-one-domain) and
[UDP blocked or degraded](../../10-operations.md#udp-blocked-or-degraded).
