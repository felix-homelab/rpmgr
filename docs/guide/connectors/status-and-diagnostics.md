# Status and diagnostics

Every gateway and connector can tell you on its own host what it is, whether it runs, and whether
it reaches the controller and its gateways. This page is for whoever runs agent hosts: it covers
`rpmgr status`, `rpmgr diag transport`, `rpmgr diag clock` and `rpmgr leave`, and what the web UI
and the API show about an agent.

## Before you start

- The commands run on the agent's host and read its files, not the API: no login is needed.
- Run them with `sudo`, or as the service user `rpmgr`: the identity's key is readable by that
  user only.
- They read the connector's boot file, else the gateway's: `--config <file>`, else
  `$RPMGR_CONFIG`, else `/etc/rpmgr/connector.yaml`, else `/etc/rpmgr/gateway.yaml`. A boot file
  that would do for both roles counts as the role its identity records
  ([Boot files](../reference/boot-files.md)).
- On an all-in-one host they do not apply: its gateway and connector are part of the controller's
  process. Use the web UI and the admin listener there ([Monitoring](../operations/monitoring.md)).

## rpmgr status

`rpmgr status` shows the agent on this host, from its identity and stored state, and asks the
running service whether it is ready:

```sh
sudo rpmgr status
```

```text
Role:           connector (boot file /etc/rpmgr/connector.yaml)
Agent:          con_01M4ZEK2EXFBJRKFW4JB7DQVZ6  spiffe://rpmgr-ewl35s75/org/org_01M4ZEHHDQE4HAJFN45X0ZD08D/connector/con_01M4ZEK2EXFBJRKFW4JB7DQVZ6
Trust domain:   rpmgr-ewl35s75
Enrolled:       2026-10-12T09:34:15Z
Certificate:    expires 2026-10-17T21:34:15Z, valid for 58h0m0s
Controller:     https://panel.example.com
Configuration:  revision 42 of epoch 01a13ee8-581f-74c2-a713-5a06c75d4532, 3 resources
Deny-list:      0 entries
Service:        running and ready
```

| Line | What it says |
|---|---|
| Role | Connector or gateway, and the boot file the command read |
| Agent | The agent's ID and its identity, as its certificate names it |
| Trust domain | The installation it belongs to |
| Enrolled | When it enrolled, or last re-enrolled |
| Certificate | When its certificate expires. The agent renews it on its own, long before ([04](../../04-security.md#leaf-certificates)). `expired; the agent re-authenticates within the grace period, else re-enroll` means it was offline too long |
| Controller | The controller endpoints it tries, in order |
| Configuration | The last configuration it applied and keeps on disk, so that it can restart while the controller is unreachable: its revision and number of resources. `none received yet` before the first; `the stored copy does not verify: …` if the copy is damaged, and then the agent does not run it |
| Deny-list | How many revoked certificates and identities it refuses |
| Service | The answer of the running service's admin listener: `running and ready`; `running, not ready:` and the reason, such as `no control session` or `no snapshot applied`; `not running (nothing answers on 127.0.0.1:7383)`; or `unknown: the admin listener is off` |

Without an identity, it says `no identity in /var/lib/rpmgr/identity (run rpmgr enroll)`
([Enrolling connectors](enroll.md)).

## rpmgr diag transport

`rpmgr diag transport` tests the data-session transports from a connector's host. For each tunnel
endpoint of the connector's gateways, or of the one gateway `--gateway <ID>` names, it opens a QUIC
session and a TCP session, closes them, and reports the result:

```sh
sudo rpmgr diag transport
```

```text
GATEWAY                        ENDPOINT             TRANSPORT  RESULT  HANDSHAKE  RTT
gw_01M4ZEJPH7EHCT1XTFPV3MFHPH  gw1.example.com:443  quic       ok      41ms       18ms
gw_01M4ZEJPH7EHCT1XTFPV3MFHPH  gw1.example.com:443  h2         ok      58ms       -

UDP socket: receive buffer 7340032 bytes, send buffer 7340032 bytes, GSO on.
MTU towards the gateway: 1500 on eth0.
```

- **RESULT** is `ok`, or `failed:` and the error. A QUIC failure while `h2` works means UDP is
  blocked on the way, in one direction or both; a failure of both points at the address, a
  firewall for TCP as well, or a proxy ([Connector networking](network.md)).
- **HANDSHAKE** is the time until the session was up; **RTT** QUIC's round-trip time after it.
- **UDP socket** shows the buffers of the UDP socket QUIC uses, and whether the kernel splits large
  sends for it (GSO). Below what QUIC asks for, it adds: `The UDP buffers are below what QUIC asks
  for: apply the installer's /etc/sysctl.d/60-rpmgr.conf.`
- **MTU** is that of the interface towards the first endpoint; it bounds QUIC's packet size.

The sessions are its own: a running connector is not disturbed. The command needs the connector's
stored configuration, which names the gateways, so start the connector once first. It runs on
connector hosts only; on a gateway's it says so. The runbook for UDP problems is
[UDP blocked or degraded](../../10-operations.md#udp-blocked-or-degraded).

## rpmgr diag clock

`rpmgr diag clock` compares this host's clock with the controller's, over a control session it
opens for the measurement:

```sh
sudo rpmgr diag clock
```

```text
Controller https://panel.example.com: its clock is 312ms ahead of this host's (round trip 18ms), within the <maximum> agents accept.
A running agent's control session reconnects once after the measurement.
```

The maximum skew an agent accepts is in [03](../../03-connections.md#failure-modes); above it, the
verdict reads `more than the <maximum> agents accept: fix NTP on this host or the controller's`.
Run time synchronisation (NTP or chrony) on every host. If no controller answers, the command says
so, and a TLS error about an expired or not yet valid certificate means this host's clock is far
off ([Troubleshooting](../operations/troubleshooting.md#clocks-and-certificates)).

The controller keeps one control session per agent, so the measurement replaces the running
agent's session, which then reconnects on its own.

## rpmgr leave

`rpmgr leave` takes the agent on this host out of service for good:

```sh
sudo rpmgr leave
```

```text
The controller revoked spiffe://rpmgr-ewl35s75/org/org_01M4ZEHHDQE4HAJFN45X0ZD08D/connector/con_01M4ZEK2EXFBJRKFW4JB7DQVZ6. Its identity and stored configuration are removed from this host.
Stop and disable rpmgr-connector.service; /etc/rpmgr/connector.yaml can go too unless the host enrolls again.
```

1. It asks the controller to revoke the agent's identity, trying each controller endpoint. The
   controller decommissions the connector or gateway as an Admin's decommission does, and records
   it in the audit log with the agent as the actor
   ([Connector lifecycle](lifecycle.md#decommission-a-connector)).
2. Only when a controller confirmed does it remove the identity, the stored configuration and the
   deny-list from the host. If none confirms, because the controller is unreachable or the
   identity is revoked already, nothing is removed and the command fails.
3. The running service notices the revocation and stops: `agent: the controller revoked this
   agent; enroll it again`. Stop and disable its unit:

   ```sh
   sudo systemctl disable --now rpmgr-connector.service
   ```

For a connector, the routes it alone served are deleted with it, as in a decommission. To use the
host again, enroll it anew with a new token; it becomes a new connector.

## In the web UI

A connector's page, under **Connectors**, shows what the controller knows of it:

- **Sessions**: `Control session up from <address>, last seen <time>.` or `No control session;
  last seen <time>.`, then one row per data session, as its gateways report them: **Gateway**,
  **Transport** (**QUIC** or **TLS and HTTP/2**), **Round trip** (QUIC sessions only) and **Since**.
- **Routes**: the routes it has targets of, and for each route it reports not ready, the reason,
  such as **blocked by the connector's local policy**, with the command that allows the target on
  the host ([Troubleshooting](../operations/troubleshooting.md#a-route-is-not-ready)).

The Connectors list shows each connector's session as **connected**, **offline** or **disabled**,
its version and when it was last seen. A gateway group's page shows the same for its gateways, and
**not enrolled** for a gateway that has not enrolled yet ([Gateways](../gateways.md)).

## With the command line and the API

```sh
rpmgr list connector
```

```text
ID                              NAME  ENABLED  CONNECTED  VERSION
con_01M4ZEK2EXFBJRKFW4JB7DQVZ6  nas   true     true       0.1.0
```

`rpmgr get -o json connector nas` adds the control session's address and last contact. The API's
`ConnectorService.GetConnectorStatus` returns all of it: the control session, the data sessions
with their transport and round trip, and the routes the connector reports not ready, with reason,
detail and since when ([API](../reference/api.md)).
