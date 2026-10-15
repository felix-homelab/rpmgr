# Preview and apply

A saved change is not yet a change on the gateways and connectors: each agent applies it on its
own, and a route's state says what they report. This page is for anyone who changes routes: it
shows how to preview a route before saving it, how to follow a change until every agent has
applied it, what each route state means, and how to export routes as YAML.

## Preview a route

A preview checks a new route, or a change of one, exactly as saving would, and compiles it for the
gateways, but saves nothing. It needs the same role as the change itself: Owner, Admin or Operator.

### With the web UI

The **New route** and the edit form both have **Preview** next to their save button. It shows:

- **Reached at**: the route's hostnames, or its public port at each public hostname of the gateway
  group ([TCP and UDP routes](tcp-and-udp.md#the-address-clients-use)).
- **Gateways that would serve it** and **Connectors its streams would go to**.
- What a gateway would refuse in its configuration with the route, or **No gateway would refuse
  it.**

A change that the save would refuse, such as a hostname outside your verified domains or a port
outside the pools, shows the same error the save would, next to its field.

### With the command line

`rpmgr preview route` takes the flags of `rpmgr create route`, or with `--route` those of
`rpmgr update route`:

```sh
rpmgr preview route --http --name blog --group default --hostname blog.example.com
rpmgr preview route --route wiki --hostname wiki.example.com --hostname docs.example.com
```

It prints the gateways that would serve the route, the connectors it would reach, one line per
problem a gateway would find, and then the route as it would be stored, as a table, or with
`-o json` or `-o yaml` in full.

## Follow a change to the agents

Every change of the configuration gets a **revision**, a number that grows with each change. The
controller sends each gateway and connector the configuration that concerns it, and each agent
reports whether it applied it. A change's **apply status** is one of:

| Apply status | Web UI | Meaning |
|---|---|---|
| `PENDING` | "Revision 42: applied by 1 of 3 agents so far." | An online agent has not applied it yet |
| `APPLIED` | "Revision 42: applied by all 3 agents." | Every online agent runs it, or a later revision |
| `REJECTED` | "Revision 42: rejected." | An online agent refused it; its reasons are listed |
| `APPLY_TIMEOUT` | "Revision 42: an agent did not answer in time." | An online agent did not answer within the acknowledgement period ([03](../../03-connections.md#timeouts-keepalive-and-backoff)) |

Agents without a live control session are not counted. They are listed apart ("Offline, they get
it when they connect: …") and apply the change when they connect again, so an offline agent never
holds a change at `PENDING`.

### In the web UI

After every save, switch or deletion, the page shows the apply status and follows it live until it
is final: each agent that has not applied the change yet, with "pending", "rejected" and its
reasons, or "did not answer in time".

### On the command line

The commands that create, change, enable, disable or delete routes, targets, access policies and
the other resources take `--wait <duration>`, at most 30 s. Such a command then answers once the
change is applied, rejected or timed out, or once the time is up, and says how far the agents got:

```sh
rpmgr update route --hsts 24h --wait 30s wiki
```

```text
Updated route rt_… in revision 42, APPLIED on 3 of 3 online agents.
```

Without `--wait`, the command answers at once, with the status at that moment, usually `PENDING`.
With `-o yaml` or `-o json`, this line goes to standard error and the resource alone to standard
output, for scripts.

### Through the API

A write waits the same way when the request carries the header `Rpmgr-Wait-Applied: <duration>`,
such as `30s`; a value that does not parse means no wait. Every write's response carries its
revision and apply status ([API](../reference/api.md),
[07](../../07-api.md#writes-and-apply-status)).

## Route states

A route's state is derived from what its agents report: the enabled gateways of its gateway group,
and the connectors of its enabled targets. The routes list shows it under **Status**; the route's
page shows it under **Observed**, with how many of the group's gateways serve the route.

| State | Meaning |
|---|---|
| **ready** | Every enabled target is ready, and every enabled gateway of the group serves the route |
| **degraded** | At least one target is ready and one gateway serves the route, but not all |
| **unavailable** | No target is ready, or no gateway serves the route |
| **pending** | An online agent of the route has not applied its latest change yet |
| **error** | An online agent of the route rejected the configuration with its latest change |
| **disabled** | The route is switched off; no gateway serves it |
| **maintenance** | An HTTP route in maintenance that an online gateway serves ([Maintenance and error pages](maintenance-and-pages.md)) |

The rules are checked in this order: **disabled**, **error**, **pending**, **maintenance**, then
**unavailable**, **degraded** or **ready**.

- A **target** is ready when its connector is enabled and online and reports the route ready.
- A **gateway** serves the route when it is online, reports the route ready, and has a data session
  to the connector of a ready target.

### Why a target or a gateway does not serve

The route's page lists each target that is not ready, and each gateway that does not serve the
route in the card **Gateways not serving**, with the reason:

| Reason | Meaning and what to do |
|---|---|
| offline | The agent has no control session. Check it on its host ([Status and diagnostics](../connectors/status-and-diagnostics.md)) |
| disabled | The target's connector is switched off or gone ([Connector lifecycle](../connectors/lifecycle.md)). A drained gateway is not listed: the route's state leaves it out ([Gateways](../gateways.md)) |
| no data session to the connector | The gateway and the connector of a ready target have no tunnel between them ([Connector networking](../connectors/network.md)) |
| blocked by the connector's local policy | None of the route's targets on that connector is allowed on its host; the page shows the command that allows the first one ([The local policy](../connectors/local-policy.md#in-the-web-ui)) |
| the connector's local policy does not load | The policy file has an error, so nothing is allowed ([The local policy](../connectors/local-policy.md)) |
| the port is in use on the gateway | Another program holds the route's port ([TCP and UDP routes](tcp-and-udp.md#troubleshooting)) |
| no data session over the route's transport | The route pins a transport the connector cannot use ([Connector networking](../connectors/network.md)) |
| the host cannot serve it | Something on the agent's host is missing, such as a certificate it could not fetch yet |

A card **Rejected by** lists the agents that refused the route's latest change, with their reasons.
The routes list sums it up: "2/3 ready", "1 blocked by local policy", "rejected by 1 agent".

On the command line, `rpmgr get route wiki` shows the state, and `rpmgr get -o json route wiki`
the whole status, with the targets and gateways that do not serve and why.

## When a save is refused

- **A value the API's rules refuse** names the field. The web UI shows it next to the field; the
  command line refuses it before sending, where it can.
- **A rule of your configuration**, such as an unverified domain (`DOMAIN_NOT_VERIFIED`), a port
  outside the pools (`PORT_NOT_IN_POOL`) or a full quota (`QUOTA_REACHED`), comes with its reason.
- **Someone else changed the route since you read it.** The web UI opens a panel: "The route
  changed since you opened it", with who changed it and when, and each field either side changed.
  **Put my changes on the new version** refills the form with the saved route and your changes on
  top, for a second save; **Drop my changes** refills it with the saved route. The command line
  refuses the change and shows the route as it is now; `--force` changes it without this check.

## Export routes as YAML

Routes, and the other resources they name, can be exported as YAML manifests: one document per
resource, with other resources named by their names, and without the IDs, etags, status and times
that the server sets ([07](../../07-api.md#declarative-manifests)). A route's manifest still
carries `updateUserId`, the ID of the user who last changed the route.

- **Web UI:** **YAML** on a route's page shows its manifest; **Export YAML** on the routes list
  shows every route. The dialog has **Copy** and **Download**. Access policies, domains, CA bundles,
  connectors and gateway groups have the same buttons.
- **Command line:**

  ```sh
  rpmgr get -o yaml route wiki
  rpmgr list -o yaml route > routes.yaml
  ```

A route's manifest looks like this:

```yaml
kind: Route
metadata:
  name: nas-web
spec:
  enabled: true
  gatewayGroup: default
  http:
    hostnames:
      - nas.example.com
    port80: PORT80_MODE_REDIRECT
    tlsMode: TLS_MODE_ACME
    websocket: true
  policies:
    - office
  targets:
    - connector: home
      enabled: true
      hostPort:
        host: 192.168.10.20
        port: 5000
      proxyProtocol: PROXY_PROTOCOL_NONE
      upstreamProtocol: UPSTREAM_PROTOCOL_HTTP
      weight: 1
```

An uploaded certificate, which has no name, appears by its ID, and a basic-auth user without a
password. Manifests are for reading and keeping; editing and applying them is planned for Phase 2
([07](../../07-api.md#declarative-manifests)).
