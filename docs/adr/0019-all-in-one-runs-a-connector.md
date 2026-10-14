# ADR-0019: All-in-one runs a connector next to its controller and gateway

Status: Accepted (decided by the product owner, D89, 2026-10-14) · Date: 2026-10-14 · Supersedes
the all-in-one clause of [ADR-0002](0002-one-binary-three-roles.md) in part

## Context

- **Services on the all-in-one host.** All-in-one ran a controller and a gateway
  ([ADR-0002](0002-one-binary-three-roles.md)). A service on the same host, such as a container
  next to rpmgr, needed a second install of the binary as a connector, enrolled with its own token.
- **Reaching the gateway from the same host.** A connector on the host dials the gateway's tunnel
  endpoint, which is the public URL's host on port 443. That needs the public name to resolve on
  the host, and a host behind a router to reach its own public address through it (hairpin NAT),
  which many home routers do not do.
- **The public host's own ports.** A connector on the gateway's host can reach that host's
  loopback services: the admin listener with its metrics, and the gateway's own ports. A route to
  one of the gateway's ports loops traffic through rpmgr again.
- **Agents that are the process.** Decommissioning the all-in-one's gateway revoked its identity,
  which stopped the whole process; it would fail again at every restart. A connector in the same
  process has the same weakness.

## Decision

**Three roles in one process**
- `rpmgr all-in-one` runs a controller, a gateway and a connector. `all-in-one init` creates the
  connector "local" in the org Default next to the gateway "local" and enrolls it through the
  in-process controller, into `<state_dir>/connector/identity`. `rpmgr all-in-one` enrolls it at
  start when that identity is missing: as the same connector while it is in service, else as a
  new one. So an installation made before this decision gets its connector without a new init
  ([02](../02-architecture.md#all-in-one-homelab-default)).
- If any of the three roles ends, the process ends; on the way out the gateway drains first, while
  the connector serves its streams and the controller answers.

**Data sessions in memory**
- The connector reaches the in-process gateway over in-memory connections, with the same TLS
  handshake, gateway pin and reverse HTTP/2 as over TCP, and never through the gateway's endpoints.
  One such session carries every route to that gateway, whatever the route's transport policy. A
  gateway in another place keeps the normal transports
  ([03](../03-connections.md#transports-and-fallback)).

**Its local policy, and rpmgr's own ports**
- The connector reads the boot file's `policy_file`, `/etc/rpmgr/policy.yaml` by default, which
  allows nothing until targets are added (D5). `rpmgr setup` asks for allowed and denied targets,
  the unit reloads on SIGHUP, and `rpmgr policy` reloads the all-in-one's unit on a host without a
  connector.
- Whatever the policy allows, the connector never dials one of rpmgr's own ports on an address of
  the host. The ports are those rpmgr listens on: the admin listener, 80, 443 (TCP and UDP),
  tunnel UDP, and every route port the gateway has bound. The addresses of the host are loopback,
  the unspecified addresses, the addresses of its interfaces, and those the public URL's host and
  the group's public hostnames resolve to (hairpin NAT)
  ([04](../04-security.md#connector-local-policy)).
- A signal to reload the policy (SIGHUP) never ends the process, also while it starts or stops.

**Built-in agents**
- The all-in-one's gateway and connector are marked built in. The API refuses to decommission
  them and to mint enrollment tokens bound to them; the web UI marks them and offers neither.
  Switching them off and draining stay possible ([06](../06-data-model.md#fleet)).

## Consequences

**Positive**

- A homelab publishes services on its one host with one install.
- No DNS or hairpin NAT is needed for the host's own services.
- Decommissioning can no longer stop an all-in-one by accident.

**Negative**

- The public host's own network becomes reachable through routes, as far as its local policy
  allows. The policy allows nothing by default, and rpmgr's own ports stay closed whatever it says,
  but a broad allowance exposes the host's other loopback services.
- Another path to rpmgr's ports, such as a router or container that forwards an address of its own
  to them (DNAT), is not detected; such a target must not be allowed for those ports.
- The local policy does not survive a compromised controller on an all-in-one, which shares the
  connector's process; it limits the routes made through the API, not an attacker in the process.
- The connector's control and data sessions show "in-process" as their remote address, and its
  data session reports the h2 transport, though it never leaves the process.
- `rpmgr status`, `diag` and `leave` still cover only separately installed agents.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Dial the gateway's public endpoint from the same process | Needs DNS and hairpin NAT, which many home networks lack |
| Allow loopback by default | Would publish the host's loopback services, rpmgr's own among them, to every route |
| Make the connector optional | The product owner asked for all three roles in every all-in-one |
