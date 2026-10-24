# Route limits

A route can cap what its visitors use: how many connections are open at once, how many requests or
new connections come in a second, and how much bandwidth they take. This page is for anyone who
publishes a service that should not be overrun, by a flood or by one heavy user. The rules behind
it are in [03](../../03-connections.md#route-limits-phase-2) and
[D131](../../14-open-decisions.md#engineering).

## What the limits count

| Limit | Counts | Over the limit, a visitor gets |
|---|---|---|
| Connections | open TCP and TLS passthrough connections, UDP flows, and HTTP requests in flight, upgraded ones such as WebSockets included | HTTP: 503 "Service unavailable" with `Retry-After`; TCP: the connection is reset; UDP: the datagram is dropped |
| Requests per second | HTTP requests, new connections or new UDP flows | HTTP: 429 "Too Many Requests" with `Retry-After`; TCP: reset; UDP: dropped |
| Bandwidth | bytes a second, in each direction separately | TCP and HTTP: the data slows down, nothing is lost; UDP: datagrams above it are dropped |

Each limit is for the route as a whole. The gateways of the route's group share it: each enabled
gateway enforces an equal part, rounded up. A gateway that is enabled but down keeps its part, so
while it is down the route gets less than its limit; disable a gateway you take down for longer.
0 means no limit. The largest values are in
[03](../../03-connections.md#route-limits-phase-2).

## Set limits

### With the command line

Give the limits when you create the route, or change them later; each flag changes only its own
limit:

```sh
rpmgr create route --tcp --name db --group eu --max-connections 200 --requests-per-second 20
rpmgr update route --bandwidth 10485760 db
rpmgr update route --requests-per-second 0 db
```

`--bandwidth` is in bytes a second; the last command removes the request limit. The
[CLI reference](../reference/cli.md#rpmgr-create-route) lists the flags.

### With the web UI

The route form gets its limits section with a later release; until then the web UI shows and keeps
the limits the command line set.

## Gateways of an earlier release

A gateway of a release before limits cannot enforce them. It does not get a route with limits at
all, rather than serve it without them: the route's status names the gateway as missing the
capability `route.limits` ([Preview and apply](preview-and-apply.md)). Update the gateway
([Updates](../operations/updates.md)) and it serves the route again.

## Troubleshooting

- **Visitors get 503 or 429 although the service is idle.** The limit is shared by the group's
  gateways: with four gateways, each takes a quarter. A gateway that is down still holds its part;
  disable it, or raise the limit.
- **A route is not served on one gateway.** See the route's status: a gateway of an earlier release
  lacks `route.limits`.
