# Overview

The overview is the first page after you sign in: your organisation at a glance, what needs
attention, and the traffic of the last 24 hours. Every member sees it; nothing on it changes
anything. Open it with **Overview** in the sidebar or with the product's mark at the top.

![The overview of the organisation "Example Lab"](../images/web/overview.png)

Under the title, **Signed in as** names you.

## Summary

A row of four figures, each a link to its page. Each shows how many of the area's resources are
well, **of** how many, and a badge under it: how many need attention, that all is well, or that the
area has nothing yet.

| Figure | Counts | Well means | Opens |
|---|---|---|---|
| **Routes serving** | Enabled routes not in maintenance | Its state is ready and no agent rejected it | [Routes](routes.md) |
| **Agents connected** | Gateways and connectors in service, not switched off | It holds a control session to the controller | [Connectors](connectors.md) |
| **Certificates in order** | The organisation's certificates | It has not failed and does not expire within 21 days | [Domains & certificates](domains.md) |
| **Domains verified** | The organisation's domain claims | It is verified | [Domains & certificates](domains.md) |

- Disabled routes, disabled connectors, drained gateways and decommissioned agents are not counted:
  nobody expects them to serve or to be connected
  ([D81](../../14-open-decisions.md#engineering)).
- Routes in maintenance are not counted either, as they are down on purpose. The routes' figure
  says how many there are, such as `1 in maintenance`
  ([D88](../../14-open-decisions.md#engineering);
  [Maintenance and error pages](../routes/maintenance-and-pages.md)).

## Traffic, last 24 hours

- **In** and **Out**: the bytes from clients to the targets and back, over all the organisation's
  routes in the last 24 hours. **Connections** counts the connections, for HTTP routes the
  streams and for UDP routes the flows; **Errors** counts those that reached no target.
- **The chart** shows the bytes in and out per hour. Hover over it for the values of an hour. A
  day without traffic shows `No traffic in this period.` instead.
- **Show the values as a table** opens the same values as a table, hour by hour, which screen
  readers and the keyboard reach.
- **Busiest routes** lists the routes with the most traffic, each linked to its page, with its
  bytes in and out.

A route's own traffic, per hour or per day, is on its page ([Routes](routes.md#traffic)). The
metrics behind it, and how long they are kept, are in [Monitoring](../operations/monitoring.md).

## Needs attention

A card beside the traffic. Each area is marked with a green tick when nothing in it needs you, or
with a warning sign and a list of what does, each item linked to its page.

| Area | Lists | When nothing is wrong |
|---|---|---|
| **Agents** | Gateways and connectors without a control session, with when each was last seen, `never connected`, or for a gateway `not enrolled yet`. Above the list: how many gateways and connectors are connected | `Every agent holds a control session.` |
| **Routes** | Routes that do not serve fully (pending, degraded, unavailable, error) or that agents rejected, with their state and how many agents rejected them | `All … routes serve fully, or are disabled.` |
| **Certificates** | Certificates that failed, with the error, or that expire within 21 days | `No certificate failed or expires within 21 days.` |
| **Domains** | Domain claims that are not verified, with their status | `Every domain is verified.` |
| **Your API tokens** | Your own API tokens that expire within 21 days or have expired | `None of your API tokens expires within 21 days.` |

As in the summary, disabled connectors and drained gateways are left out of **Agents**, and
disabled routes and routes in maintenance out of **Routes**.

## What to do next

- An agent that is not connected: check it on its host with `rpmgr status`
  ([Status and diagnostics](../connectors/status-and-diagnostics.md)).
- A route that does not serve fully: open it; its page says which target or gateway does not serve
  it and why ([Routes](routes.md#route-detail)).
- A certificate or a domain: open [Domains & certificates](domains.md).
- An API token about to expire: make a new one on your [Account](account.md#api-tokens) page.
- Anything else: [Troubleshooting](../operations/troubleshooting.md).
