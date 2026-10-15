# Maintenance and error pages

The gateways answer some requests themselves: for a name no route serves, when a service cannot
be reached, and for an HTTP route in maintenance. This page is for anyone who runs HTTP services
behind rpmgr: it shows the built-in pages and who gets them, and how to take a service down for
maintenance with a word to its visitors.

## The built-in pages

A browser gets a page from the gateway instead of bare text
([D87](../../14-open-decisions.md#engineering)):

| Page | Status | When |
|---|---|---|
| "Site not available" | 404 | No route serves the hostname or the path, or the route is disabled |
| "Service unavailable" | 503 | No connector with a ready target, or the gateway cannot take the request now |
| "Service unavailable" | 502 | The target refused or reset the connection, or its HTTPS certificate failed the check |
| "Service unavailable" | 504 | The target did not answer in time |
| "Down for maintenance" | 503 | The route is in maintenance ([Maintenance](#maintenance)) |

Each page names the status, such as `503 · Service Unavailable`, and the hostname the visitor asked
for, and says in plain words what happened:

- "Site not available": "Nothing is published at *host*. Check the address, or try again later if
  you expected a site here."
- "Service unavailable": "The service at *host* cannot be reached right now. Please try again in a
  few minutes."
- "Down for maintenance": "The service at *host* is undergoing maintenance and will be back soon.",
  followed by the route's maintenance message, if it has one.

Both 503 answers carry a `Retry-After` header ([03](../../03-connections.md#http-routes)).

### Who gets a page

- Only a client whose `Accept` header names `text/html`, which browsers send, gets a page. curl,
  scripts and API clients get the plain text they always got, such as
  `no route for this host and path` or `Service Unavailable`, with the same status.
- A `HEAD` request gets the headers alone.
- A response your service sends, its own errors included, always passes unchanged: the gateway
  never replaces it.

### How the pages are built

The pages are built into rpmgr and are in English. Each is one self-contained HTML document with
light and dark themes: no script, nothing loaded from elsewhere, and a `Content-Security-Policy`
that allows only its own style. It is sent with `Cache-Control: no-store`, so a browser asks again
once the service is back. The hostname appears as escaped text, as the visitor asked for it, never
the one a route sends upstream.

Pages of your own per gateway group are planned for Phase 2
([05](../../05-features.md#http-features)).

### Names no route serves

- **On port 443**, the gateway completes the TLS handshake for any name: with a valid certificate it
  holds whose names cover the requested one, such as a route's wildcard certificate, or else with
  its self-signed default certificate. A browser shows a certificate warning for the default
  certificate first, then the "Site not available" page. A request on that connection for another
  name gets 421, so that the browser asks again on a connection of its own
  ([03](../../03-connections.md#port-443-multiplexing)).
- **On port 80**, a name no route serves gets the "Site not available" page. On an all-in-one, the
  controller's own name is the exception: port 80 redirects it to the public URL.

## Maintenance

Maintenance takes an HTTP service down with a word to its visitors, while the route stays
configured and published ([D88](../../14-open-decisions.md#engineering)).

### What maintenance does

- The route stays on its gateways, with its certificate, its HSTS and its port-80 mode.
- Every request that the route's access policies admit, basic auth included, gets 503 with
  `Retry-After` and the "Down for maintenance" page, which shows your message. A client that does
  not ask for HTML gets `Service Unavailable: down for maintenance`, followed by the message, as
  text. A request an access policy refuses gets the refusal, as before.
- No request reaches a connector or a target. Maintenance works even when no target is ready, so
  you may stop the service and its host.
- Requests already running, WebSockets included, finish as they do when a route changes. A request
  with a body gets its answer without the body being read, and an HTTP/1.1 connection then closes.

Only HTTP routes have maintenance: a TCP, UDP or TLS passthrough route cannot show a page. Compare
the **Enabled** switch: a disabled route is removed from the gateways, so its visitors get "Site
not available" (404) instead.

### Put a route in maintenance

**With the web UI:**

1. Open the route's page.
2. Optionally set the message first: choose **Edit**, enter the
   **Maintenance message (plain text, at most 500 characters)**, and choose **Save**.
3. Turn on the **Maintenance** switch next to **Enabled**. The page follows the change to the
   gateways. The configured settings then say "in maintenance" and "The maintenance page says: …".
4. To end maintenance, turn the switch off again.

The **Edit** form has the setting as well: **Maintenance**, **On: show the maintenance page** or
**Off: serve the route**.

**With the command line:**

```sh
rpmgr update route --maintenance \
  --maintenance-message "Back at 18:00 UTC. Sorry for the interruption." --wait 30s wiki
rpmgr update route --maintenance=false --wait 30s wiki
```

`--maintenance-message ""` removes the message. `rpmgr create route --http --maintenance …` creates
a route that starts in maintenance.

### The message

- Plain text of at most 500 characters. Line breaks are kept; no other control characters are
  allowed.
- Characters that change the direction of text (U+202A to U+202E and U+2066 to U+2069) are refused,
  as they could turn the text around where it is shown.
- It is always shown as text, never as HTML: markup appears as typed.

### Who may do it, and what is recorded

Switching maintenance on and off and changing the message need the role Owner, Admin or Operator,
like any other route change ([Members and roles](../accounts/members-and-roles.md)). The
[audit log](../operations/audit-log.md) records it as a route update. A change of the maintenance
fields alone does not check the route's hostnames against your domains again.

### The route's state

Once the gateways have applied it, the route's state is **maintenance**, as long as an online
gateway of its group serves it. Until then it is **pending**, and if an agent rejected the change,
**error** ([Preview and apply](preview-and-apply.md)). The overview counts routes in maintenance
apart and leaves them out of "Needs attention".

A gateway of v0.1.0-rc.6 or earlier ignores maintenance and serves the route until it is upgraded
([Upgrades](../install/upgrades.md)).
