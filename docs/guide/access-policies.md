# Access policies

An access policy decides who may reach a route: by the client's IP address on every route type,
and on HTTP routes with a user name and password (basic auth) or with a header that only your CDN
or your clients know (a required header). Policies are reusable: one policy,
such as "office only", can guard many routes. This page is for anyone who publishes services and
wants to limit who reaches them.

## Before you start

- Creating, changing and attaching policies needs the role Owner, Admin or Operator
  ([Members and roles](accounts/members-and-roles.md)).
- Know the addresses your clients come from, as the gateways see them. Behind a load balancer or
  another proxy, set the gateway group's trusted proxies first
  ([The client's address](#the-clients-address)).
- For the command line, a stored API token
  ([API tokens and the command line](accounts/api-tokens-and-cli.md)).

## The rules

A policy has a name, an optional description and up to 50 rules of four kinds:

| Kind | Web UI | Command line | Applies to |
|---|---|---|---|
| Allow addresses | **Allow addresses** | `--rule allow:<cidr>,…` | every route type |
| Deny addresses | **Deny addresses** | `--rule deny:<cidr>,…` | every route type |
| Basic auth | **Basic auth (HTTP routes)** | `--rule basic-auth:<user>,…` | HTTP routes only |
| Required header | **Require a header (HTTP routes)** | `--rule require-header:<header>` | HTTP routes only |

An address rule holds up to 1000 CIDRs, IPv4 or IPv6, such as `203.0.113.0/24`, `2001:db8::/32`, or
`198.51.100.7/32` for a single address; an address without a prefix length is refused. A CIDR with
host bits set is stored masked: `10.0.0.1/16` becomes `10.0.0.0/16`.

### How address rules decide

A route applies the rules of all its policies together, and **a deny always wins**
([D85](../14-open-decisions.md#engineering)):

1. If a deny rule contains the client's address, the client is refused, whatever any allow rule
   says, and in whatever order the rules and the route's policies come.
2. Otherwise, if an allow rule contains the address, the client is admitted.
3. If no rule contains it, the client is admitted only when none of the route's rules is an allow
   rule.

So allow rules make an allow list, deny rules alone make a block list, and a deny inside an allowed
range takes that part out. An IPv4-mapped IPv6 address, such as `::ffff:192.0.2.1`, counts as its
IPv4 address, for the client and in a CIDR alike. A route without policies admits everyone.

| The route's rules | 192.0.2.10 | 192.0.2.99 | 198.51.100.5 |
|---|---|---|---|
| allow `192.0.2.0/24` | admitted | admitted | refused |
| allow `192.0.2.0/24`, deny `192.0.2.99/32` | admitted | refused | refused |
| deny `198.51.100.0/24` | admitted | admitted | refused |
| none | admitted | admitted | admitted |

### The client's address

The client's address is the TCP connection's peer, or a UDP datagram's source. On an HTTP route
whose gateways sit behind a proxy or load balancer, add that proxy to the gateway group's **Trusted
proxies** ([Gateways](gateways.md)): for a request from a trusted proxy, the client is the last
address in `X-Forwarded-For` that is not a trusted proxy. A chain that does not parse counts as the
proxy's own address. Without that setting, every request seems to come from the proxy.

### Basic auth

A basic-auth rule holds up to 100 users, each with a name and a password. A password follows the
length rule of account passwords ([04](../04-security.md#human-authentication-and-sessions)).

- The controller stores only an argon2id hash of each password, and the gateways get only the
  hashes. A password is never shown again; when you edit a policy, a user whose password you leave
  empty keeps it.
- A request that the address rules admit must then pass every basic-auth rule of the route's
  policies, in order. Without credentials, or with wrong ones, it gets 401 with
  `WWW-Authenticate: Basic`, and the browser asks for them. A browser sends one user name and
  password, so put all users of a route into one rule: with two rules, the credentials must pass
  both.
- A client address that tries too many passwords gets 429 with `Retry-After` until it may try
  again ([04](../04-security.md#secrets-at-rest-and-in-logs)).
- The gateway removes the `Authorization` header before the request goes upstream, so the service
  never sees the passwords.
- A policy with a basic-auth rule cannot be attached to a TCP, UDP, "TCP and UDP" or TLS
  passthrough route, whose clients could never answer it, and a policy that such a route applies
  cannot get a basic-auth rule.

### Required header

A required-header rule admits only requests that carry a header with one of its values, a shared
secret. Use it when a CDN or another proxy that you control sits in front of the route: the CDN
adds the header to every request it forwards, so a client that goes around the CDN to the gateway
is refused.

- A rule names one header, such as `X-Origin-Token`, and up to four values, so that you can add a
  new value, change the CDN over to it, and then remove the old one. A value has at least 32
  visible characters and no spaces; the web UI generates one for you.
- The controller stores only a SHA-256 hash of each value, and the gateways get only the hashes. A
  value is never shown again: copy it to your CDN before you save. When you edit a policy, a
  required header whose values you leave empty keeps them.
- A request that the address rules admit must carry the header of every required-header rule of
  the route's policies, with one of its values, or it gets 403. The rules are checked before
  basic auth.
- The gateway removes the header before the request goes upstream, so the service never sees the
  secret.
- A policy requires a header once. Headers that HTTP uses for the connection, the gateway's
  forwarding headers, `Host`, `Authorization`, `Cookie` and `Rpmgr-` headers cannot be required.
- As with basic auth, a policy with a required header cannot be attached to a route that is not an
  HTTP route, and a policy that such a route applies cannot get one.
- A gateway that is older than the rule does not serve a route that applies it until the gateway
  is upgraded; the route's status names the gateway ([Upgrades](install/upgrades.md)).

## Create a policy

### With the web UI

1. Open **Access policies** and choose **New access policy**.
2. Enter a **Name**, lower-case letters, digits and hyphens, and optionally a **Description**.
3. Under **Rules**, the form starts with one **Allow addresses** rule; choose **Add a rule** for
   each further one. Each rule starts with a list that chooses its kind:
   - for **Allow addresses** or **Deny addresses**, enter the **Addresses (CIDRs, one per line)**;
   - for **Basic auth (HTTP routes)**, choose **Add a user** for each user, the first one too, and
     enter a **User** and a **Password**;
   - for **Require a header (HTTP routes)**, enter the **Header** and a **Value**, or choose
     **Generate a value**; **Add a value** adds another, up to four.

   **Remove the rule** takes a rule out.
4. Choose **Create the policy**.

The list shows each policy's rules in short, such as "allow 192.0.2.0/24", "basic auth: alice,
bob", "requires header X-Origin-Token", and the routes that use it. **Edit…** changes a policy; **Remove…** removes it, which is
refused while a route applies it.

### With the command line

An allow list for an office network, with one address taken out:

```sh
rpmgr create access-policy --name office-only \
  --rule allow:192.0.2.0/24,2001:db8:10::/48 \
  --rule deny:192.0.2.99/32
```

A basic-auth policy. Passwords are never given as arguments: they come from a file of
`user:password` lines, and a user the file does not name is asked for on the terminal. Write the
file with an editor, readable by you alone (`chmod 600 users.txt`):

```text
# users.txt
alice:correct horse battery staple
bob:another long secret
```

```sh
rpmgr create access-policy --name staff-login \
  --rule basic-auth:alice,bob --passwords-file users.txt
```

The command warns when other users may read the file. Blank lines and lines starting with `#` are
skipped.

A required header for a CDN. Its values come from a file of `header: value` lines, one line per
value, or, for a header the file does not name, one value from the terminal:

```text
# cdn-values.txt
X-Origin-Token: replace-me-with-the-value-your-cdn-sends
```

```sh
rpmgr create access-policy --name cdn-only \
  --rule require-header:X-Origin-Token --header-values-file cdn-values.txt
```

To change a policy, give the flags you change. The rules given replace all of the policy's rules;
when asked for a password of a user who has one, or for the value of a header the policy requires,
an empty answer keeps it:

```sh
rpmgr update access-policy \
  --rule allow:192.0.2.0/24,198.51.100.0/24 --rule deny:192.0.2.99/32 office-only
rpmgr delete access-policy office-only
```

## Attach policies to a route

### With the web UI

1. Open the route's page and find the **Access policies** card. Without policies it says "The route
   applies no access policy: every client reaches it."
2. Under **Add a policy**, choose one and choose **Attach**; **Detach** takes one off.
3. Choose **Save**. The page follows the change to the gateways.

### With the command line

```sh
rpmgr update route --policy office-only --policy staff-login --wait 30s wiki
rpmgr update route --policy "" --wait 30s wiki
```

`--policy` takes a name or an ID and replaces the route's list; given once empty, it detaches every
policy. `rpmgr create route` takes `--policy` as well. A route applies at most 20 policies, each
once.

The order of a route's policies, and of a policy's rules, does not change who is admitted: a deny
rule of any policy wins over every allow rule, and the web UI offers no order to set.

## What clients see

| Route type | Refused by an address rule | Required header | Basic auth |
|---|---|---|---|
| HTTP | 403 | 403 without the header or with a wrong value | 401 without or with wrong credentials, 429 after too many attempts |
| TCP, TLS passthrough | the connection is reset before it reaches a connector | — | — |
| UDP | the datagram is dropped and counted; no flow starts | — | — |

## Changes and open connections

- **Tightening applies at once.** When a change of a policy, or of a route's policies, refuses
  clients that were admitted before, the gateways reset those clients' TCP and TLS passthrough
  connections, end their UDP flows, and cancel their HTTP requests, WebSockets included, as soon as
  they apply the change ([03](../03-connections.md#access-policies)).
- **Loosening** takes effect for the next connection or request.
- A changed basic-auth user list applies to the next request; the gateways forget what they had
  verified for the policy before.
- A required header whose value you remove ends the requests and WebSockets that were admitted
  with that value; adding a value ends nothing.

A gateway of v0.1.0-rc.6 or earlier decides by the first matching rule until it is upgraded
([Upgrades](install/upgrades.md)). Single sign-on with OIDC in front of a route and rate and
connection limits are planned for Phase 2 ([05](../05-features.md#edge-access-control-and-limits)).
