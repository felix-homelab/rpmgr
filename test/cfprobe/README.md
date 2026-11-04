# Cloudflare probe: run sheet for VB-09 to VB-12 and VB-26

`cfprobe` checks the open Cloudflare questions of the
[verification backlog](../../docs/13-roadmap.md#verification-backlog) against a real zone of your
account. CI never runs it and no assistant sees a token
([D110](../../docs/14-open-decisions.md#project-and-process)): you run it by hand before v0.4.0,
and again on the 1.0 release candidate. CI tests the same code against the fake Cloudflare API,
`internal/dns/cftest`.

It uses the product's Cloudflare client
([15](../../docs/15-dns.md#cloudflare-specifics)) for records, zones and token verification, and its
own raw requests only where a header or a field the client hides is the question.

## What it does, and what it never does

- **Tokens** come only from a file or from standard input (`-`), never from an argument or the
  environment. Every output line is scrubbed of them, and the program prints no token. A file that
  other users can read gets an `INFO SETUP` warning.
- **Records** are created only under one random label, `_rpmgr-probe-<10 hex>`, in your zone
  (`owned.<label>.<zone>`, `foreign.<label>.<zone>`, and so on). With `-apex-cname` it also
  creates one CNAME at the zone apex, but only if the apex has no records at all.
- **Cleanup:** it deletes exactly the records it created (by ID, and everything under its label)
  before it ends, also after a failed check or an interrupt. What it cannot delete is printed as
  `FAIL CLEANUP LEFTOVER <type> <name> (record <id>)` and makes the exit status 1. A record that
  existed before is never written; the run compares all of them before and after.
- **VB-09 burst** sends only read requests. It is off unless you pass `-burst N` **and**
  `-confirm-burst`, stops at the first 429 or the first other error, and accepts at most 2000
  requests. Once Cloudflare answers 429, all API calls of that Cloudflare user are blocked for
  minutes, the dashboard included. The records are cleaned up before the burst starts.

Lines start with `PASS`, `FAIL` or `INFO`. `INFO` is an observation to record, not a verdict. The
under-scoped token is expected to fail, so its refusal is a `PASS`.

| Check | Lines | Answers |
|---|---|---|
| VB-09 | 429 after N requests, shape of `Retry-After` (seconds, date or absent), related headers, whether the client maps it to `dns.RateLimited`, whether the account-owned and the under-scoped token are blocked too | [15](../../docs/15-dns.md#batches-failures-and-the-rate-budget): shape of the 429, own budget of account-owned tokens |
| VB-10 | marker round-trip (51 characters, then 100), a patch that changes the comment alone, a record without a marker untouched, a failed batch all-or-nothing and its message, listing by comment | [15](../../docs/15-dns.md#ownership-ledger) |
| VB-11 | CNAME unproxied and proxied (TTL 1), proxied wildcard on this plan, CNAME at the apex (`-apex-cname`) | [15](../../docs/15-dns.md#proxied-http-routes) |
| VB-12 | token verify (user and account-owned), expiry, zone status and type, how many zones the token sees, the under-scoped token refused | [15](../../docs/15-dns.md#connecting-importing-and-disconnecting) |
| VB-26 | every identifier seen (zone, records, token, account) is 32 lower-case hex characters | [15](../../docs/15-dns.md#cloudflare-specifics) |

**Not covered, and printed as such:** a proxied CNAME to another account's name (error 1014, slice
7.3 with a second account), request-size and timeout limits, ACME HTTP-01 through the proxy,
partial, secondary and child zones, paging with more than 50 zones, moved zones, scoping a token
below a zone. These `[V]` tags stay. Whether Cloudflare flattens an apex CNAME is not visible in
the API; the probe reports that the API accepts it.

## Prepare

- A Cloudflare account on the **Free plan**.
- A **spare zone**, active and full, **without mail** and without services: the probe writes there
  (under its label) and, with `-apex-cname`, briefly at the apex. Name it `<zone>` below.
- Three tokens, each expiring within a few days and, for the first two, scoped to `<zone>`:
  - **user token** (My Profile, API Tokens, custom): Zone / Zone / Read and Zone / DNS / Edit,
    zone resource `<zone>` only;
  - **account-owned token** (Manage Account, Account API Tokens): the same permissions and zone;
    its account ID is the 32-character ID in the dashboard URL (not a secret);
  - **under-scoped token** (user token): Zone / Zone / Read only, no DNS permission. The probe
    expects it to be refused.
- A checkout of this repository and Go.

Store the tokens without echo and readable only by you:

```sh
umask 077
mkdir -p ~/cfprobe-tokens
for n in user account under; do
  printf 'paste the %s token, then Enter and Ctrl-D: ' "$n"
  stty -echo; cat > ~/cfprobe-tokens/$n; stty echo; echo
done
```

## Dry run, no Cloudflare

```sh
go test -count=1 -tags rpmgrtest ./test/cfprobe
go build -o ~/cfprobe ./test/cfprobe
```

## Run 1: everything except the burst

Replace `<zone>` and `<account-id>`. `-apex-cname` is only for a zone whose apex has no records.

```sh
~/cfprobe -zone <zone> \
  -token-file ~/cfprobe-tokens/user \
  -under-scoped-token-file ~/cfprobe-tokens/under \
  -account-id <account-id> -account-token-file ~/cfprobe-tokens/account \
  -apex-cname | tee ~/cfprobe-run1.txt
```

A token can also come from standard input, for example from a password manager, for at most one of
the three: `pass show cf/user | ~/cfprobe -token-file - …`.

Exit status 0: no `FAIL` and nothing left behind. 1: a `FAIL` or a leftover. 2: a mistake in the
command line or a token file; nothing was sent.

## Run 2: the rate-limit burst (VB-09), last

Run it only after run 1 is clean. It blocks the API of the Cloudflare user that owns the user token
for minutes, the dashboard included, so do not run it while you need the account. Choose N above
the request budget in [15](../../docs/15-dns.md#batches-failures-and-the-rate-budget); the requests
are sent one after another, so the budget is reached only if your connection is fast enough. "No
429 after N requests" is then a result too, not a failure.

```sh
~/cfprobe -zone <zone> \
  -token-file ~/cfprobe-tokens/user \
  -under-scoped-token-file ~/cfprobe-tokens/under \
  -account-id <account-id> -account-token-file ~/cfprobe-tokens/account \
  -burst 1500 -confirm-burst | tee ~/cfprobe-run2.txt
```

When it says `NOW open the Cloudflare dashboard`, do so within the minutes the block lasts and
note whether the dashboard was blocked (it is VB-09's question about the same user). The `INFO`
lines say whether the account-owned and the under-scoped token were blocked as well.

## What to paste back

Paste the **PASS/FAIL/INFO output** of both runs (`~/cfprobe-run1.txt`, `~/cfprobe-run2.txt`) and
one sentence on the dashboard. The output holds the names of the probe records, the record and zone
IDs and the error messages of Cloudflare; none of it is secret. It contains no token: the program
replaces any token it sees with `[redacted]`, but read it once before you paste. Never paste the
token files.

Afterwards revoke the three tokens in the dashboard (they expire anyway) and delete
`~/cfprobe-tokens`. If the output has a `LEFTOVER` line, delete that record in the dashboard (search
for `_rpmgr-probe-`).

## Recording the results

A follow-up PR (slice 6.3 delivers the probe, not the results) records them, in the style of the
resolved items of the backlog:

- In [13](../../docs/13-roadmap.md#verification-backlog), each of VB-09 to VB-12 and VB-26 is struck
  through and given **Resolved** (date, commit of `cfprobe`, the facts the lines showed), or
  **Partly resolved** with what stays open (the "not covered" list above).
- In [15](../../docs/15-dns.md) (and [04](../../docs/04-security.md) for VB-12), each `[V VB-nn]`
  tag becomes `[F cfprobe <date> <check>]` where the run showed it, and stays `[V]` where it did
  not. A result that contradicts the text changes the text, and a decision that depends on it goes
  into [14](../../docs/14-open-decisions.md) with the next `D` number.
- Slices 6.9, 6.12 and 6.13 read VB-10 and VB-09, and 7.3 and 6.6 read VB-11 and VB-12; tell the
  maintainer-side assistant if a result changes their design.
