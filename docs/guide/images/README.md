# Images of the user guide

This directory holds the pictures of the user guide. `web/` holds one screenshot per page of the
web UI, which the [web UI reference](../web-ui/README.md) shows. This page is for whoever
maintains the guide: it says how the screenshots are made and how to make them again after the web
UI changed.

## What the screenshots show

The screenshots are generated, never edited by hand. They show a made-up organisation, "Example
Lab", in the light theme, in a window of 1440 × 900 pixels. Most pages are shown whole. The
public pages, the dialogs and a few pages, such as `audit.png`, `gateways.png` and
`settings-updates.png`, show only the window, so a page longer than the window is cut off at its
foot. `mobile-menu.png` alone shows a phone's screen, 390 × 844 pixels, as the menu exists only on
small screens.

The data is fake: names under `example.com` and `example.net`, addresses from the
documentation ranges of RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and RFC 3849
(`2001:db8::/32`), and users named after computing pioneers. The installation runs only for the
screenshots, on the machine that takes them, and is deleted afterwards; the identifiers, keys and
pins in the pictures belong to nothing.

## Make the screenshots again

One command builds the web UI, starts the made-up installation and writes every screenshot into
`docs/guide/images/web/`, replacing the old ones:

```sh
.github/scripts/screenshots.sh
```

To write only some of them, name them without `.png`, separated by commas:

```sh
.github/scripts/screenshots.sh routes,route-detail
```

It needs Docker, Node and npm, and Go, as the browser tests of the web UI do
([12](../../12-testing-and-quality.md#test-strategy)). It takes about a minute after the first run,
which downloads the Playwright image. While it runs, it listens on the port 8443 when that is
free, otherwise on any free port, and on the few ports between 30000 and 30099 that its made-up
TCP and UDP routes take, on all interfaces.

Check the new pictures before you commit them: `git diff --stat docs/guide/images/web` shows which
changed. A page whose layout changed needs its text in `docs/guide/web-ui/` checked too.

## How it works

| Part | Does |
|---|---|
| [`.github/scripts/screenshots.sh`](../../../.github/scripts/screenshots.sh) | Builds `web/` into `internal/webui`, then runs `TestScreens` with `SCREENS` set |
| [`test/webe2e/screens_test.go`](../../../test/webe2e/screens_test.go) | `TestScreens`: runs an all-in-one and two more connectors in the test process, seeds them through the public API, runs the browser in the Playwright image of `.github/scripts/lib.sh`, and recompresses the PNGs |
| [`web/screens.config.ts`](../../../web/screens.config.ts) | The Playwright configuration: light theme, 1440 × 900, the browser trusting only the test certificate |
| [`web/screens/screens.spec.ts`](../../../web/screens/screens.spec.ts) | The walk through the UI that takes each screenshot |

`TestScreens` skips itself unless the variable `SCREENS` is set, to `all` or to a list of names,
so the browser tests in CI never take screenshots. It is built with the `webe2e` tag, as the
browser tests are:

```sh
source .github/scripts/lib.sh
npm --prefix web ci && npm --prefix web run build
SCREENS=all go test -tags webe2e -count=1 -timeout 15m -run '^TestScreens$' ./test/webe2e/
```

## Add a screenshot

1. Add the steps to `web/screens/screens.spec.ts`: navigate, wait for the page's heading, then call
   `shot(page, "<name>")`, or `shot(page, "<name>", true)` for the whole page.
2. If the page needs data the seed lacks, add it in `seed` in `test/webe2e/screens_test.go`, with
   made-up names and documentation addresses. Never write anything that looks like an rpmgr token
   (`rpmgr_` and a kind): secret scanners read every branch.
3. Run `.github/scripts/screenshots.sh <name>` and embed the picture with a relative path, such as
   `![…](../images/web/<name>.png)`.
