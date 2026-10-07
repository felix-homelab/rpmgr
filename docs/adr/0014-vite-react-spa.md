# ADR-0014: A Vite + React + TypeScript single-page app, embedded in the binary

Status: Accepted (decided by the product owner on 2026-10-06) · Date: 2026-10-06

## Context

The web UI is served by the Controller and embedded in the single binary
([ADR-0002](0002-one-binary-three-roles.md)). It talks to the API through generated ConnectRPC
clients ([ADR-0016](0016-connectrpc-public-api-grpc-go-agents.md)).

Because the UI is embedded as static files, nothing needs server-side rendering, middleware or API
routes; a framework built around those features would serve only as a bundler and router.

The UI needs:
- forms generated from the typed model (no blob editors);
- live status and log streams;
- a terminal (Phase 3);
- i18n;
- a strict Content Security Policy.

## Decision

- **Vite + React + TypeScript** single-page app, built to static assets and embedded with
  `embed.FS`, served by the Controller with a strict CSP and HSTS.
- **Routing and data:** TanStack Router (type-safe routes) and TanStack Query, using
  connect-query for generated, typed API hooks [V VB-06].
- **UI:** shadcn/ui on Radix primitives with Tailwind CSS: accessible components that live in the
  repository.
- **Forms:** react-hook-form with protovalidate-es as its resolver, so the browser evaluates the
  same protovalidate rules as the server [V VB-16]; hand-written zod schemas are the fallback.
  Client-side validation improves the user experience only; the server's protovalidate rules are
  authoritative ([08](../08-software-stack.md)).
- **Charts:** Recharts through the shadcn/ui chart components.
- **Each form maps 1:1 to a resource.** There is no blob merging. Saves send the resource with its
  etag, so concurrent edits are detected rather than silently overwritten
  ([07](../07-api.md#writes-and-apply-status)).
- **Other libraries:**
  - xterm.js for the terminal (Phase 3);
  - CodeMirror 6 for the YAML view of resources [V VB-07];
  - i18next with English as the source locale; Phase 1 ships English only
    ([D32](../14-open-decisions.md#project-and-process)).
- Tests: unit tests for pure modules, and Playwright end-to-end tests against a real topology
  ([12](../12-testing-and-quality.md)).

## Consequences

**Positive**

- A simpler build with fewer framework concepts. Static output is what the Controller embeds anyway.
- Type-safe routes and API calls end to end, generated from the same protobufs as the server.
- No Node.js runtime in production. The Controller serves files from memory.

**Negative**

- No server-side rendering. This is acceptable for an authenticated admin UI that is not
  public-facing and does not need SEO.
- **Every page and component is written new.** shadcn/ui components are added from shadcn/ui
  itself.
- **More choices to own.** Vite gives fewer conventions than Next.js, so the project must document
  its routing and data patterns ([09](../09-web-ui.md)).

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Next.js static export | SSR, middleware and API routes are unavailable under `output: 'export'`; extra framework surface for a pure SPA |
| Next.js with a Node server | Adds a runtime and a process to every Controller; conflicts with the single static binary |
| HTMX / server-rendered Go templates | Weak fit for live streams, a graph view and complex typed forms |
| SvelteKit / Vue | Viable, but the maintainer's component experience is React + shadcn |
