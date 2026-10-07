# CLAUDE.md

Guidance for Claude Code and other AI coding assistants working in this repository. It summarises
the project's rules; [CONTRIBUTING.md](CONTRIBUTING.md) and [RELEASING.md](RELEASING.md) are the
authority and win on any conflict. Personal settings belong in the ignored `CLAUDE.local.md` and
`.claude/settings.local.json`, not here.

## The project

- **rpmgr** (Reverse Proxy Manager) publishes services on private networks through public gateways,
  managed from one control plane. One Go binary, `rpmgr`, runs every role: controller, gateway,
  connector, all-in-one ([02](docs/02-architecture.md)).
- **Status:** **Phase 0** (spikes, [13](docs/13-roadmap.md#phase-0--spikes)) is complete;
  **Phase 1** (MVP, [13](docs/13-roadmap.md#phase-1--mvp)) is being implemented, slice by slice,
  along the GitHub milestones `P1-M01` … `P1-M12`; one issue per slice. Decisions for it: D48–D61.
- A personal open-source project with one maintainer, the product owner, who decides; Apache-2.0.
- Read first: [README](README.md) → [00](docs/00-vision-and-scope.md) →
  [02](docs/02-architecture.md) → [03](docs/03-connections.md) → [04](docs/04-security.md); phases
  and spikes in [13](docs/13-roadmap.md); every decision taken so far in
  [14](docs/14-open-decisions.md); load-bearing decisions in [docs/adr/](docs/adr/).

## Documents are the source of truth

- **Design first.** Behaviour is described in the documents before it is implemented, and docs
  change in the same PR as the behaviour. Where each fact goes: CONTRIBUTING, "Where each fact
  goes"; checklist: "Feature documentation checklist".
- **Single sources of truth.** Connection timeouts, sizes and limits live only in
  [03](docs/03-connections.md); identities, lifetimes and cryptographic parameters only in
  [04](docs/04-security.md); DNS timers and limits only in [15](docs/15-dns.md). Link to them;
  never restate a value elsewhere.
- **Tags.** `[F …]` fact with a checked citation (source at version and line, or vendor docs with a
  retrieval date), `[R]` recommendation, `[T]` target, `[V Sx]`/`[V VB-xx]` to verify. A fact you
  have not checked yourself is `[V]`, never `[F]`.
- **Identifiers are never reused:** next free `ADR-NNNN`, `Dnn`, `Sn`, `VB-nn`, `Un`; resolved items
  are struck through, not deleted. A decision the product owner takes is recorded in 14 with the
  next `D` number.
- **ADRs:** an *Accepted* ADR's decision is never edited; a changed decision gets a new ADR that
  supersedes it. *Proposed* ADRs move to *Accepted* through their spike or the product owner.
- **Stand-alone documents** ([D33](docs/14-open-decisions.md#project-and-process)): rpmgr is never
  compared with other tunnel products. The one exception is [11](docs/11-migration.md), which names
  the formats the importer reads. Libraries and standards rpmgr uses or evaluated may be named.
- **Style:** British spelling ("behaviour", "organisation"; but "authorization", "license");
  short declarative sentences; prose wrapped at 100 columns, a table row on one line; links with
  the document number as text at the end of the sentence, `([03](03-connections.md#…))`; units with
  a space (`30 s`, `4 MiB`); diagrams in Mermaid; UI mock-ups as box-drawing ASCII.

## Git and GitHub

The repository is `github.com/felix-homelab/rpmgr`; use `gh` for issues and PRs.

- **Never push to `main`** (a ruleset blocks it) and never rewrite `main`, `release/*` or a tag.
- **Never force-push and never delete a remote branch** (D44): bring a pushed branch up to date by
  merging `main` into it; the maintainer deletes branches. Rebase only branches not yet pushed.
  Run every check locally before the first push; if a pushed PR's commits must change, push the
  corrected history to a new branch (`…-v2`), open a new PR and close the old one (D54).
- **Branches** (CONTRIBUTING, "Branches"): `feature/<issue>-<desc>` and `bugfix/<issue>-<desc>`
  need a GitHub issue; `improvement/<desc>` (tooling, docs, no behaviour change), `merge/<desc>`,
  `tmp/<desc>` (spikes, never merged), `release/<major>.<minor>`. Lowercase, digits, `-`, `.`;
  at most 60 characters.
- **Commits:** Conventional Commits, `<type>(<scope>)!: <subject>`, at most 72 characters,
  imperative, lowercase start, no period. Types `feat fix perf refactor docs test build ci chore
  revert`; scopes are the `area:` labels or `adr`, `deps`, `release`. The body says why. Always
  `git commit -s` (DCO). Substantial AI-written content carries a `Co-Authored-By:` footer naming
  the assistant.
- **Merge commits** ([D35](docs/14-open-decisions.md#project-and-process)): every branch commit
  reaches `main`, so each commit must build, be signed off and have a valid header. Fold review
  fix-ups in before merging: `git commit --fixup <commit>`, then `git rebase --autosquash main`.
- **Pull requests:** fill in the [template](.github/pull_request_template.md), including "Not
  verified"; labels `type:…`, `area:…`, `phase:…`, and `no-changelog` when nothing user-visible
  changes, otherwise a CHANGELOG entry under `## [Unreleased]` in the same PR; a feature slice that
  users cannot reach yet carries `no-changelog`, and the PR that makes it reachable writes the
  entry (D52). Merge only on green CI, with `gh pr merge <n> --merge`. Size: production code should
  stay below 400 changed lines; CI warns at 400 and fails above 800 unless labelled `mechanical`
  (D53).
- **Checks** (all in `.github/scripts/`, the same locally and in CI; Docker needed for some):
  `test-checks.sh`, `check-spdx.sh`, `check-workflows.sh`, `check-links.sh`, `check-mermaid.sh`,
  `check-secrets.sh`, and for PR metadata `check-pr-title.sh "<title>"` and
  `check-branch-name.sh <branch>`. Run the link and Mermaid checks after every document edit.
- Every source file starts with `SPDX-License-Identifier: Apache-2.0` in its comment syntax.
  Actions are pinned by commit SHA, tool images by digest.
- Never commit secrets, private keys, tokens or build output. Security vulnerabilities are never
  discussed in public issues ([SECURITY.md](SECURITY.md)).

## Spikes

Phase 0 is complete; the same process applies to later spikes, such as S9 at the start of Phase 2.
Process in CONTRIBUTING, "Spikes"; questions, methods, pass criteria and the pre-agreed rules in
[13](docs/13-roadmap.md#phase-0--spikes). In short:

- An issue from the *Spike* template; code in `spikes/sx/` (its own Go module, with a README that
  repeats every run and raw results in `results/`) on `tmp/sx-<desc>`, never merged.
- The result PR from `feature/<issue>-sx-<desc>` (`docs(adr): …`, `no-changelog`) adds
  `docs/spikes/Sx.md` from the [template](docs/spikes/TEMPLATE.md), applies the rule to the ADR and
  updates every affected document. Afterwards: tag `spike/sx` on the branch tip and push it; the
  maintainer deletes the branch.
- The rule decides; a spike never re-opens a decision. Pin the current releases and re-check, at
  those versions, every `[F]` fact the decision rests on (D39). A local dry run never decides a
  rule that needs external resources (D37); only the product owner can replace such a rule, as
  D45 and D46 did for S1 and S6.
- Go: the latest stable release, pinned with the `toolchain` directive; `CGO_ENABLED=0`.
- Even spike code follows the security rules of [04](docs/04-security.md): TLS 1.3 only, no
  `InsecureSkipVerify` (tests use a generated test CA), no 0-RTT, `crypto/rand` for keys and tokens.

## Product code

- One Go module, `github.com/felix-homelab/rpmgr` (`go 1.26.0`, `toolchain go1.27.1`), laid out as
  in [02](docs/02-architecture.md#source-layout-proposed); `CGO_ENABLED=0` everywhere.
- Spike code is copied from the archive tags (`git show spike/sx:spikes/sx/<file>`), adapted and
  kept with its tests; the PR names the tag and files.
- Generated Go code (protobuf, gRPC, ConnectRPC, Ent) is committed and checked for drift by CI.
- Test keys, seeding and fault hooks live only behind the build tag `rpmgrtest`, which release
  builds refuse (D60).
- A PR that implements a named security regression test of 12 marks it `done` in
  `.github/scripts/security-tests.txt`; CI fails otherwise (D61).

## Definition of done

From CONTRIBUTING: builds cleanly without new warnings; existing tests pass; new behaviour has
tests for **error cases and edge conditions**, not only the happy path; documents and CHANGELOG
updated; anything not run or verified is stated plainly in the PR description and in the summary
to the maintainer.
