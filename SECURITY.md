# Security policy

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion for a vulnerability.**

Report it privately through GitHub: *Security* → *Report a vulnerability*
(<https://github.com/felix-homelab/rpmgr/security/advisories/new>). This is the only reporting
channel. Please include:

- the affected version or commit, and the role (controller, gateway, connector);
- what an attacker can do, and under which conditions;
- steps to reproduce, or a proof of concept;
- whether the issue is already public.

Do not include real credentials, tokens or private keys; describe them instead.

## What happens next

| Step | Target |
|---|---|
| Acknowledgement | 3 working days |
| First assessment (valid or not, severity) | 10 working days |
| Fix released, critical severity | 14 days after the assessment |
| Fix released, high severity | 30 days after the assessment |
| Fix released, medium or low severity | With the next regular release |

rpmgr has one maintainer, so these are targets, not guarantees; if a target will be missed, the
reporter is told why and when to expect the fix.

The fix is developed in a private security advisory and released for every supported version at
the same time ([RELEASING.md](RELEASING.md#security-releases)). The advisory, with a CVE where
applicable, is published when the fixed releases are available. Reporters are credited unless they
prefer not to be.

## Supported versions

Nothing has been released yet (design phase). Before 1.0.0, only the latest `0.y` release receives
fixes. From 1.0.0 on, the latest minor release receives all fixes, and the previous minor receives
security fixes and fixes for critical defects (data loss, outages)
([RELEASING.md](RELEASING.md#supported-versions)).

## Scope

- **In scope:** the rpmgr binary in every role, the web UI, the install scripts, release artifacts
  and their signatures, and the security model in [docs/04-security.md](docs/04-security.md) —
  a design flaw is a valid report.
- **Out of scope:** vulnerabilities in third-party dependencies that rpmgr does not make reachable
  (please report them upstream, and tell us if rpmgr is affected); attacks that need full control
  of a host the threat model already treats as compromised
  ([04](docs/04-security.md#threat-model)); denial of service by volume alone.
