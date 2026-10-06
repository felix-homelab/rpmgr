# ADR-0002: One binary with three roles

Status: Accepted (decided by the product owner on 2026-10-06) · Date: 2026-10-06

## Context

rpmgr has three kinds of process:

- the **Controller**, the control plane;
- the **Gateway**, the public ingress;
- the **Connector**, the private-side agent.

They share most of their code: the tunnel layer, PKI, protobuf types, policy, telemetry and the
upgrade logic.

Being able to install one binary everywhere, and to run everything on one VPS, matters most to the
homelab persona ([00](../00-vision-and-scope.md#who-it-is-for)).

rpmgr's design adds two constraints:

- Versions must line up. The control protocol uses capability negotiation, but within a single
  host every role should come from the same release ([03](../03-connections.md#versioning-and-capabilities)).
- Signed OTA updates have to verify, mirror and stage artifacts. Every extra binary multiplies that
  work ([ADR-0013](0013-signed-ota.md)).

## Decision

- Ship **one statically linked binary, `rpmgr`** (`CGO_ENABLED=0`). Its subcommands are
  `controller`, `gateway`, `connector` and `all-in-one`, plus CLI tools: `enroll`, `policy`,
  `apply`, `import`, `backup`, `restore`, `migrate`, `version`
  ([02](../02-architecture.md#roles)).
- A process runs **exactly one role**. The one exception is `all-in-one`, which runs a Controller
  and a Gateway in the same process for the smallest deployments
  ([02](../02-architecture.md#deployment-topologies)).
- Roles talk to each other only through their public protocols: the control session and the data
  session. They never use shared in-process state. `all-in-one` wires the same interfaces
  together in memory, so it exercises the same code paths as a split deployment.
- An optional **connector-only build** for small devices, shipped in Phase 2
  ([D21](../14-open-decisions.md#engineering)): made with a build tag that leaves out the
  controller, store and UI, published as `rpmgr-connector_<version>_<os>_<arch>` and installed as
  `rpmgr`. It comes from the same source and version, and the signed manifest lists it with
  `variant: connector` ([04](../04-security.md#release-signing)).

## Consequences

**Positive**

- One artifact per OS/arch (plus the connector-only variant), one version number, one signed
  manifest, one update path.
- `all-in-one` gives homelab users a one-process installation.
- Shared code for TLS, PKI and the tunnel exists exactly once.

**Negative**

- Every role carries code it does not run, so the full binary is larger. This matters only on
  constrained devices; the connector-only build covers that case.
- Each role's dependency surface is the union of all roles' dependencies, which makes the
  vulnerability-scan scope larger. govulncheck reports reachable code only, which limits the noise.
- Every role must reject configuration keys that belong to another role. The strict configuration
  loader ([10](../10-operations.md)) handles this.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Separate binaries per role | Three artifacts to sign, mirror and stage; possible version skew on one host; no in-process all-in-one |
| One binary that runs several roles at once, freely combined | Hard to reason about resource isolation and privilege; the only combination worth supporting is Controller + Gateway |
| Plugins or dynamically loaded roles | Go plugins are fragile across builds; static linking is what keeps installation simple |
