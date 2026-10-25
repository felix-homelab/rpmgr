# ADR-0022: A restart hands the listening sockets to a re-executed binary

Status: Proposed (design phase; slice 17.2 decides by the rule below) · Date: 2026-10-25

## Context

- **The goal.** A gateway, an all-in-one and a connector restart, for an update too, without
  refusing a visitor connection, and the old process drains its open connections
  ([D127](../14-open-decisions.md#project-and-process)). Today a restart closes the listeners,
  drains for the gateway drain period and exits; a lone gateway refuses connections until the new
  process listens ([03](../03-connections.md#failure-modes)).
- **Dynamic ports.** Besides 443, 80, the QUIC socket and the admin port, a gateway opens a
  listener for each `tcp`, `udp` and CONNECT route port its snapshot names, at run time. Sockets
  that systemd opens from `.socket` units must be known when the unit starts.
- **Shared queues.** Two processes that hold the same listening socket share its queue of
  connections waiting to be accepted, so whichever accepts next takes a connection and none is
  lost. Two sockets bound with `SO_REUSEPORT` each have their own queue, and closing one resets the
  connections waiting in it [V VB-08].
- **Datagrams.** A datagram on a shared UDP socket goes to whichever process reads it. A QUIC
  packet of the old process's connection read by the new one is unknown there; with the gateway's
  persisted `StatelessResetKey` the new process would answer with a valid stateless reset and end
  the connection ([03](../03-connections.md#quic-parameters)).
- **The service manager.** The units are `Type=simple` today and restart by stopping first. A unit
  keeps running when its main process exits only if systemd was told of the new main process
  (`MAINPID=` over the notify socket) [V VB-08].
- **Who may get the sockets.** They may sit on privileged ports, which the unit grants through
  `CAP_NET_BIND_SERVICE`; a socket that another local process could collect would let it serve a
  public hostname ([04](../04-security.md#socket-hand-off-phase-2)).

## Decision

**Mechanism** ([03](../03-connections.md#restarts-with-socket-hand-off-phase-2))
- On a trigger (`SIGUSR2` from `rpmgr handoff`, `systemctl reload`, the install scripts or the
  root updater), the running process checks the installed binary and starts it as its child,
  passing every listening socket by inheritance, a manifest naming each one and a status pipe.
- The child checks each descriptor against the manifest and its boot file, starts from the stored
  last-known-good snapshot, opens its control session and reports ready over the pipe. Only then
  does the old process stop accepting, send `Drain{reason: handoff}` to its data sessions and
  drain its open connections for the hand-off drain
  ([D146](../14-open-decisions.md#engineering)). The child tells systemd it is the main process.
- A child that is not ready in time is killed and the old process serves on; the restart is
  reported as failed.
- An all-in-one stops its controller and closes SQLite between the child's start and its
  readiness, and takes the controller up again if the child fails.
- A connector has no listening socket and hands over its sessions the same way
  ([D147](../14-open-decisions.md#engineering)).

**UDP and QUIC**
- During the drain only the old process reads the shared UDP sockets. QUIC connection IDs carry the
  process generation; the old process passes Initial packets and packets of the new generation,
  and datagrams of new `udp` route flows, to the new process over a local socket pair. The new
  process reads the sockets itself once the old one exits.

**Units** ([10](../10-operations.md#hardened-systemd-units),
[D148](../14-open-decisions.md#engineering))
- `Type=notify`, `NotifyAccess=all`; `systemctl reload` of a gateway or all-in-one runs the
  hand-off. Containers restart without one ([D149](../14-open-decisions.md#engineering)).

## Consequences

**Positive**

- No new visitor connection is refused while a gateway or all-in-one restarts, and long-lived
  connections survive an update for the hand-off drain.
- A failed update never takes a lone gateway down: the old process serves until the new one is
  ready, so a rollback only puts the previous binary back.
- No socket or file is ever open for another process to collect the sockets.

**Negative**

- The old process takes part, so the first restart that keeps traffic up starts from a release
  that has the hand-off; v0.2.0 → v0.3.0 restarts as before.
- An old process may run for the hand-off drain next to the new one, with its memory; at most one.
- The UDP relay costs throughput during the drain, and drops datagrams beyond its queue.
- An all-in-one's web UI and API answer 503 for the seconds its controller moves; only several
  controller replicas avoid that (P2-M09).
- Containers get no hand-off.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| systemd socket activation (`.socket` units) | Route ports are opened at run time from the snapshot, and a socket unit must name its ports at start |
| `SO_REUSEPORT`, the new process binding the same ports | Each socket has its own queue; closing the old one resets the connections waiting in it [V VB-08], and any process of the service user could bind the port too |
| Descriptors over a unix socket to a process systemd starts (SCM_RIGHTS) | Needs a listening unix socket and a peer check; kept as the first fallback below |
| systemd's file-descriptor store and a plain restart | The old process must exit before the new one starts, so nothing drains and connections wait unanswered; `FileDescriptorStorePreserve=` needs systemd 254, newer than Ubuntu 22.04's 249 |

## Verification

**VB-08, slice 17.2** (a study on `tmp/socket-hand-off-study`, never merged; pinned Go, quic-go and
systemd 249 and 257; every [F] fact re-checked, D39). The rules were agreed before it runs
([D150](../14-open-decisions.md#engineering)):

- **S-1, TCP.** Under at least 500 new connections per second, a hand-off by re-exec refuses or
  resets no new connection, the unit stays `active` throughout, and open connections run to the
  drain timeout. Fails → descriptors over a unix socket to a process systemd starts, with a peer
  check; fails too → the file-descriptor store with a short restart, and 03 states the gap.
- **S-2, QUIC.** With generation-tagged connection IDs and the relay, no old session receives a
  stateless reset, connectors' sessions run on the new process within 5 s of `Drain` (p99, local
  network), and relayed throughput is at least half the direct one. Fails → the new process reads
  UDP only after the old one exits, and connectors on `auto` use TCP meanwhile; fails too → the
  old process ends its QUIC sessions at the hand-off, cutting their streams, and 03 states it.
- **S-3, `udp` routes.** Through the relay a UDP echo loses no more datagrams than the link does.
  Fails → the old process serves every UDP flow until the drain ends; flows open then start again
  in the new process.
- **S-4, sessions.** With a lone gateway and one to four connectors, new visitor connections during
  the hand-off succeed within the session wait, and p99 until every connector has sessions to the
  new process is at most 3 s. Fails → the old process accepts public connections until the new
  one has sessions of every connector the old one had.
- **S-5, control session.** The old process takes `Goodbye{superseded}` during a hand-off without
  ending early, and the controller shows the gateway connected throughout.
- **S-6, all-in-one.** Never two writers on the SQLite file (a lock on it); the API's 503 window is
  at most 10 s plus the migration; an injected migration failure lets the old process reopen the
  database with nothing lost.
- **S-7, facts.** Every [V VB-08] above is checked and becomes an [F] with its source, or the
  design changes with it.

The study moves this ADR to Accepted, with the fallbacks its results trigger written in.
