# ADR-0022: A restart hands the listening sockets to a re-executed binary

Status: Accepted (spike S10 applied the rule, with the fallbacks of S-2, S-3 and S-4;
[S10](../spikes/S10.md)) · Date: 2026-10-26

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
  lost: 200 of 200 queued connections were served after the old process closed its copy. Two
  sockets bound with `SO_REUSEPORT` each have their own queue, and closing one reset 94 to 105 of
  200 queued connections [F S10, `spikes/s10/results/host-experiments.txt`, Linux 6.18].
- **Datagrams.** A datagram on a shared UDP socket goes to whichever process reads it. A QUIC
  packet of the old process's connection read by the new one is unknown there, and with the
  gateway's persisted `StatelessResetKey` the new process answers with a stateless reset [F
  quic-go v0.64.1 `transport.go:630-646`]: when both processes read, every old session ended so
  [F S10, run D].
- **quic-go's fast path.** quic-go reads in batches and writes with `WriteMsgUDP` only on a
  connection that offers `ReadMsgUDP`, `WriteMsgUDP` and `SyscallConn`, as `*net.UDPConn` does;
  any other gets its basic path [F quic-go v0.64.1 `sys_conn.go:42-102`]. A wrapper that inspects
  each datagram therefore takes the slow path all the time, not only during a hand-off.
- **The service manager.** The units are `Type=simple` today and restart by stopping first. A unit
  keeps running when its main process exits only if systemd was told of the new main process
  (`MAINPID=` over the notify socket) [F systemd v257 `man/sd_notify.xml:292-298`]; with
  `NotifyAccess=all` systemd 249 and 257 accepted it from the new process, kept the unit active
  and restarted the unit when that process was killed, while logging that it supervises a process
  that is not its child [F S10, 11 runs].
- **Who may get the sockets.** They may sit on privileged ports, which the unit grants through
  `CAP_NET_BIND_SERVICE`; a socket that another local process could collect would let it serve a
  public hostname ([04](../04-security.md#socket-hand-off-phase-2)).

## Decision

**Mechanism** ([03](../03-connections.md#restarts-with-socket-hand-off-phase-2))
- On a trigger (`SIGUSR2` from `rpmgr handoff`, `systemctl reload`, the install scripts or the
  root updater), the running process checks the installed binary and starts it as its child,
  passing every listening socket by inheritance, a manifest naming each one and a status pipe.
- The child checks each descriptor against the manifest and its boot file, starts from the stored
  last-known-good snapshot, opens its control session and reports ready over the pipe; the old
  process takes the `Goodbye{superseded}` this causes and opens no further control session, so
  the two never supersede each other in turn.
- Only then does the old process send `Drain{reason: handoff}` to its data sessions. It keeps
  accepting public connections until the child has sessions of every connector it had, at the
  latest until it exits (the fallback of S-4), then stops accepting and drains its open
  connections for the hand-off drain ([D146](../14-open-decisions.md#engineering)). The child
  tells systemd it is the main process.
- A child that is not ready in time is killed and the old process serves on; the restart is
  reported as failed.
- An all-in-one stops its controller and closes SQLite between the child's start and its
  readiness, and takes the controller up again if the child fails.
- A connector has no listening socket and hands over its sessions the same way
  ([D147](../14-open-decisions.md#engineering)).

**UDP and QUIC** (the fallback of S-2 and S-3, [S10](../spikes/S10.md))
- Only the old process reads the UDP sockets until it exits. It accepts no new QUIC session after
  the switch, keeps its open ones and serves every `udp` route flow, new ones included. The new
  process starts its QUIC listener and its UDP routes once the old one has exited.
- Connectors on `auto` open their new sessions over TCP meanwhile and come back to QUIC at the next
  re-probe; a connector pinned to `quic` reaches the new process only after the old one has exited.
- QUIC stays on the plain socket, with quic-go's fast path; nothing tags connection IDs or relays
  datagrams.

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
- QUIC keeps its full speed: no wrapper sits in the read path between hand-offs.

**Negative**

- The old process takes part, so the first restart that keeps traffic up starts from a release
  that has the hand-off; v0.2.0 → v0.3.0 restarts as before.
- An old process may run for the hand-off drain next to the new one, with its memory; at most one.
- During the drain, connectors on `auto` run over TCP to the new process. A connector pinned to
  `quic` has no session there until the old process exits, so with one the old process keeps
  accepting public connections until then and cuts those still open at the hand-off drain.
- A `udp` flow still open when the old process exits starts again in the new one, and datagrams in
  flight at that moment may be lost.
- An all-in-one's web UI and API answer 503 for the seconds its controller moves; only several
  controller replicas avoid that (P2-M09).
- Containers get no hand-off.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| systemd socket activation (`.socket` units) | Route ports are opened at run time from the snapshot, and a socket unit must name its ports at start |
| `SO_REUSEPORT`, the new process binding the same ports | Each socket has its own queue; closing the old one reset about half of the connections waiting in it [F S10], and any process of the service user could bind the port too |
| Descriptors over a unix socket to a process systemd starts (SCM_RIGHTS) | Needs a listening unix socket and a peer check; the first fallback of S-1, not needed |
| systemd's file-descriptor store and a plain restart | The old process must exit before the new one starts, so nothing drains and connections wait unanswered; `FileDescriptorStorePreserve=` needs systemd 254 [F systemd v257 `man/systemd.service.xml:1205-1219`], newer than Ubuntu 22.04's 249 |
| QUIC connection IDs tagged with the process generation, and a relay of datagrams from the old process to the new one (the design's first choice) | S10: relayed QUIC reached 5 % (systemd 249 host) and 39 % (257 host) of quic-go's direct throughput, below the rule's half, and the relay lost datagrams of `udp` flows; its datagram wrapper also takes quic-go off its fast path for good |

## Verification

**VB-08, spike S10** ([S10](../spikes/S10.md),
[issue #880](https://github.com/felix-homelab/rpmgr/issues/880); code on `tmp/s10-socket-handoff`,
tag `spike/s10`; Go 1.27.3, quic-go v0.64.1, systemd 249 and 257). The rules were agreed before
it ran ([D150](../14-open-decisions.md#engineering)):

- **S-1, TCP.** Under at least 500 new connections per second, a hand-off by re-exec refuses or
  resets no new connection, the unit stays `active` throughout, and open connections run to the
  drain timeout. Fails → descriptors over a unix socket to a process systemd starts, with a peer
  check; fails too → the file-descriptor store with a short restart, and 03 states the gap.
  **Result: passed** (0 refused, 0 reset in 11 runs; the unit active or reloading throughout).
- **S-2, QUIC.** With generation-tagged connection IDs and the relay, no old session receives a
  stateless reset, connectors' sessions run on the new process within 5 s of `Drain` (p99, local
  network), and relayed throughput is at least half the direct one. Fails → the new process reads
  UDP only after the old one exits, and connectors on `auto` use TCP meanwhile; fails too → the
  old process ends its QUIC sessions at the hand-off, cutting their streams, and 03 states it.
  **Result: failed on throughput (0.05 and 0.39 of direct); the first fallback applies and
  passed** (no reset, connectors on `auto` on the new process within 0.33 s, no visitor failure).
- **S-3, `udp` routes.** Through the relay a UDP echo loses no more datagrams than the link does.
  Fails → the old process serves every UDP flow until the drain ends; flows open then start again
  in the new process. **Result: failed (3 datagrams lost on a lossless link); the fallback
  applies.**
- **S-4, sessions.** With a lone gateway and one to four connectors, new visitor connections during
  the hand-off succeed within the session wait, and p99 until every connector has sessions to the
  new process is at most 3 s. Fails → the old process accepts public connections until the new
  one has sessions of every connector the old one had. **Result: passed for connectors on `auto`
  (0.33 s at most) and over QUIC with the relay (0.04 s); failed under S-2's fallback for a
  connector pinned to `quic` (20.2 s, until the old process exited); the fallback applies.**
- **S-5, control session.** The old process takes `Goodbye{superseded}` during a hand-off without
  ending early, and the controller shows the gateway connected throughout. **Result: passed** by
  the controller's code and tests, not in the model: the controller records a session's end only
  for its own epoch; the old process must not redial after the `Goodbye`, as above.
- **S-6, all-in-one.** Never two writers on the SQLite file (a lock on it); the API's 503 window is
  at most 10 s plus the migration; an injected migration failure lets the old process reopen the
  database with nothing lost. **Result: passed** (12 to 29 ms plus the migration; no row lost).
- **S-7, facts.** Every [V VB-08] above is checked and becomes an [F] with its source, or the
  design changes with it. **Result: done**; the design changed with S-2, S-3 and S-4.
