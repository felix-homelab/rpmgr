> **Not the reference testbed** (docker-dryrun): these numbers do not decide the rule (D37).

### M1 single-stream throughput (Mbit/s)

| Cell | direct | QUIC | TCP + h2 | QUIC ÷ h2 |
|---|---|---|---|---|
| docker-dryrun RTT 1 ms loss 0 % down ×1 | 2.24e+04 | 741 | 2.1e+03 | 0.35 |
| docker-dryrun RTT 1 ms loss 0 % up ×1 | 2.22e+04 | 751 | 2.22e+03 | 0.34 |
| docker-dryrun RTT 80 ms loss 0 % down ×1 | 368 | 170 | 337 | 0.51 |
| docker-dryrun RTT 80 ms loss 0 % up ×1 | 48.5 | 176 | 340 | 0.52 |

### M2 32-stream goodput at 1 % loss (Mbit/s)

| Cell | direct | QUIC | TCP + h2 | QUIC ÷ h2 |
|---|---|---|---|---|
| docker-dryrun RTT 1 ms loss 1 % down ×32 | 2.05e+04 | 341 | 1.86e+03 | 0.18 |
| docker-dryrun RTT 1 ms loss 1 % up ×32 | 2.52e+04 | 331 | 1.78e+03 | 0.19 |
| docker-dryrun RTT 80 ms loss 1 % down ×32 | 86.9 | 4.21 | 4.49 | 0.94 |
| docker-dryrun RTT 80 ms loss 1 % up ×32 | 114 | 4.22 | 4.63 | 0.91 |

### M3 connection-setup latency p99 (ms)

| Cell | direct | QUIC | TCP + h2 | QUIC ÷ h2 |
|---|---|---|---|---|
| docker-dryrun RTT 1 ms loss 0 % setup | 2.81 | 3.18 | 2.98 | 1.07 |
| docker-dryrun RTT 80 ms loss 0 % setup | 165 | 82.1 | 81.5 | 1.01 |

### M4 CPU per Gbit/s (CPU s per Gbit)

| Cell | direct | QUIC | TCP + h2 | QUIC ÷ h2 |
|---|---|---|---|---|
| docker-dryrun RTT 1 ms loss 0 % down ×1 | — | 2.49 | 1.22 | 2.03 |
| docker-dryrun RTT 1 ms loss 0 % down ×32 | — | 2.7 | 2.14 | 1.26 |
| docker-dryrun RTT 1 ms loss 0 % up ×1 | — | 2.18 | 1.42 | 1.54 |
| docker-dryrun RTT 1 ms loss 0 % up ×32 | — | 2.37 | 1.55 | 1.53 |

### Targets (03)

| Target | Cell | Value | Met |
|---|---|---|---|
| Single stream ≥ 80 % of direct (quic) | docker-dryrun RTT 1 ms loss 0 % down ×1 | 3 % | **no** |
| Single stream ≥ 80 % of direct (h2) | docker-dryrun RTT 1 ms loss 0 % down ×1 | 9 % | **no** |
| Single stream ≥ 80 % of direct (quic) | docker-dryrun RTT 1 ms loss 0 % up ×1 | 3 % | **no** |
| Single stream ≥ 80 % of direct (h2) | docker-dryrun RTT 1 ms loss 0 % up ×1 | 10 % | **no** |
| Single stream ≥ 80 % of direct (quic) | docker-dryrun RTT 80 ms loss 0 % down ×1 | 46 % | **no** |
| Single stream ≥ 80 % of direct (h2) | docker-dryrun RTT 80 ms loss 0 % down ×1 | 92 % | yes |
| Single stream ≥ 80 % of direct (quic) | docker-dryrun RTT 80 ms loss 0 % up ×1 | 362 % | yes |
| Single stream ≥ 80 % of direct (h2) | docker-dryrun RTT 80 ms loss 0 % up ×1 | 702 % | yes |
| 32 streams at 1 % loss: QUIC ≥ 1.5 × h2 | docker-dryrun RTT 1 ms loss 1 % down ×32 | 0.18 × | **no** |
| 32 streams at 1 % loss: QUIC ≥ 1.5 × h2 | docker-dryrun RTT 1 ms loss 1 % up ×32 | 0.19 × | **no** |
| 32 streams at 1 % loss: QUIC ≥ 1.5 × h2 | docker-dryrun RTT 80 ms loss 1 % down ×32 | 0.94 × | **no** |
| 32 streams at 1 % loss: QUIC ≥ 1.5 × h2 | docker-dryrun RTT 80 ms loss 1 % up ×32 | 0.91 × | **no** |
| Added setup p99 ≤ RTT + 2 ms (quic) | docker-dryrun RTT 1 ms loss 0 % setup | +0.37 ms | yes |
| Added setup p99 ≤ RTT + 2 ms (h2) | docker-dryrun RTT 1 ms loss 0 % setup | +0.17 ms | yes |
| Added setup p99 ≤ RTT + 2 ms (quic) | docker-dryrun RTT 80 ms loss 0 % setup | -82.48 ms | yes |
| Added setup p99 ≤ RTT + 2 ms (h2) | docker-dryrun RTT 80 ms loss 0 % setup | -83.14 ms | yes |

### D19 rule

| Metric | Geometric mean, oriented (> 1 favours QUIC) | Winner |
|---|---|---|
| M1 single-stream throughput (Mbit/s) | 0.420 | h2 |
| M2 32-stream goodput at 1 % loss (Mbit/s) | 0.413 | h2 |
| M3 connection-setup latency p99 (ms) | 0.965 | tie |
| M4 CPU per Gbit/s (CPU s per Gbit) | 0.638 | h2 |

Wins: QUIC 0, TCP + h2 3 → default transport: **h2**
