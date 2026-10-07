# S8 raw results

Recorded on 2026-10-06 on an x86-64 host (20 logical CPUs, Linux 6.18 under WSL2, Docker 29.8)
with `../run.sh`; the binaries were built with Go 1.27.1, `CGO_ENABLED=0`, and the emulated ones
run with QEMU 10.0.13 user mode inside the `qemu.Dockerfile` container, as the invoking user.

| File | Contents |
|---|---|
| `own-<arch>.log` | The spike's tests (`store_test.go`, `crash_test.go`) |
| `suite-<arch>.log` | modernc.org/sqlite v1.60.1's own test suite, main run |
| `suite-<arch>-ofd-child.log`, `suite-<arch>-ofd-setter.log` | Emulated targets only: the five OFD-locking tests that re-execute the test binary, run directly in their child mode |
| `suite-<arch>-seh-shm.log` | arm and arm64 only: `TestSEHTruncatedShm` alone; it aborts the process under QEMU (see `sigbusaddr.log`) |
| `sigbusaddr.log` | `cmd/sigbusaddr`: the fault address a SIGBUS on a truncated mapping reports, natively and under each emulator |
| `repeat-TestIssue118-<arch>.log` | `TestIssue118`, a heap-profile sampling check, in ten separate processes per target |
| `repeat-TestBackupCommitClosesConnOnError-<arch>.log` | The one suite test that needs file permissions enforced, in three separate processes as a non-root user |
| `run1/` | The first emulated suite runs, before the targeted skips and as root inside the container: `TestSEHTruncatedShm` aborted the arm and arm64 runs, `TestConcurrentGoroutines` failed on its `go test -race` step (no toolchain in the emulator), and `TestIssue118` failed once on arm64 |

The amd64 suite ran natively, including `TestConcurrentGoroutines`' recursive `go test -race`
step (PASS). Durations of each run are in the last line of its log.
