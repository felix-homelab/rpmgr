# S8 on real arm64 hardware

GitHub-hosted arm64 runner (`ubuntu-24.04-arm`: Azure, Arm Neoverse-N2, 4 vCPUs, Linux 6.17),
workflow `.github/workflows/s8-arm64.yml` on this branch, run 37578500214 on 2026-10-07. arm64 and
armv7 (GOARM=7) binaries ran **natively**: the logs have no `qemu … version` line, which only the
emulated path of `run.sh` writes. (The `emulator:` field in the log header names the emulator for
the architecture whether or not it is used.)

| Log | Result |
|---|---|
| `suite-arm64.log`, `suite-arm.log` | modernc.org/sqlite v1.60.1 suite: 158 pass, 2 skip (by design, as on every platform), 0 fail; `TestSEHTruncatedShm` passes natively, `TestConcurrentGoroutines` including its `-race` re-run passes |
| `own-arm64.log`, `own-arm.log` | The spike's controller tests: 10 pass, 1 skip (`TestCrashChild`, the child half of the crash test) |
