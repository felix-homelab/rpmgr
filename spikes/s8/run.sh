#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Spike S8: builds the spike's tests and modernc.org/sqlite's own test suite for every target
# platform and runs them: natively on linux/amd64, and under QEMU user-mode emulation in a
# container for linux/arm64, linux/arm (GOARM=7) and linux/riscv64. Logs go to results/.
#
# Usage: run.sh [build|own|suite|probe|repeat|all] [arch...]   (default: all amd64 arm64 arm riscv64)
# Needs: Go (the toolchain in go.mod), Docker. On an arm64 host such as the Raspberry Pi 5,
# EMULATE= (empty) runs arm64 and arm natively: EMULATE= ./run.sh all arm64 arm
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
bin=${BIN:-$here/bin}
results=$here/results
step=${1:-all}
shift || true
archs=("${@:-amd64 arm64 arm riscv64}")
read -r -a archs <<<"${archs[*]}"
emulate=${EMULATE-yes}
image=rpmgr-s8-qemu
suite_timeout=${SUITE_TIMEOUT:-8h}

qemu_for() {
  case $1 in
    arm64) echo qemu-aarch64-static ;;
    arm) echo qemu-arm-static ;;
    riscv64) echo qemu-riscv64-static ;;
    *) echo "" ;;
  esac
}

build() {
  mkdir -p "$bin"
  go -C "$here" get -t modernc.org/sqlite@v1.60.1 # test-only dependencies of the suite
  for a in "${archs[@]}"; do
    local goarm=""
    [[ $a == arm ]] && goarm=7
    echo "build linux/$a"
    GOOS=linux GOARCH=$a GOARM=$goarm CGO_ENABLED=0 go -C "$here" test -c -o "$bin/s8_$a.test" .
    GOOS=linux GOARCH=$a GOARM=$goarm CGO_ENABLED=0 go -C "$here" test -c -o "$bin/sqlite_$a.test" modernc.org/sqlite
  done
  docker build -q -t "$image" -f "$here/qemu.Dockerfile" "$here" >/dev/null
}

# run_bin <arch> <log> <binary> [args...]: native for amd64 (or EMULATE= on a matching host),
# otherwise inside the emulator container. Environment variables named in RUN_ENV ("K=V ...")
# are passed to the binary. The suite needs the package directory as its working directory, so
# the module source is mounted read-only and copied to a writable place first.
run_bin() {
  local a=$1 log=$2 b=$3
  shift 3
  local q src
  q=$(qemu_for "$a")
  src=$(go -C "$here" list -m -f '{{.Dir}}' modernc.org/sqlite)
  read -r -a envs <<<"${RUN_ENV-}"
  mkdir -p "$results"
  {
    echo "# $(date -u +%FT%TZ) linux/$a $(basename "$b") $* ${RUN_ENV-}"
    echo "# host: $(uname -srm); emulator: ${q:-none}"
  } >"$log"
  if [[ $a == amd64 || -z $emulate ]]; then
    local work rc=0 start
    work=$(mktemp -d)
    cp -r "$src/." "$work/" && chmod -R u+w "$work"
    start=$(date +%s)
    # sh -c, as in the container, so quoted arguments (regexes) are parsed the same way.
    (cd "$work" && env "${envs[@]}" sh -c "\"$b\" $*") >>"$log" 2>&1 || rc=$?
    echo "# exit $rc after $(($(date +%s) - start)) s" >>"$log"
    rm -rf "$work"
    return $rc
  fi
  local eflags=(-e "S8_EXEC_PREFIX=$q")
  for e in "${envs[@]}"; do eflags+=(-e "$e"); done
  # As the invoking user, not root: some suite tests rely on file permissions being enforced.
  docker run --rm --name "rpmgr-s8-$a-$(basename "$b" .test)-$$-$RANDOM" -u "$(id -u):$(id -g)" \
    -v "$b:/t/bin:ro" -v "$src:/t/src:ro" "${eflags[@]}" "$image" \
    sh -c "cp -r /t/src /tmp/work && chmod -R u+w /tmp/work && cd /tmp/work && \
           $q --version | head -n1; start=\$(date +%s); $q /t/bin $*; rc=\$?; \
           echo \"# exit \$rc after \$((\$(date +%s) - start)) s\"; exit \$rc" >>"$log" 2>&1
}

own() {
  local pids=()
  for a in "${archs[@]}"; do
    run_bin "$a" "$results/own-$a.log" "$bin/s8_$a.test" -test.v -test.count=1 -test.timeout=1h &
    pids+=($!)
  done
  local rc=0
  for p in "${pids[@]}"; do wait "$p" || rc=1; done
  return $rc
}

# Under emulation two kinds of suite tests cannot run as written:
# - TestConcurrentGoroutines ends by re-running itself with `go test -race`, which needs a Go
#   toolchain and the race detector inside the emulator; -inner (the suite's own flag, read only
#   by this test) skips that step. amd64 runs it natively, including the -race step.
# - Five OFD-locking tests re-execute the test binary, which QEMU user mode cannot do without
#   binfmt_misc. They are skipped in the main run and run again directly in the child mode they
#   would re-execute into: the suite's child markers plus MODERNC_SQLITE_OFD_LOCK=1, which
#   executes their scenarios in process with OFD locking on.
# - TestSEHTruncatedShm needs the fault address of a SIGBUS on a truncated mapping; QEMU's arm
#   and aarch64 user mode deliver the signal without it (see `run.sh probe`), so on those two the
#   test is skipped in the main run, which it would otherwise abort, and run alone afterwards.
ofd_child='^TestOFDLock(SurvivesOSClose|InterleavedReadersWrite|ReadOnlyFirstLocker|FailedFirstLock)$'
ofd_setter='^TestOFDLockingSetter$'
seh_shm='^TestSEHTruncatedShm$'
suite() {
  local pids=()
  for a in "${archs[@]}"; do
    (
      if [[ $a == amd64 || -z $emulate ]]; then
        run_bin "$a" "$results/suite-$a.log" "$bin/sqlite_$a.test" -test.v -test.timeout="$suite_timeout"
      else
        rc=0
        skip="$ofd_child|$ofd_setter"
        if [[ $a == arm || $a == arm64 ]]; then
          skip="$skip|$seh_shm"
          run_bin "$a" "$results/suite-$a-seh-shm.log" "$bin/sqlite_$a.test" -test.v "-test.run='$seh_shm'" || true
        fi
        run_bin "$a" "$results/suite-$a.log" "$bin/sqlite_$a.test" -test.v -test.timeout="$suite_timeout" \
          -inner "-test.skip='$skip'" || rc=1
        RUN_ENV="MODERNC_SQLITE_OFD_LOCK=1 MODERNC_SQLITE_TEST_OFD_CHILD=1" \
          run_bin "$a" "$results/suite-$a-ofd-child.log" "$bin/sqlite_$a.test" -test.v "-test.run='$ofd_child'" || rc=1
        RUN_ENV="MODERNC_SQLITE_TEST_OFD_SETTER_CHILD=1" \
          run_bin "$a" "$results/suite-$a-ofd-setter.log" "$bin/sqlite_$a.test" -test.v "-test.run='$ofd_setter'" || rc=1
        exit $rc
      fi
    ) &
    pids+=($!)
  done
  local rc=0
  for p in "${pids[@]}"; do wait "$p" || rc=1; done
  return $rc
}

# probe: which fault address a SIGBUS on a truncated mapping reports on each platform
# (cmd/sigbusaddr); explains TestSEHTruncatedShm under emulation.
probe() {
  local log=$results/sigbusaddr.log rc=0
  mkdir -p "$results"
  : >"$log"
  for a in "${archs[@]}"; do
    local goarm=""
    [[ $a == arm ]] && goarm=7
    GOOS=linux GOARCH=$a GOARM=$goarm CGO_ENABLED=0 go -C "$here" build -o "$bin/sigbusaddr_$a" ./cmd/sigbusaddr
    if [[ $a == amd64 || -z $emulate ]]; then
      echo "native ($(uname -m)):" >>"$log"
      "$bin/sigbusaddr_$a" >>"$log" 2>&1 || rc=1
    else
      local q
      q=$(qemu_for "$a")
      echo "$q:" >>"$log"
      docker run --rm --name "rpmgr-s8-sigbus-$a-$$" -v "$bin/sigbusaddr_$a:/b:ro" "$image" "$q" /b >>"$log" 2>&1 || rc=1
    fi
  done
  cat "$log"
  return $rc
}

# repeat: runs one suite test REPEAT_N times, each in a new process, per architecture
# (REPEAT_TEST, default TestIssue118, a heap-profile sampling check). Summary in
# results/repeat-<test>-<arch>.log.
repeat() {
  local test=${REPEAT_TEST:-TestIssue118} n=${REPEAT_N:-10} pids=()
  for a in "${archs[@]}"; do
    (
      local sum=$results/repeat-$test-$a.log pass=0 fail=0
      : >"$sum"
      for i in $(seq 1 "$n"); do
        if run_bin "$a" "$results/repeat-$test-$a-$i.tmp" "$bin/sqlite_$a.test" -test.v "-test.run='^$test\$'"; then
          pass=$((pass + 1))
          echo "run $i: $(grep -E "^--- (PASS|SKIP): $test" "$results/repeat-$test-$a-$i.tmp")" >>"$sum"
        else
          fail=$((fail + 1))
          { echo "## run $i failed:"; cat "$results/repeat-$test-$a-$i.tmp"; } >>"$sum"
        fi
        rm -f "$results/repeat-$test-$a-$i.tmp"
      done
      echo "# linux/$a $test: $pass of $n separate runs passed, $fail failed" | tee -a "$sum"
    ) &
    pids+=($!)
  done
  for p in "${pids[@]}"; do wait "$p"; done
}

case $step in
  build) build ;;
  probe) probe ;;
  repeat) repeat ;;
  own) own ;;
  suite) suite ;;
  all) build && own && suite ;;
  *) echo "usage: $0 [build|own|suite|probe|repeat|all] [arch...]" >&2; exit 2 ;;
esac
