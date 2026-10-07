# QEMU user-mode emulators for running linux/arm64, linux/arm and linux/riscv64 test binaries on
# an amd64 host without touching the host's binfmt_misc: the binaries are started explicitly as
# `qemu-<arch>-static <binary>` inside this container (spike S8, D38).
FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
RUN apt-get update \
 && apt-get install -y --no-install-recommends qemu-user-static \
 && rm -rf /var/lib/apt/lists/*
