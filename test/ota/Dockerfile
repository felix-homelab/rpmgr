# SPDX-License-Identifier: Apache-2.0
#
# A systemd host for the root updater's tests (docs/12-testing-and-quality.md, "Continuous
# integration"): the updater restarts role services and asks systemd about them, so a stub would
# test nothing. The test mounts /var on a tmpfs, which makes the binary's directory and the
# updater's state different filesystems.
FROM mirror.gcr.io/library/debian@sha256:913f6706df59a68922d1dd08f78c2476560a8d367897200a6005b00e5f67c2d5

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates curl passwd systemd systemd-sysv util-linux \
    && rm -rf /var/lib/apt/lists/*

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
