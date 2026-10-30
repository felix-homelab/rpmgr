# SPDX-License-Identifier: Apache-2.0
#
# A systemd host for the root updater's tests (docs/12-testing-and-quality.md, "Continuous
# integration"): the updater restarts role services and asks systemd about them, so a stub would
# test nothing. The test mounts /var on a tmpfs, which makes the binary's directory and the
# updater's state different filesystems.
FROM mirror.gcr.io/library/debian@sha256:2dc419c6d7fe3dad0a2f9fd469c34cc90b0f9ba642d8fde837fe3d7d34a0e7f1

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates curl dbus passwd systemd systemd-sysv util-linux \
    && rm -rf /var/lib/apt/lists/*

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
