# SPDX-License-Identifier: Apache-2.0
#
# A Debian 12 host with systemd as PID 1, for the real-world run (README.md). Base image pinned
# by digest (CONTRIBUTING).
FROM mirror.gcr.io/library/debian@sha256:2c037a04925515fdd6ea85ea14a682d0e79931f5e9f5d07b6dbfc6ba12f9e858
ENV container=docker
RUN apt-get update && apt-get install -y --no-install-recommends systemd systemd-sysv dbus ca-certificates curl \
    openssl iproute2 procps jq minisign sqlite3 \
    && rm -rf /var/lib/apt/lists/* && systemctl mask getty@tty1.service console-getty.service
COPY shared-root.service /etc/systemd/system/
RUN systemctl enable shared-root.service
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
