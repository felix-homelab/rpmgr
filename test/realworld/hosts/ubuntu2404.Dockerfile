# SPDX-License-Identifier: Apache-2.0
#
# An Ubuntu 24.04 host with systemd as PID 1, for the real-world run (README.md). Base image
# pinned by digest (CONTRIBUTING).
FROM mirror.gcr.io/library/ubuntu@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55
ENV container=docker
RUN apt-get update && apt-get install -y --no-install-recommends systemd systemd-sysv dbus ca-certificates curl \
    openssl iproute2 procps \
    && rm -rf /var/lib/apt/lists/* && systemctl mask getty@tty1.service console-getty.service
COPY shared-root.service /etc/systemd/system/
RUN systemctl enable shared-root.service
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
