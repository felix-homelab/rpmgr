# SPDX-License-Identifier: Apache-2.0
#
# The TLS-intercepting proxy of the WSS cell (docs/12-testing-and-quality.md, "Where the cells
# run"): mitmproxy, pinned by digest (CONTRIBUTING), with the addon that records what it sees.
FROM mirror.gcr.io/mitmproxy/mitmproxy:12.3.1@sha256:2711066c855659b5af8b1dbb84494ed3eff69b42ece439c60b4fe09a2db829d4
COPY observe.py /opt/rpmgr/observe.py
