# SPDX-License-Identifier: Apache-2.0
"""What the intercepting proxy of the WSS cell sees, written to observed.json in its directory.

connects: the authorities of the CONNECT requests; refused: the server names for which the client
refused the proxy's certificate; websockets: the URLs of the WebSockets it relayed; messages and
bytes: their messages and payload bytes; marker: the messages whose payload holds the text of the
option marker, which the cell sends through its routes in the clear.
"""

import json
import os

from mitmproxy import ctx, http, tls

OUT = "/var/lib/rpmgr/observed.json"


class Observe:
    def __init__(self):
        self.seen = {"connects": [], "refused": [], "websockets": [], "messages": 0, "bytes": 0, "marker": 0}

    def load(self, loader):
        loader.add_option("marker", str, "", "text the payloads must not hold")

    def write(self):
        tmp = OUT + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.seen, f)
        os.replace(tmp, OUT)

    def add(self, key, value):
        if value not in self.seen[key]:
            self.seen[key].append(value)
            self.write()

    def running(self):
        self.write()

    def http_connect(self, flow: http.HTTPFlow):
        self.add("connects", flow.request.authority)

    def tls_failed_client(self, data: tls.TlsData):
        self.add("refused", data.context.client.sni or "")

    def websocket_start(self, flow: http.HTTPFlow):
        self.add("websockets", flow.request.pretty_url)

    def websocket_message(self, flow: http.HTTPFlow):
        m = flow.websocket.messages[-1]
        self.seen["messages"] += 1
        self.seen["bytes"] += len(m.content)
        if ctx.options.marker and ctx.options.marker.encode() in m.content:
            self.seen["marker"] += 1
        # The relayed messages are not kept: the cell sends megabytes.
        flow.websocket.messages.clear()
        self.write()


addons = [Observe()]
