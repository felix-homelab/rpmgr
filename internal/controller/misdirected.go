// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"net"
	"net/http"
	"strings"
	"time"
)

// misdirected answers 421 Misdirected Request (RFC 9110, section 15.5.20) to a request whose Host
// names another host than the server name its connection's ClientHello sent, compared
// case-insensitively and without a final dot or a port (docs/03-connections.md, "Transport"). A
// browser reuses an HTTP/2 connection for every name the certificate covers, such as a wildcard
// certificate's or a gateway's other names, and must not get the controller's UI or API for a name
// that is not the controller's: it asks again on a connection of its own. A connection without a
// server name, such as one to an IP address, has no name to differ from and is served. An HTTP/1.1
// connection closes after the answer, without reading a request body.
func misdirected(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.TLS.ServerName == "" || strings.EqualFold(hostName(r.Host), strings.TrimSuffix(r.TLS.ServerName, ".")) {
			next.ServeHTTP(w, r)
			return
		}
		if r.ProtoMajor == 1 {
			w.Header().Set("Connection", "close")
			if r.ContentLength != 0 {
				_ = http.NewResponseController(w).SetReadDeadline(time.Now())
			}
		}
		http.Error(w, http.StatusText(http.StatusMisdirectedRequest), http.StatusMisdirectedRequest)
	})
}

// hostName returns a Host header without its port, the brackets of an IPv6 literal and a final dot.
func hostName(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	} else if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	return strings.TrimSuffix(host, ".")
}
