// SPDX-License-Identifier: Apache-2.0

package load

import (
	"fmt"
	"net"
	"net/http"
	"time"
)

// ServeWho answers every connection with name, the connector the service runs beside, and a
// newline, then closes. New connections show which connector a gateway chose (VB-18).
func ServeWho(ln net.Listener, name string) error {
	return serve(ln, func(c *net.TCPConn) {
		_, _ = fmt.Fprintln(c, name)
		_ = c.CloseWrite()
	})
}

// ServeUDPEcho sends every datagram back to its sender.
func ServeUDPEcho(pc net.PacketConn) error {
	buf := make([]byte, 64<<10)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		_, _ = pc.WriteTo(buf[:n], from)
	}
}

// ServeHTTP is the HTTP upstream: every request gets 200 and a 1 KiB body.
func ServeHTTP(ln net.Listener) error {
	body := block[:1024]
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(body)
	})}
	return srv.Serve(ln)
}
