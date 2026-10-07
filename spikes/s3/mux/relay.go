// SPDX-License-Identifier: Apache-2.0

package mux

import (
	"io"
	"net"
	"time"
)

// SegmentingRelay accepts on l and forwards to target. Client→target bytes are written in chunks
// of at most mss bytes with TCP_NODELAY and a pause between them, so the gateway's peek sees a
// ClientHello as several segments, as on a path with a 1500-byte MTU. target→client is copied
// unchanged. It dials from 127.0.0.2, so the gateway's events tell relayed connections apart.
func SegmentingRelay(l net.Listener, target string, mss int, pause time.Duration) {
	d := &net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2)}}
	for {
		in, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			out, err := d.Dial("tcp", target)
			if err != nil {
				_ = in.Close()
				return
			}
			_ = out.(*net.TCPConn).SetNoDelay(true)
			go func() {
				buf := make([]byte, mss)
				for {
					n, err := in.Read(buf)
					if n > 0 {
						if _, werr := out.Write(buf[:n]); werr != nil {
							break
						}
						time.Sleep(pause)
					}
					if err != nil {
						break
					}
				}
				_ = out.(*net.TCPConn).CloseWrite()
			}()
			_, _ = io.Copy(in, out)
			_ = in.Close()
			_ = out.Close()
		}()
	}
}
