// SPDX-License-Identifier: Apache-2.0

package tunnel

import (
	"errors"
	"io"
	"net"
	"sync"
)

// relayBuffer is the copy buffer per direction of a relay.
const relayBuffer = 32 << 10

var relayBuffers = sync.Pool{New: func() any { b := make([]byte, relayBuffer); return &b }}

// halfCloser is a connection with a separate send direction: *net.TCPConn, *net.UnixConn and
// wrappers that pass CloseWrite on.
type halfCloser interface {
	CloseWrite() error
}

// Relay copies between a stream and a connection in both directions until both have ended
// (docs/03-connections.md, "One stream per user connection"). The end of one direction is a
// half-close of the other: a FIN becomes CloseWrite, and the other direction carries on. An error
// in either direction aborts both: the stream is reset and a TCP connection, or a wrapper with
// SetLinger, is closed with SO_LINGER=0, so the peer sees a reset rather than an orderly end. It returns the bytes copied
// from the stream to the connection and back.
func Relay(st Stream, c net.Conn) (toConn, toStream int64) {
	var (
		wg    sync.WaitGroup
		abort sync.Once
	)
	fail := func() {
		abort.Do(func() {
			st.Abort()
			if l, ok := c.(interface{ SetLinger(sec int) error }); ok {
				_ = l.SetLinger(0)
			}
			_ = c.Close()
		})
	}
	wg.Go(func() {
		var err error
		toConn, err = copyHalf(c, st)
		if err == nil {
			if hc, ok := c.(halfCloser); ok {
				err = hc.CloseWrite()
			}
		}
		if err != nil {
			fail()
		}
	})
	wg.Go(func() {
		var err error
		toStream, err = copyHalf(st, c)
		if err == nil {
			err = st.CloseWrite()
		}
		if err != nil {
			fail()
		}
	})
	wg.Wait()
	_ = st.Close()
	_ = c.Close()
	return toConn, toStream
}

// copyHalf copies one direction with a pooled buffer; the end of input is no error.
func copyHalf(dst io.Writer, src io.Reader) (int64, error) {
	bp := relayBuffers.Get().(*[]byte)
	defer relayBuffers.Put(bp)
	// The wrappers hide ReaderFrom and WriterTo, so that the pooled buffer is used.
	n, err := io.CopyBuffer(struct{ io.Writer }{dst}, struct{ io.Reader }{src}, *bp)
	if errors.Is(err, io.EOF) {
		err = nil
	}
	return n, err
}
