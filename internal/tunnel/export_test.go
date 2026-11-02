// SPDX-License-Identifier: Apache-2.0

package tunnel

import (
	"context"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// WithMaxStreams lowers the connector's stream limit, for tests.
func WithMaxStreams(w H2Windows, n int) H2Windows {
	w.maxStreams = n
	return w
}

// PendingFlows is how many unknown flows a session keeps datagrams for.
const PendingFlows = pendingFlows

// BudgetWithStallAge makes the stalled-stream rule of QUIC sessions admitted by b reset streams
// after age.
func BudgetWithStallAge(b *Budget, age time.Duration) *Budget {
	b.stallAge = age
	return b
}

// WithStallAge makes the stalled-stream rule of an HTTP/2 session reset streams after age.
func WithStallAge(w H2Windows, age time.Duration) H2Windows {
	w.stallAge = age
	return w
}

// StallResets is how many streams the stalled-stream rule of s has reset.
func StallResets(s Session) int {
	switch s := s.(type) {
	case *H2Gateway:
		return s.stalls.Resets()
	case *H2Connector:
		return s.stalls.Resets()
	case *QUICSession:
		return s.stalls.Resets()
	}
	panic("unknown session")
}

// StallWatched is how many streams the stalled-stream rule of s watches.
func StallWatched(s Session) int {
	var st *Stalls
	switch s := s.(type) {
	case *H2Gateway:
		st = s.stalls
	case *H2Connector:
		st = s.stalls
	case *QUICSession:
		st = s.stalls
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	return len(st.streams)
}

// SessionWindows are the windows a QUIC session was admitted with.
func SessionWindows(s *QUICSession) H2Windows { return s.windows }

// Admit makes the listener admit a connection from addr as if quic-go had called its
// GetConfigForClient and ConnContext, and returns how the connection ends.
func (l *QUICListener) Admit(addr string, verified bool) (end func(), err error) {
	ua, perr := net.ResolveUDPAddr("udp", addr)
	if perr != nil {
		return nil, perr
	}
	info := &quic.ClientInfo{RemoteAddr: ua, AddrVerified: verified}
	if _, err := l.admit(info); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	if _, err := l.connContext(ctx, info); err != nil {
		cancel()
		return nil, err
	}
	return cancel, nil
}

// PendingBytes is what the listener's unclaimed admissions hold.
func (l *QUICListener) PendingBytes() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.pendingBytes
}
