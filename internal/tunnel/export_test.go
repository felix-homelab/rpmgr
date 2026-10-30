// SPDX-License-Identifier: Apache-2.0

package tunnel

import "time"

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

// SetAdmissionExpiry shortens how long a QUIC reservation waits for its handshake, for tests; the
// returned function restores it.
func SetAdmissionExpiry(d time.Duration) func() {
	old := admissionExpiry
	admissionExpiry = d
	return func() { admissionExpiry = old }
}
