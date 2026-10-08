// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"cmp"
	"context"
	"errors"
	"net"
	"slices"
	"time"

	tunnelv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/tunnel/v1"
	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// ErrNoDataSession is ControlConn's error without a data session to carry the control session.
var ErrNoDataSession = errors.New("connector: no data session to carry the control session")

// ControlConn carries a control session through a data session (CONTROL_PASSTHROUGH,
// docs/03-connections.md, "Control sessions through a data session"); it is the agent's
// ControlOptions.Fallback. It tries the established sessions, QUIC ones first: on QUIC it opens
// the stream itself, on HTTP/2 it asks for one with an OpenRequest. The control session's TLS runs
// inside the stream, from the agent to the controller; the gateway only splices it.
func (m *Sessions) ControlConn(ctx context.Context) (net.Conn, error) {
	m.mu.Lock()
	var cands []*session
	for _, gs := range m.gateways {
		for _, l := range gs.links {
			for s := range l.sessions {
				cands = append(cands, s)
			}
		}
	}
	m.mu.Unlock()
	rank := func(s *session) int {
		if s.s.Transport() == "quic" {
			return 0
		}
		return 1
	}
	slices.SortStableFunc(cands, func(a, b *session) int { return cmp.Compare(rank(a), rank(b)) })
	err := ErrNoDataSession
	for _, s := range cands {
		var st tunnel.Stream
		if st, err = openControl(ctx, s); err == nil {
			s.streams.Add(1)
			return tunnel.Conn(&countedStream{Stream: st, s: s}, tunnel.StreamAddr("connector"),
				tunnel.StreamAddr("controller via gateway "+s.l.gw)), nil
		}
		m.o.Logger.Debug("no control session through a data session", "gateway", s.l.gw, "transport", s.s.Transport(), "error", err)
	}
	return nil, err
}

// openControl opens a CONTROL_PASSTHROUGH stream on s.
func openControl(ctx context.Context, s *session) (tunnel.Stream, error) {
	if s.s.Transport() != "quic" {
		st, _, err := s.requests.Request(ctx, tunnelv1.StreamKind_STREAM_KIND_CONTROL_PASSTHROUGH, "", nil)
		return st, err
	}
	st, err := s.s.OpenStream(ctx)
	if err != nil {
		return nil, err
	}
	if err := tunnel.WriteMessage(st, &tunnelv1.StreamOpen{Kind: tunnelv1.StreamKind_STREAM_KIND_CONTROL_PASSTHROUGH}); err != nil {
		st.Abort()
		return nil, err
	}
	timer := time.AfterFunc(tunnel.OpenTimeout, st.Abort)
	stop := context.AfterFunc(ctx, st.Abort)
	res := &tunnelv1.StreamResult{}
	err = tunnel.ReadMessage(st, res)
	intime := timer.Stop() && stop()
	switch {
	case err != nil || !intime:
		st.Abort()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err == nil {
			err = tunnel.ErrOpenTimeout
		}
		return nil, err
	case res.GetCode() != tunnelv1.ResultCode_RESULT_CODE_NO_ERROR:
		_ = st.Close()
		return nil, &tunnel.OpenRejectedError{Code: res.GetCode()}
	}
	return st, nil
}
