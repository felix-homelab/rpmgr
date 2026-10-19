// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"encoding/json"
	"net"
	"sync"
)

// Msg is the simulated control-session protocol, JSON lines over TCP. It stands for rpmgr's
// Hello/Welcome, snapshot pushes, Goodbye and ProbeTarget; what S9 measures is how a signal moves
// between replicas, not the agent protocol itself, so the session carries no TLS.
type Msg struct {
	T          string `json:"t"`                  // hello, welcome, rev, agent, goodbye, probe, probe_result
	Agent      string `json:"agent,omitempty"`    // hello
	Node       string `json:"node,omitempty"`     // welcome
	Epoch      int64  `json:"epoch,omitempty"`    // welcome
	Seq        int64  `json:"seq,omitempty"`      // welcome, rev: configuration revision
	AgentSeq   int64  `json:"aseq,omitempty"`     // welcome, agent: the agent's own snapshot
	T0         int64  `json:"t0,omitempty"`       // rev, agent: commit time (UnixNano); 0 for a resync
	Reason     string `json:"reason,omitempty"`   // goodbye: superseded, overloaded, shutdown
	RetryAfter int64  `json:"retry_ms,omitempty"` // goodbye
	ID         int64  `json:"id,omitempty"`       // probe, probe_result
	DelayMs    int64  `json:"delay_ms,omitempty"` // probe: how long the simulated connector takes
}

type wire struct {
	c   net.Conn
	r   *bufio.Reader
	mu  sync.Mutex
	enc *json.Encoder
}

func newWire(c net.Conn) *wire {
	return &wire{c: c, r: bufio.NewReaderSize(c, 64<<10), enc: json.NewEncoder(c)}
}

func (w *wire) send(m Msg) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.enc.Encode(m)
}

func (w *wire) recv() (Msg, error) {
	line, err := w.r.ReadBytes('\n')
	if err != nil {
		return Msg{}, err
	}
	var m Msg
	return m, json.Unmarshal(line, &m)
}
