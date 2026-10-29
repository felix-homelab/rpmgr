// SPDX-License-Identifier: Apache-2.0

package handoff

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// The messages about the drain of the old process (docs/03-connections.md, "Restarts with socket
// hand-off", "Showing and ending the drain").
const (
	// MsgDrain goes from the old process to the new one: what the old one still holds, in the
	// reason as Drain.String writes it.
	MsgDrain = "drain"
	// MsgEnd goes from the new process to the old one: end the drain now, close what is left and
	// exit.
	MsgEnd = "end"
)

// DrainReportEvery is how often the old process reports what it still holds (D160).
const DrainReportEvery = 5 * time.Second

// Drain is what the old process of a hand-off still holds while it drains.
type Drain struct {
	// Conns are the open TCP and HTTP connections, or for a connector the open streams.
	Conns int64
	// Flows are the open UDP flows.
	Flows int64
	// Sessions are the open data sessions.
	Sessions int64
	// Since is when the drain began, the switch.
	Since time.Time
	// Ends is when it ends at the latest.
	Ends time.Time
}

// String is the text of a MsgDrain reason: five decimal numbers, the counts and the two times as
// seconds of the Unix epoch.
func (d Drain) String() string {
	return fmt.Sprintf("%d %d %d %d %d", d.Conns, d.Flows, d.Sessions, d.Since.Unix(), d.Ends.Unix())
}

// ParseDrain reads what Drain.String wrote. A count below 0 or a text of another shape is an
// error: the new process shows nothing for it.
func ParseDrain(s string) (Drain, error) {
	f := strings.Fields(s)
	if len(f) != 5 {
		return Drain{}, fmt.Errorf("handoff: a drain report of %d fields, expected 5", len(f))
	}
	var n [5]int64
	for i, v := range f {
		x, err := strconv.ParseInt(v, 10, 64)
		if err != nil || x < 0 {
			return Drain{}, fmt.Errorf("handoff: drain report field %d is %q", i+1, v)
		}
		n[i] = x
	}
	return Drain{Conns: n[0], Flows: n[1], Sessions: n[2], Since: time.Unix(n[3], 0), Ends: time.Unix(n[4], 0)}, nil
}

// ReportDrain runs in the old process while it drains: it tells the new process what the old one
// still holds, at once and then every DrainReportEvery (every, if not 0), until ctx ends or the
// pipe breaks. counts returns the counts; since and ends are the drain's.
func ReportDrain(ctx context.Context, send func(typ, reason string) error, every time.Duration,
	since, ends time.Time, counts func() (conns, flows, sessions int64)) {
	if every <= 0 {
		every = DrainReportEvery
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		c, f, s := counts()
		if err := send(MsgDrain, Drain{Conns: c, Flows: f, Sessions: s, Since: since, Ends: ends}.String()); err != nil {
			return // the new process is gone
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Watch runs in the new process and reads the status pipe until it breaks, which is the old
// process exiting: it passes each MsgDrain report to drain and every other message to other, which
// may be nil. A report it cannot read is skipped. It returns the error that ended the pipe.
func Watch(p *Pipe, drain func(Drain), other func(typ, reason string)) error {
	for {
		typ, reason, err := p.Recv()
		if err != nil {
			return err
		}
		switch {
		case typ == MsgDrain:
			if d, err := ParseDrain(reason); err == nil {
				drain(d)
			}
		case other != nil:
			other(typ, reason)
		}
	}
}

// EndOld asks the old process of the hand-off that started this one to end its drain.
func EndOld(p *Pipe) error { return p.Send(MsgEnd, "") }
