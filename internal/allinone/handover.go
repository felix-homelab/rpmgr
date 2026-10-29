// SPDX-License-Identifier: Apache-2.0

package allinone

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/memnet"
	"github.com/felix-homelab/rpmgr/internal/telemetry"
)

// memSwap is the in-memory network of the roles: it hands connections to the controller that runs
// now. A controller that stopped for a hand-over leaves a closed listener, so that the gateway and
// the built-in agents get an error and redial until a controller serves again.
type memSwap struct {
	mu  sync.Mutex
	cur *memnet.Listener
}

func (m *memSwap) set(l *memnet.Listener) {
	m.mu.Lock()
	m.cur = l
	m.mu.Unlock()
}

func (m *memSwap) get() *memnet.Listener {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cur
}

func (m *memSwap) Deliver(c net.Conn) { m.get().Deliver(c) }

func (m *memSwap) Dial(ctx context.Context, addr string) (net.Conn, error) {
	return m.get().Dial(ctx, addr)
}

func (m *memSwap) Close() error { return m.get().Close() }

// tracked remembers what a controller registered, so that a controller that starts again in the
// same process can register it again.
type tracked struct {
	telemetry.Registry
	mu sync.Mutex
	cs []prometheus.Collector
}

func (t *tracked) Register(c prometheus.Collector) error {
	if err := t.Registry.Register(c); err != nil {
		return err
	}
	t.mu.Lock()
	t.cs = append(t.cs, c)
	t.mu.Unlock()
	return nil
}

func (t *tracked) MustRegister(cs ...prometheus.Collector) {
	for _, c := range cs {
		if err := t.Register(c); err != nil {
			panic(err)
		}
	}
}

func (t *tracked) unregister() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, c := range t.cs {
		t.Unregister(c)
	}
	t.cs = nil
}

// ctlHolder runs the controller and can stop it for a hand-over and start it again: the database
// is closed when the controller has ended, and the old process opens it again only if the new one
// failed (docs/03-connections.md, "All-in-one hand-over").
type ctlHolder struct {
	opts  controller.RunOptions // all but Listener, Restart, Registry, Readiness and Listening
	reg   telemetry.Registry
	ready func(check func(context.Context) error) // adds a check to the admin listener's
	mem   *memSwap
	// gone receives the error of a controller that ended on its own, not for a hand-over.
	gone chan error

	mu         sync.Mutex
	cur        *ctlRun
	check      atomic.Pointer[func(context.Context) error]
	registered bool
}

type ctlRun struct {
	cancel   context.CancelFunc
	restart  chan struct{}
	fin      chan struct{} // closed when Run returned; err is then set
	err      error
	handover atomic.Bool
}

// start runs a controller and returns once it listens, or its error.
func (h *ctlHolder) start() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	inst := memnet.NewListener()
	h.mem.set(inst)
	ctx, cancel := context.WithCancel(context.Background())
	r := &ctlRun{cancel: cancel, restart: make(chan struct{}), fin: make(chan struct{})}
	listening := make(chan struct{})
	reg := &tracked{Registry: h.reg}
	o := h.opts
	o.Listener, o.Restart, o.Registry = inst, r.restart, reg
	o.Listening = func() { close(listening) }
	o.Readiness = func(c func(context.Context) error) {
		h.check.Store(&c)
		if !h.registered {
			h.registered = true
			h.ready(func(ctx context.Context) error { return (*h.check.Load())(ctx) })
		}
	}
	go func() {
		r.err = controller.Run(ctx, o)
		reg.unregister()
		close(r.fin)
		select {
		case <-listening:
		default:
			return // start reports it
		}
		if !r.handover.Load() {
			select {
			case h.gone <- r.err:
			default:
			}
		}
	}()
	h.cur = r
	select {
	case <-listening:
		return nil
	case <-r.fin:
		if r.err == nil {
			return errors.New("allinone: the controller ended before it ran")
		}
		return r.err
	}
}

// stop ends the controller and returns once it closed the database. For a hand-over it says
// goodbye with the reason restart and leaves the in-memory network closed.
func (h *ctlHolder) stop(handover bool) error {
	h.mu.Lock()
	r := h.cur
	h.mu.Unlock()
	if r == nil {
		return nil
	}
	if handover && r.handover.CompareAndSwap(false, true) {
		close(r.restart)
	}
	r.cancel()
	<-r.fin
	if handover {
		closed := memnet.NewListener()
		_ = closed.Close()
		h.mem.set(closed)
	}
	return r.err
}

// follower runs the loop that follows the gateway group's hostnames, which reads the database:
// a hand-over ends it with the controller and a resume starts it again.
type follower struct {
	run func(ctx context.Context)

	mu   sync.Mutex
	stop func()
}

func (f *follower) start(ctx context.Context) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stop != nil {
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); f.run(ctx) }()
	f.stop = func() { cancel(); <-done }
}

func (f *follower) end() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stop != nil {
		f.stop()
		f.stop = nil
	}
}
