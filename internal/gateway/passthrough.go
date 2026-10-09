// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
)

// PassthroughRoute is a tls_passthrough route as the gateway serves it, from its snapshot.
type PassthroughRoute struct {
	ID        string
	Hostnames []string // normalised; one may start with "*." for every name one label below
	// Access is who may connect.
	Access Access
}

// Passthrough serves the gateway's tls_passthrough routes on port 443 (docs/03-connections.md,
// "TLS passthrough routes"): the router asks it for the route of a ClientHello's SNI, and the
// connection, still encrypted and with the ClientHello replayed, goes over a stream to a connector
// of the route. It implements Routes; http routes come later. Connections of a removed route are
// reset after the route drain period.
type Passthrough struct {
	sessions *Sessions
	revision func() *agentv1.Revision
	logger   *slog.Logger
	ctx      context.Context
	cancel   context.CancelFunc

	table  atomic.Pointer[map[string]string] // hostname → route ID
	access atomic.Pointer[map[string]Access] // route ID → who may connect

	mu      sync.Mutex
	conns   map[string]map[net.Conn]struct{} // route ID → open connections
	removal removalDrain
}

// NewPassthrough returns the tls_passthrough routes over sessions; Close resets their
// connections.
func NewPassthrough(sessions *Sessions, revision func() *agentv1.Revision, logger *slog.Logger) *Passthrough {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &Passthrough{sessions: sessions, revision: revision, logger: logger, ctx: ctx, cancel: cancel,
		conns: map[string]map[net.Conn]struct{}{}}
	empty := map[string]string{}
	p.table.Store(&empty)
	none := map[string]Access{}
	p.access.Store(&none)
	return p
}

// Apply makes routes the served ones in one swap; the connections of a route no longer among them
// are reset after the route drain period.
func (p *Passthrough) Apply(routes []PassthroughRoute) {
	next := map[string]string{}
	access := map[string]Access{}
	for _, r := range routes {
		for _, h := range r.Hostnames {
			next[h] = r.ID
		}
		access[r.ID] = r.Access
	}
	old := *p.table.Load()
	oldAccess := *p.access.Swap(&access)
	p.table.Store(&next)
	for id, a := range access {
		if !oldAccess[id].Same(a) {
			p.enforce(id, a)
		}
	}
	removed := map[string]bool{}
	for _, id := range old {
		removed[id] = true
	}
	for _, id := range next {
		delete(removed, id)
	}
	for id := range removed {
		time.AfterFunc(p.removal.period(), func() { p.abortRoute(id) })
	}
}

// SetRemovalDrain sets how long the connections of a route removed from now on stay open; 0 is
// the route drain period.
func (p *Passthrough) SetRemovalDrain(d time.Duration) { p.removal.Store(int64(d)) }

func (p *Passthrough) abortRoute(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, served := func() (string, bool) {
		for _, rid := range *p.table.Load() {
			if rid == id {
				return rid, true
			}
		}
		return "", false
	}(); served {
		return // added back meanwhile
	}
	for c := range p.conns[id] {
		abort(c)
	}
}

// route returns the route of a lower-case SNI: its exact hostname, else the wildcard one label up.
func (p *Passthrough) route(sni string) (string, bool) {
	t := *p.table.Load()
	if id, ok := t[sni]; ok {
		return id, true
	}
	if i := strings.IndexByte(sni, '.'); i > 0 {
		if id, ok := t["*"+sni[i:]]; ok {
			return id, true
		}
	}
	return "", false
}

// Passthrough implements Routes.
func (p *Passthrough) Passthrough(sni string) (func(net.Conn), bool) {
	id, ok := p.route(sni)
	if !ok {
		return nil, false
	}
	return func(c net.Conn) { p.handle(c, id, sni) }, true
}

// HTTP implements Routes: http routes are not served yet.
func (p *Passthrough) HTTP(string) bool { return false }

// enforce resets the connections of a route that its new access rules no longer allow.
func (p *Passthrough) enforce(id string, a Access) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for c := range p.conns[id] {
		if !a.AllowsAddr(c.RemoteAddr()) {
			abort(c)
		}
	}
}

func (p *Passthrough) handle(c net.Conn, id, sni string) {
	if !(*p.access.Load())[id].AllowsAddr(c.RemoteAddr()) {
		abort(c)
		return
	}
	p.mu.Lock()
	if p.conns[id] == nil {
		p.conns[id] = map[net.Conn]struct{}{}
	}
	p.conns[id][c] = struct{}{}
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		delete(p.conns[id], c)
		if len(p.conns[id]) == 0 {
			delete(p.conns, id)
		}
		p.mu.Unlock()
	}()
	carry(p.ctx, p.sessions, p.revision, p.logger, c, id, sni, 0)
}

// Conns returns the number of open passthrough connections.
func (p *Passthrough) Conns() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, cs := range p.conns {
		n += len(cs)
	}
	return n
}

// Close resets every connection.
func (p *Passthrough) Close() {
	p.cancel()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, cs := range p.conns {
		for c := range cs {
			abort(c)
		}
	}
}
