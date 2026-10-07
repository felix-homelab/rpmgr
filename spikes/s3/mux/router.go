// SPDX-License-Identifier: Apache-2.0

package mux

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"time"
)

// ALPN identifiers (docs/03-connections.md, "Versioning and capabilities").
const (
	ALPNTunnelH2   = "rpmgr-tunnel-h2/1"
	ALPNTunnelQUIC = "rpmgr-tunnel/1"
)

// Decision is the router's action for one TCP/443 connection (docs/03, "Port 443 multiplexing").
type Decision string

// Decisions, one per row of the routing table in docs/03 plus the peek failures.
const (
	DecideController  Decision = "controller"       // controller.<td>, reauth.controller.<td>, UI hostnames
	DecideTunnelH2    Decision = "tunnel-h2"        // <this-gateway>.gateway.<td> + ALPN rpmgr-tunnel-h2/1
	DecidePassthrough Decision = "passthrough"      // SNI of a TLS-passthrough route
	DecideHTTP        Decision = "http"             // SNI of an http route hostname
	DecideDefault     Decision = "default-close"    // no SNI or unknown SNI
	DecideNotTLS      Decision = "close-not-tls"    // first bytes are not a TLS handshake record
	DecidePeekFailed  Decision = "close-peek-error" // timeout, oversize or malformed ClientHello
)

// Event records one routing decision; the spike writes them as JSON lines.
type Event struct {
	Time           time.Time `json:"time"`
	Listener       string    `json:"listener"`
	Remote         string    `json:"remote"`
	Decision       Decision  `json:"decision"`
	SNI            string    `json:"sni,omitempty"`
	ALPN           []string  `json:"alpn,omitempty"`
	HelloSize      int       `json:"hello_size,omitempty"`
	Records        int       `json:"records,omitempty"`
	Reads          int       `json:"reads,omitempty"`
	RawBytes       int       `json:"raw_bytes,omitempty"`
	KeyShareGroups []string  `json:"key_share_groups,omitempty"`
	KeyShareBytes  int       `json:"key_share_bytes,omitempty"`
	ECH            bool      `json:"ech,omitempty"`
	PeekMicros     int64     `json:"peek_us"`
	Error          string    `json:"error,omitempty"`
}

// Router is the gateway's TCP/443 multiplexer.
type Router struct {
	TrustDomain   string   // <td>
	GatewayID     string   // this gateway's ID; its tunnel name is <id>.gateway.<td>
	ControllerUI  []string // public UI hostnames of the in-process controller (all-in-one)
	Passthrough   map[string]string
	HTTPHostnames map[string]bool

	Controller func(c net.Conn)      // all-in-one: in-process controller, still TLS-encrypted
	Tunnel     func(c *tls.Conn)     // data session over TLS + reverse HTTP/2
	HTTP       func(c *tls.Conn)     // HTTP engine
	TunnelTLS  *tls.Config           // gateway certificate, client certificates required
	HTTPTLS    *tls.Config           // per-SNI certificates via GetConfigForClient
	DefaultTLS *tls.Config           // default certificate for unknown or missing SNI
	OnEvent    func(Event)           // optional
	Dial       func(addr string) (net.Conn, error)

	MaxPeek     int
	PeekTimeout time.Duration
	Name        string

	wg sync.WaitGroup
}

// Serve accepts connections until l is closed.
func (r *Router) Serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				r.wg.Wait()
				return nil
			}
			return err
		}
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.Handle(c)
		}()
	}
}

// Decide applies the routing table to a peeked ClientHello.
func (r *Router) Decide(ch *ClientHello) Decision {
	sni := strings.ToLower(strings.TrimSuffix(ch.ServerName, "."))
	td := strings.ToLower(r.TrustDomain)
	switch {
	case sni == "":
		return DecideDefault
	case sni == "controller."+td || sni == "reauth.controller."+td || slices.Contains(r.ControllerUI, sni):
		return DecideController
	case strings.HasSuffix(sni, ".gateway."+td):
		// Only this gateway's own name, and only with the tunnel ALPN. Another gateway's name
		// could not be served anyway: the connector checks the name and the SPIFFE ID.
		if sni == r.GatewayID+".gateway."+td && slices.Contains(ch.ALPN, ALPNTunnelH2) {
			return DecideTunnelH2
		}
		return DecideDefault
	case r.Passthrough[sni] != "":
		return DecidePassthrough
	case r.HTTPHostnames[sni]:
		return DecideHTTP
	default:
		return DecideDefault
	}
}

// Handle peeks at one connection, decides and hands it over.
func (r *Router) Handle(c net.Conn) {
	start := time.Now()
	ev := Event{Time: start, Listener: r.Name, Remote: c.RemoteAddr().String()}
	ch, err := Peek(c, r.maxPeek(), r.peekTimeout())
	ev.PeekMicros = time.Since(start).Microseconds()
	if err != nil {
		ev.Decision = DecidePeekFailed
		if errors.Is(err, ErrNotTLS) {
			ev.Decision = DecideNotTLS
		}
		ev.Error = err.Error()
		r.emit(ev)
		_ = c.Close()
		return
	}
	ev.SNI, ev.ALPN, ev.HelloSize, ev.Records, ev.Reads = ch.ServerName, ch.ALPN, ch.Size, ch.Records, ch.Reads
	ev.RawBytes, ev.KeyShareBytes, ev.ECH = len(ch.Raw), ch.KeyShareBytes, ch.ECH
	for _, g := range ch.KeyShareGroups {
		ev.KeyShareGroups = append(ev.KeyShareGroups, GroupName(g))
	}
	ev.Decision = r.Decide(ch)
	r.emit(ev)

	rc := NewReplayConn(c, ch.Raw)
	switch ev.Decision {
	case DecideController:
		r.Controller(rc)
	case DecideTunnelH2:
		r.Tunnel(tls.Server(rc, r.TunnelTLS))
	case DecidePassthrough:
		r.splice(rc, r.Passthrough[strings.ToLower(ch.ServerName)])
	case DecideHTTP:
		r.HTTP(tls.Server(rc, r.HTTPTLS))
	default:
		// Complete the handshake with the default certificate, then close: there is no
		// fallback route (D31).
		tc := tls.Server(rc, r.DefaultTLS)
		_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
		_ = tc.Handshake()
		_ = tc.Close()
	}
}

func (r *Router) splice(client *ReplayConn, backend string) {
	dial := r.Dial
	if dial == nil {
		dial = func(addr string) (net.Conn, error) { return net.DialTimeout("tcp", addr, 5*time.Second) }
	}
	up, err := dial(backend)
	if err != nil {
		_ = client.Close()
		return
	}
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite() // half-close preserved
		} else {
			_ = dst.Close()
		}
		done <- struct{}{}
	}
	go cp(up, client) // replays the recorded ClientHello first
	go cp(client, up)
	<-done
	<-done
	_ = up.Close()
	_ = client.Close()
}

func (r *Router) emit(ev Event) {
	if r.OnEvent != nil {
		r.OnEvent(ev)
	}
}

func (r *Router) maxPeek() int {
	if r.MaxPeek > 0 {
		return r.MaxPeek
	}
	return MaxPeekBytes
}

func (r *Router) peekTimeout() time.Duration {
	if r.PeekTimeout > 0 {
		return r.PeekTimeout
	}
	return PeekTimeout
}

// GroupName names the TLS key-exchange groups the spike reports.
func GroupName(g uint16) string {
	switch g {
	case 0x001d:
		return "X25519"
	case 0x0017:
		return "P-256"
	case 0x0018:
		return "P-384"
	case 0x0019:
		return "P-521"
	case 0x11ec:
		return "X25519MLKEM768"
	case 0x11eb:
		return "SecP256r1MLKEM768"
	case 0x11ed:
		return "SecP384r1MLKEM1024"
	case 0x0200:
		return "MLKEM512"
	case 0x0201:
		return "MLKEM768"
	case 0x0202:
		return "MLKEM1024"
	}
	if g&0x0f0f == 0x0a0a {
		return "GREASE"
	}
	return fmt.Sprintf("0x%04x", g)
}

// SPIFFEFromChain returns the single SPIFFE URI SAN of a verified peer leaf.
func SPIFFEFromChain(chains [][]*x509.Certificate) (string, error) {
	if len(chains) == 0 || len(chains[0]) == 0 {
		return "", errors.New("no verified chain")
	}
	leaf := chains[0][0]
	if len(leaf.URIs) != 1 || leaf.URIs[0].Scheme != "spiffe" {
		return "", errors.New("peer certificate has no single SPIFFE URI SAN")
	}
	return leaf.URIs[0].String(), nil
}
