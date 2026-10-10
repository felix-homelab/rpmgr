// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// Probe is one handshake of `rpmgr diag transport` to one tunnel endpoint of a gateway.
type Probe struct {
	Gateway, Endpoint string
	Transport         string        // TransportQUIC or TransportH2
	Handshake         time.Duration // until the session was up
	RTT               time.Duration // QUIC's smoothed round-trip time after the handshake
	Err               error
}

// Diagnosis is what `rpmgr diag transport` found (docs/10-operations.md, "UDP blocked or
// degraded").
type Diagnosis struct {
	Probes []Probe
	Tuning tunnel.Tuning // of the UDP socket the QUIC probes used
	// MTU is the MTU of the interface towards the first endpoint, which bounds the QUIC packet
	// size; Interface names it. Zero when it cannot be found.
	MTU       int
	Interface string
}

// Diagnose is `rpmgr diag transport`: with the connector's identity and its last-known-good
// configuration, it opens a QUIC and a TCP data session to every tunnel endpoint of the gateway
// gatewayID, or of every gateway without one, and closes each at once; it also reads the tuning of
// the UDP socket and the MTU towards the gateway. A running connector is not disturbed.
func Diagnose(ctx context.Context, identityDir, stateDir, gatewayID string, now func() time.Time) (Diagnosis, error) {
	l, err := agent.ReadLocal(identityDir, stateDir, now())
	if err != nil {
		return Diagnosis{}, err
	}
	if l.Kind != string(pki.KindConnector) {
		return Diagnosis{}, fmt.Errorf("connector: diag transport runs on a connector host; this is a %s's identity", l.Kind)
	}
	if l.Snapshot == nil {
		return Diagnosis{}, errors.Join(errors.New("connector: no configuration from the controller yet, so no gateway is known; start the connector first"), l.SnapshotErr)
	}
	if leaf := l.Certificate.Leaf; leaf == nil || len(leaf.URIs) != 1 {
		return Diagnosis{}, errors.New("connector: the certificate has no rpmgr identity")
	}
	own, err := pki.ParseSPIFFE(l.Certificate.Leaf.URIs[0], l.TrustDomain)
	if err != nil {
		return Diagnosis{}, err
	}
	endpoints := map[string][]string{}
	for _, res := range l.Snapshot.GetResources() {
		if g := res.GetConnectorGateway(); g != nil && (gatewayID == "" || res.GetId() == gatewayID) {
			endpoints[res.GetId()] = g.GetTunnelEndpoints()
		}
	}
	if len(endpoints) == 0 {
		return Diagnosis{}, fmt.Errorf("connector: the configuration names no gateway %q for this connector", gatewayID)
	}
	pc, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return Diagnosis{}, err
	}
	tr := &quic.Transport{Conn: pc}
	defer func() { _ = tr.Close(); _ = pc.Close() }()
	m := &Sessions{o: Options{QUIC: tr, Budget: tunnel.NewBudget(tunnel.DefaultWindowBudget)}}
	d := Diagnosis{Tuning: tunnel.TuningOf(pc)}
	for _, gw := range slices.Sorted(maps.Keys(endpoints)) {
		id := pki.Identity{TrustDomain: l.TrustDomain, Org: own.Org, Kind: pki.KindGateway, ID: gw}
		if err := id.Validate(); err != nil {
			return Diagnosis{}, err
		}
		cfg := pki.ClientConfig(l.Certificate, l.Roots, id.DNSName(), pki.Expect{TrustDomain: l.TrustDomain, Exact: &id}, now, nil)
		for _, ep := range endpoints[gw] {
			if d.Interface == "" {
				d.Interface, d.MTU = interfaceTowards(ctx, ep)
			}
			d.Probes = append(d.Probes, probe(ctx, gw, ep, TransportQUIC, func(ctx context.Context) (tunnel.Session, error) {
				return m.dialQUIC(ctx, ep, cfg)
			}, now), probe(ctx, gw, ep, TransportH2, func(ctx context.Context) (tunnel.Session, error) {
				return m.dialH2(ctx, ep, cfg)
			}, now))
		}
	}
	return d, nil
}

func probe(ctx context.Context, gw, ep, transport string, dial func(context.Context) (tunnel.Session, error), now func() time.Time) Probe {
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	p := Probe{Gateway: gw, Endpoint: ep, Transport: transport}
	start := now()
	s, err := dial(ctx)
	p.Handshake, p.Err = now().Sub(start), err
	if err == nil {
		if q, ok := s.(*tunnel.QUICSession); ok {
			p.RTT = q.RTT()
		}
		_ = s.Close()
	}
	return p
}

// interfaceTowards returns the interface the kernel picks to reach ep and its MTU.
func interfaceTowards(ctx context.Context, ep string) (string, int) {
	local, err := localAddr(ctx, ep)
	if err != nil {
		return "", 0
	}
	ifs, err := net.Interfaces()
	if err != nil {
		return "", 0
	}
	for _, ifc := range ifs {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.Equal(net.IP(local.AsSlice())) {
				return ifc.Name, ifc.MTU
			}
		}
	}
	return "", 0
}
