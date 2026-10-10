// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
)

// The commands of an agent host (docs/16-cli.md): `rpmgr status`, `leave` and `diag`.

// localTimeout bounds each call of a command to the controller.
const localTimeout = 10 * time.Second

// Local is what `rpmgr status` reads on the host, without the running agent.
type Local struct {
	Loaded
	Snapshot *agentv1.Snapshot // the last-known-good snapshot; nil without one
	// SnapshotErr says why a stored snapshot does not verify.
	SnapshotErr error
	Denied      int // unexpired entries of the stored deny-list
	DenyErr     error
}

// ReadLocal reads the identity in identityDir and the agent's stored state in stateDir at now,
// verifying both as the agent does when it starts.
func ReadLocal(identityDir, stateDir string, now time.Time) (Local, error) {
	l, err := Load(identityDir)
	if err != nil {
		return Local{}, err
	}
	out := Local{Loaded: l}
	out.Snapshot, out.SnapshotErr = lastKnownGood(l, stateDir, now)
	d := NewDenyList(DenyListOptions{StateDir: stateDir, Root: l.Root, Signers: func() []*x509.Certificate { return l.Signing },
		Now: func() time.Time { return now }})
	out.DenyErr = d.Load()
	out.Denied = len(d.entries())
	return out, nil
}

// lastKnownGood reads and verifies the stored snapshot; nil, nil when there is none.
func lastKnownGood(l Loaded, stateDir string, now time.Time) (*agentv1.Snapshot, error) {
	b, err := os.ReadFile(filepath.Join(stateDir, LastKnownGoodFile)) //nolint:gosec // G304: the configured state directory
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	signed := &agentv1.Signed{}
	if err := proto.Unmarshal(b, signed); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadLastKnownGood, err)
	}
	return snapshot.VerifySnapshot(signed, l.Signing, l.Root, l.SPIFFE(), now)
}

// controllerConn connects to a controller endpoint as the agent, at SNI controller.<td>.
func controllerConn(l Loaded, endpoint string, dial func(ctx context.Context, addr string) (net.Conn, error)) (*grpc.ClientConn, error) {
	addr, err := dialAddr(endpoint)
	if err != nil {
		return nil, err
	}
	cfg := pki.ClientConfig(l.Certificate, l.Roots, "controller."+l.TrustDomain,
		pki.Expect{TrustDomain: l.TrustDomain, Kinds: []pki.Kind{pki.KindController}}, nil, nil)
	return grpc.NewClient("passthrough:///"+addr, append(dialOptions(dial), grpc.WithTransportCredentials(credentials.NewTLS(cfg)))...)
}

// ErrNotLeft is returned by Leave when no controller endpoint confirmed the revocation.
var ErrNotLeft = errors.New("agent: no controller confirmed the revocation; nothing was revoked or removed here")

// Leave is `rpmgr leave`: the controller revokes the agent's identity (Control.Leave), tried at
// each endpoint in turn, and only then are the identity in identityDir and the agent's stored
// snapshot and deny-list in stateDir removed (docs/03-connections.md, "Leaving"). It returns the
// identity that left.
func Leave(ctx context.Context, identityDir, stateDir string, dial func(ctx context.Context, addr string) (net.Conn, error)) (Loaded, error) {
	l, err := Load(identityDir)
	if err != nil {
		return Loaded{}, err
	}
	var errs []error
	left := false
	for _, ep := range l.Endpoints {
		cc, err := controllerConn(l, ep, dial)
		if err == nil {
			cctx, cancel := context.WithTimeout(ctx, localTimeout)
			_, err = agentv1.NewControlClient(cc).Leave(cctx, &agentv1.LeaveRequest{})
			cancel()
			_ = cc.Close()
		}
		if err == nil {
			left = true
			break
		}
		errs = append(errs, fmt.Errorf("%s: %w", ep, err))
	}
	if !left {
		return l, fmt.Errorf("%w: %w", ErrNotLeft, errors.Join(errs...))
	}
	for _, p := range []string{filepath.Join(identityDir, KeyFile), filepath.Join(identityDir, KeyFile+pending),
		filepath.Join(identityDir, ChainFile), filepath.Join(identityDir, ChainFile+pending), filepath.Join(identityDir, RootsFile),
		filepath.Join(identityDir, SigningFile), filepath.Join(identityDir, AgentFile),
		filepath.Join(stateDir, LastKnownGoodFile), filepath.Join(stateDir, DenyListFile)} {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return l, fmt.Errorf("agent: the identity is revoked, but %s is left: %w", p, err)
		}
	}
	return l, nil
}

// Clock is what `rpmgr diag clock` measured.
type Clock struct {
	Endpoint string
	RTT      time.Duration
	// Offset is the controller's clock minus this host's, at the middle of the round trip.
	Offset time.Duration
}

// MaxClockSkew is the clock offset above which agents warn (docs/03-connections.md, "Failure
// modes").
const MaxClockSkew = 30 * time.Second

// MeasureClock is `rpmgr diag clock`: it opens a control session at the first endpoint that
// answers and compares the server_time of its Welcome with this host's clock, then ends it. The
// controller keeps one session per agent, so a running agent's session is superseded and
// reconnects. A TLS refusal of the controller's certificate as expired or not yet valid is
// returned as it is: then this host's clock is far off.
func MeasureClock(ctx context.Context, identityDir, version string, now func() time.Time,
	dial func(ctx context.Context, addr string) (net.Conn, error)) (Clock, error) {
	l, err := Load(identityDir)
	if err != nil {
		return Clock{}, err
	}
	boot := make([]byte, 16)
	if _, err := rand.Read(boot); err != nil {
		return Clock{}, err
	}
	var errs []error
	for _, ep := range l.Endpoints {
		c, err := measure(ctx, l, ep, version, hex.EncodeToString(boot), now, dial)
		if err == nil {
			return c, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", ep, err))
	}
	return Clock{}, errors.Join(errs...)
}

func measure(ctx context.Context, l Loaded, ep, version, boot string, now func() time.Time,
	dial func(ctx context.Context, addr string) (net.Conn, error)) (Clock, error) {
	cc, err := controllerConn(l, ep, dial)
	if err != nil {
		return Clock{}, err
	}
	defer func() { _ = cc.Close() }()
	sctx, cancel := context.WithTimeout(ctx, localTimeout)
	defer cancel()
	st, err := agentv1.NewControlClient(cc).Session(sctx)
	if err != nil {
		return Clock{}, err
	}
	sent := now()
	if err := st.Send(&agentv1.AgentMessage{Msg: &agentv1.AgentMessage_Hello{Hello: &agentv1.Hello{Version: version, BootId: boot,
		AgentTime: timestamppb.New(sent)}}}); err != nil {
		return Clock{}, err
	}
	m, err := st.Recv()
	if err != nil {
		return Clock{}, err
	}
	got := now()
	w := m.GetWelcome()
	if w == nil {
		if g := m.GetGoodbye(); g != nil {
			return Clock{}, fmt.Errorf("the controller ended the session: %s", g.GetReason())
		}
		return Clock{}, errors.New("the controller did not answer with a Welcome")
	}
	rtt := got.Sub(sent)
	return Clock{Endpoint: ep, RTT: rtt, Offset: w.GetServerTime().AsTime().Sub(sent.Add(rtt / 2))}, nil
}
