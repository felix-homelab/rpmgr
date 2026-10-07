// SPDX-License-Identifier: Apache-2.0

package agent_test

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
)

const epoch1, epoch2 = "0192f0aa-0000-7000-8000-000000000001", "0192f0aa-0000-7000-8000-000000000002"

// rtEnv is a test CA with its signing keys and an agent identity.
type rtEnv struct {
	root, inter, config, audit, nextConfig pki.KeyPair
	id                                     agent.Loaded
	stateDir                               string
	is                                     *pki.Issuer
	ident                                  pki.Identity
}

func newRTEnv(t *testing.T) *rtEnv {
	t.Helper()
	const td = "rpmgr-7f3k2q6m"
	now := time.Now()
	e := &rtEnv{stateDir: t.TempDir()}
	var err error
	if e.root, err = pki.NewRoot(td, now); err != nil {
		t.Fatal(err)
	}
	if e.inter, err = pki.NewIntermediate(e.root, now); err != nil {
		t.Fatal(err)
	}
	is, err := pki.NewIssuer(e.root.Cert, e.inter, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []struct {
		p   pki.Purpose
		dst *pki.KeyPair
	}{{pki.PurposeConfigSigning, &e.config}, {pki.PurposeAuditCheckpoint, &e.audit}, {pki.PurposeConfigSigning, &e.nextConfig}} {
		key, err := pki.NewKey()
		if err != nil {
			t.Fatal(err)
		}
		cert, err := is.IssueSigner(&key.PublicKey, s.p)
		if err != nil {
			t.Fatal(err)
		}
		*s.dst = pki.KeyPair{Cert: cert, Key: key}
	}
	key, err := pki.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	csr, _ := x509.ParseCertificateRequest(der)
	e.is, e.ident = is, pki.Identity{TrustDomain: td, Org: ids.New("org"), Kind: pki.KindConnector, ID: ids.New("con")}
	leaf, err := is.IssueLeaf(csr, e.ident, pki.DefaultLeafLifetime)
	if err != nil {
		t.Fatal(err)
	}
	e.id = agent.Loaded{Dir: t.TempDir(), Root: e.root.Cert, Signing: []*x509.Certificate{e.config.Cert, e.inter.Cert},
		Certificate: tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf}}
	return e
}

// res is a resource with its hash.
func res(t *testing.T, id string, size uint64) *agentv1.Resource {
	t.Helper()
	r := &agentv1.Resource{Id: id, Kind: &agentv1.Resource_Reference{Reference: &agentv1.ResourceReference{Size: size}}}
	h, err := snapshot.ResourceHash(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Hash = h
	return r
}

// signed signs a snapshot for the env's agent with kp.
func (e *rtEnv) signed(t *testing.T, kp pki.KeyPair, ep string, seq uint64, rs ...*agentv1.Resource) *agentv1.Signed {
	t.Helper()
	s, err := snapshot.Sign(kp, &agentv1.Snapshot{Revision: &agentv1.Revision{DbEpoch: ep, Seq: seq}, Agent: e.id.SPIFFE(),
		ControllerEndpoints: []string{"https://ctl.example"}, Resources: rs})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// fakeApplier records what it is asked to apply and refuses resources named "bad".
type fakeApplier struct {
	mu      sync.Mutex
	applied []agent.Changes
	seqs    []uint64
	block   chan struct{} // if set, Apply waits for it
	started chan struct{}
}

func (f *fakeApplier) Validate(snap *agentv1.Snapshot) []*agentv1.SnapshotError {
	var errs []*agentv1.SnapshotError
	for _, r := range snap.GetResources() {
		if r.GetId() == "bad" {
			errs = append(errs, &agentv1.SnapshotError{ResourceId: "bad", Message: "not valid"})
		}
	}
	return errs
}

func (f *fakeApplier) Apply(_ context.Context, snap *agentv1.Snapshot, c agent.Changes) []*agentv1.ResourceStatus {
	if f.started != nil {
		f.started <- struct{}{}
	}
	if f.block != nil {
		<-f.block
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applied = append(f.applied, c)
	f.seqs = append(f.seqs, snap.GetRevision().GetSeq())
	return []*agentv1.ResourceStatus{{ResourceId: "rt_1", Detail: "test"}}
}

func (f *fakeApplier) appliedSeqs() []uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.seqs)
}

// runtime starts a runtime whose answers go to the returned channel.
func (e *rtEnv) runtime(t *testing.T, f *fakeApplier) (*agent.Runtime, chan *agentv1.AgentMessage) {
	t.Helper()
	out := make(chan *agentv1.AgentMessage, 16)
	rt := agent.NewRuntime(agent.RuntimeOptions{Identity: e.id, StateDir: e.stateDir, Applier: f,
		Send: func(m *agentv1.AgentMessage) bool { out <- m; return true }})
	rt.Welcome(&agentv1.Welcome{DbEpoch: epoch1})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { rt.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return rt, out
}

func offer(rt *agent.Runtime, s *agentv1.Signed) {
	rt.Message(&agentv1.ControllerMessage{Msg: &agentv1.ControllerMessage_Snapshot{Snapshot: s}})
}

func answer(t *testing.T, out chan *agentv1.AgentMessage) *agentv1.AgentMessage {
	t.Helper()
	select {
	case m := <-out:
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("no answer")
		return nil
	}
}

func quiet(t *testing.T, out chan *agentv1.AgentMessage) {
	t.Helper()
	select {
	case m := <-out:
		t.Fatalf("unexpected answer %v", m)
	case <-time.After(100 * time.Millisecond):
	}
}

func lkg(t *testing.T, e *rtEnv) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(e.stateDir, agent.LastKnownGoodFile))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestBadSnapshotKeepsLastKnownGood (framework clause; traffic in 4.13): a snapshot that is invalid,
// badly signed or signed by a key that is not a config-signing key is rejected as a whole; the
// agent keeps running the last applied snapshot, keeps its copy on disk, and loads it after a
// restart.
func TestBadSnapshotKeepsLastKnownGood(t *testing.T) {
	e := newRTEnv(t)
	f := &fakeApplier{}
	rt, out := e.runtime(t, f)
	good := e.signed(t, e.config, epoch1, 1, res(t, "rt_1", 1))
	offer(rt, good)
	a := answer(t, out).GetApplied()
	if a == nil || a.GetRevision().GetSeq() != 1 || !slices.Equal(a.GetHash(), snapshot.Hash(good)) || len(a.GetNotReady()) != 1 {
		t.Fatalf("answer to a good snapshot: %v", a)
	}
	stored := lkg(t, e)

	tampered := e.signed(t, e.config, epoch1, 3, res(t, "rt_1", 2))
	tampered.Signature[len(tampered.Signature)-1] ^= 1
	// The audit-checkpoint key, even when a Welcome lists its certificate as a signer.
	rt.Welcome(&agentv1.Welcome{DbEpoch: epoch1, SigningCertificates: [][]byte{e.config.Cert.Raw, e.audit.Cert.Raw, e.inter.Cert.Raw}})
	for name, bad := range map[string]*agentv1.Signed{
		"invalid resource":   e.signed(t, e.config, epoch1, 2, res(t, "rt_1", 1), res(t, "bad", 1)),
		"tampered signature": tampered,
		"audit key":          e.signed(t, e.audit, epoch1, 4, res(t, "rt_1", 2)),
		"unknown key":        e.signed(t, newRTEnv(t).config, epoch1, 5, res(t, "rt_1", 2)),
	} {
		offer(rt, bad)
		r := answer(t, out).GetRejected()
		if r == nil || len(r.GetErrors()) == 0 || !slices.Equal(r.GetHash(), snapshot.Hash(bad)) {
			t.Fatalf("%s: answer %v, want Rejected", name, r)
		}
	}
	if got := f.appliedSeqs(); !slices.Equal(got, []uint64{1}) {
		t.Fatalf("applied %v, want only revision 1", got)
	}
	if !slices.Equal(lkg(t, e), stored) {
		t.Fatal("a rejected snapshot replaced the last-known-good copy")
	}
	h := &agentv1.Hello{}
	rt.Hello(h)
	if h.GetLastApplied().GetSeq() != 1 || !slices.Equal(h.GetLastAppliedHash(), snapshot.Hash(good)) {
		t.Fatalf("Hello after rejections: %v", h)
	}

	// A restart loads the last-known-good copy before any session.
	f2 := &fakeApplier{}
	rt2 := agent.NewRuntime(agent.RuntimeOptions{Identity: e.id, StateDir: e.stateDir, Applier: f2})
	if err := rt2.LoadLastKnownGood(context.Background()); err != nil {
		t.Fatal(err)
	}
	h = &agentv1.Hello{}
	rt2.Hello(h)
	if !slices.Equal(f2.appliedSeqs(), []uint64{1}) || h.GetLastApplied().GetSeq() != 1 {
		t.Fatalf("after a restart: applied %v, Hello %v", f2.appliedSeqs(), h)
	}
}

// TestRuntime_TamperedLastKnownGood: a copy that does not verify is not applied.
func TestRuntime_TamperedLastKnownGood(t *testing.T) {
	e := newRTEnv(t)
	other := newRTEnv(t)
	good, err := proto.Marshal(e.signed(t, e.config, epoch1, 1, res(t, "rt_1", 1)))
	if err != nil {
		t.Fatal(err)
	}
	flipped := slices.Clone(good)
	flipped[len(flipped)/2] ^= 1
	forOther, _ := proto.Marshal(other.signed(t, e.config, epoch1, 1)) // signed by the right key, for another agent
	invalid, _ := proto.Marshal(e.signed(t, e.config, epoch1, 1, res(t, "bad", 1)))
	for name, b := range map[string][]byte{"flipped byte": flipped, "garbage": []byte("not a snapshot"),
		"another agent": forOther, "invalid": invalid} {
		if err := os.WriteFile(filepath.Join(e.stateDir, agent.LastKnownGoodFile), b, 0o600); err != nil {
			t.Fatal(err)
		}
		f := &fakeApplier{}
		rt := agent.NewRuntime(agent.RuntimeOptions{Identity: e.id, StateDir: e.stateDir, Applier: f})
		if err := rt.LoadLastKnownGood(context.Background()); !errors.Is(err, agent.ErrBadLastKnownGood) {
			t.Errorf("%s: %v, want ErrBadLastKnownGood", name, err)
		}
		h := &agentv1.Hello{}
		rt.Hello(h)
		if len(f.appliedSeqs()) != 0 || h.GetLastApplied() != nil {
			t.Errorf("%s: a bad copy was applied", name)
		}
	}
	// No copy is no error.
	rt := agent.NewRuntime(agent.RuntimeOptions{Identity: e.id, StateDir: t.TempDir(), Applier: &fakeApplier{}})
	if err := rt.LoadLastKnownGood(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// TestRuntime_Revisions: a snapshot that is not newer is ignored; a new database epoch is accepted
// only once a Welcome announced it; the snapshot already running is acknowledged again.
func TestRuntime_Revisions(t *testing.T) {
	e := newRTEnv(t)
	f := &fakeApplier{}
	rt, out := e.runtime(t, f)
	s5 := e.signed(t, e.config, epoch1, 5)
	offer(rt, s5)
	answer(t, out)

	offer(rt, e.signed(t, e.config, epoch1, 4))
	quiet(t, out)
	offer(rt, e.signed(t, e.config, epoch1, 5, res(t, "rt_1", 1))) // same revision, other content
	quiet(t, out)
	offer(rt, e.signed(t, e.config, epoch2, 1)) // a new epoch, not announced
	quiet(t, out)

	offer(rt, s5) // the controller missed the answer
	if a := answer(t, out).GetApplied(); a.GetRevision().GetSeq() != 5 {
		t.Fatalf("re-acknowledgement: %v", a)
	}

	rt.Welcome(&agentv1.Welcome{DbEpoch: epoch2})
	offer(rt, e.signed(t, e.config, epoch2, 1))
	if a := answer(t, out).GetApplied(); a.GetRevision().GetDbEpoch() != epoch2 || a.GetRevision().GetSeq() != 1 {
		t.Fatalf("a lower revision of the announced epoch: %v", a)
	}
	if got := f.appliedSeqs(); !slices.Equal(got, []uint64{5, 1}) {
		t.Fatalf("applied %v", got)
	}
}

// TestRuntime_LatestWins: of the snapshots that arrive while one is applied, only the newest is
// applied next.
func TestRuntime_LatestWins(t *testing.T) {
	e := newRTEnv(t)
	f := &fakeApplier{block: make(chan struct{}), started: make(chan struct{}, 4)}
	rt, out := e.runtime(t, f)
	offer(rt, e.signed(t, e.config, epoch1, 1))
	<-f.started
	offer(rt, e.signed(t, e.config, epoch1, 2))
	offer(rt, e.signed(t, e.config, epoch1, 3))
	f.block <- struct{}{}
	<-f.started
	f.block <- struct{}{}
	answer(t, out)
	if a := answer(t, out).GetApplied(); a.GetRevision().GetSeq() != 3 {
		t.Fatalf("applied %v next, want 3", a)
	}
	if got := f.appliedSeqs(); !slices.Equal(got, []uint64{1, 3}) {
		t.Fatalf("applied %v, want [1 3]", got)
	}
}

// TestRuntime_Changes: resources are compared by hash; unchanged ones are reported as such.
func TestRuntime_Changes(t *testing.T) {
	e := newRTEnv(t)
	f := &fakeApplier{}
	var endpoints []string
	out := make(chan *agentv1.AgentMessage, 4)
	rt := agent.NewRuntime(agent.RuntimeOptions{Identity: e.id, StateDir: e.stateDir, Applier: f,
		Send: func(m *agentv1.AgentMessage) bool { out <- m; return true }, OnEndpoints: func(eps []string) { endpoints = eps }})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { rt.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	offer(rt, e.signed(t, e.config, epoch1, 1, res(t, "a", 1), res(t, "b", 1), res(t, "c", 1)))
	answer(t, out)
	offer(rt, e.signed(t, e.config, epoch1, 2, res(t, "a", 1), res(t, "b", 2), res(t, "d", 1)))
	answer(t, out)
	f.mu.Lock()
	c := f.applied[1]
	f.mu.Unlock()
	if !slices.Equal(c.Unchanged, []string{"a"}) || !slices.Equal(c.Changed, []string{"b"}) ||
		!slices.Equal(c.Added, []string{"d"}) || !slices.Equal(c.Removed, []string{"c"}) {
		t.Fatalf("changes %+v", c)
	}
	if !slices.Equal(endpoints, []string{"https://ctl.example"}) {
		t.Fatalf("endpoints %v", endpoints)
	}
}

// TestRuntime_ResourceChecks: a resource whose hash does not match its content, a duplicate ID or
// an empty ID rejects the snapshot before the role sees it.
func TestRuntime_ResourceChecks(t *testing.T) {
	e := newRTEnv(t)
	f := &fakeApplier{}
	rt, out := e.runtime(t, f)
	wrongHash := res(t, "rt_1", 1)
	wrongHash.Hash = res(t, "rt_1", 2).GetHash()
	for name, rs := range map[string][]*agentv1.Resource{
		"wrong hash": {wrongHash},
		"duplicate":  {res(t, "rt_1", 1), res(t, "rt_1", 1)},
		"empty ID":   {res(t, "", 1)},
	} {
		offer(rt, e.signed(t, e.config, epoch1, 1, rs...))
		if r := answer(t, out).GetRejected(); r == nil {
			t.Errorf("%s: not rejected", name)
		}
	}
	if len(f.appliedSeqs()) != 0 {
		t.Fatal("the role saw an invalid snapshot")
	}
}

// TestRuntime_NextSigningKey: a Welcome's signing certificates let the agent verify a snapshot
// signed by the next key, and are stored for the next start.
func TestRuntime_NextSigningKey(t *testing.T) {
	e := newRTEnv(t)
	f := &fakeApplier{}
	rt, out := e.runtime(t, f)
	next := e.signed(t, e.nextConfig, epoch1, 1)
	offer(rt, next)
	if answer(t, out).GetRejected() == nil {
		t.Fatal("a snapshot of an unknown key was applied")
	}
	rt.Welcome(&agentv1.Welcome{DbEpoch: epoch1, SigningCertificates: [][]byte{e.config.Cert.Raw, e.nextConfig.Cert.Raw, e.inter.Cert.Raw}})
	offer(rt, e.signed(t, e.nextConfig, epoch1, 2))
	if answer(t, out).GetApplied() == nil {
		t.Fatal("a snapshot of the next key was not applied")
	}
	l, err := os.ReadFile(filepath.Join(e.id.Dir, agent.SigningFile))
	if err != nil || len(l) == 0 {
		t.Fatalf("signing certificates not stored: %v", err)
	}
	// A Welcome with a certificate that does not parse changes nothing.
	rt.Welcome(&agentv1.Welcome{DbEpoch: epoch1, SigningCertificates: [][]byte{[]byte("junk")}})
	offer(rt, e.signed(t, e.nextConfig, epoch1, 3))
	if answer(t, out).GetApplied() == nil {
		t.Fatal("a bad Welcome replaced the signing certificates")
	}
}

// TestRuntime_PersistFailure: a copy that cannot be stored does not stop the snapshot from being
// applied and acknowledged.
func TestRuntime_PersistFailure(t *testing.T) {
	e := newRTEnv(t)
	e.stateDir = filepath.Join(t.TempDir(), "missing")
	f := &fakeApplier{}
	rt, out := e.runtime(t, f)
	offer(rt, e.signed(t, e.config, epoch1, 1))
	if answer(t, out).GetApplied() == nil {
		t.Fatal("not acknowledged")
	}
}
