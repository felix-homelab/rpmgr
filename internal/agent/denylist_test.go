// SPDX-License-Identifier: Apache-2.0

package agent_test

import (
	"bytes"
	"crypto/x509"
	"errors"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
)

// denyEnv is a deny-list on a test CA with a clock the test moves.
type denyEnv struct {
	*rtEnv
	now time.Time
}

func newDenyEnv(t *testing.T) *denyEnv {
	return &denyEnv{rtEnv: newRTEnv(t), now: time.Now()}
}

func (e *denyEnv) list() *agent.DenyList {
	return agent.NewDenyList(agent.DenyListOptions{StateDir: e.stateDir, Root: e.root.Cert, Now: func() time.Time { return e.now },
		Signers: func() []*x509.Certificate { return []*x509.Certificate{e.config.Cert, e.inter.Cert} }})
}

func serial(s string, notAfter time.Time) *agentv1.DenyEntry {
	return &agentv1.DenyEntry{Subject: &agentv1.DenyEntry_Serial{Serial: s}, NotAfter: timestamppb.New(notAfter)}
}

func identity(s string, notAfter time.Time) *agentv1.DenyEntry {
	return &agentv1.DenyEntry{Subject: &agentv1.DenyEntry_Identity{Identity: s}, NotAfter: timestamppb.New(notAfter)}
}

func (e *denyEnv) signedList(t *testing.T, kp pki.KeyPair, epoch string, seq uint64, es ...*agentv1.DenyEntry) *agentv1.Signed {
	t.Helper()
	s, err := snapshot.Sign(kp, &agentv1.DenyList{Version: &agentv1.Revision{DbEpoch: epoch, Seq: seq}, Full: true, Entries: es})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// cert is a certificate with a serial and an identity, enough for Denied.
func cert(serialHex, spiffe string) *x509.Certificate {
	n, _ := new(big.Int).SetString(serialHex, 16)
	u, _ := url.Parse(spiffe)
	return &x509.Certificate{SerialNumber: n, URIs: []*url.URL{u}}
}

const idA, idB = "spiffe://rpmgr-7f3k2q6m/org/o/connector/con_a", "spiffe://rpmgr-7f3k2q6m/org/o/connector/con_b"

// TestDenyList_PersistedAcrossGatewayRestart (in-process clause; process level in 4.16): the
// stored deny-list is loaded before any session, without a controller; a list with a lower version
// or of a new database epoch never removes an unexpired entry; entries disappear after the
// covered certificate's NotAfter.
func TestDenyList_PersistedAcrossGatewayRestart(t *testing.T) {
	e := newDenyEnv(t)
	d := e.list()
	soon, later := e.now.Add(time.Hour), e.now.Add(48*time.Hour)
	if err := d.Apply(e.signedList(t, e.config, epoch1, 10, serial("a1", soon), identity(idA, later))); err != nil {
		t.Fatal(err)
	}
	// A lower version of a new epoch, as after a restore, without the earlier entries.
	if err := d.Apply(e.signedList(t, e.config, epoch2, 1, serial("b1", later))); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]*x509.Certificate{"serial a1": cert("a1", idB), "identity A": cert("ff", idA),
		"serial b1": cert("b1", idB)} {
		if !d.Denied(c) {
			t.Errorf("%s is not denied", name)
		}
	}
	if d.Denied(cert("c1", idB)) {
		t.Error("a certificate that is not on the list is denied")
	}
	want := pki.DenyDigest([]*agentv1.DenyEntry{serial("a1", soon), identity(idA, later), serial("b1", later)},
		snapshot.KeyID(e.config.Cert))
	if !bytes.Equal(d.Digest(), want) {
		t.Error("the digest is not that of the union")
	}

	// A restart, with no controller: the stored list is loaded.
	restarted := e.list()
	if err := restarted.Load(); err != nil {
		t.Fatal(err)
	}
	if !restarted.Denied(cert("a1", idB)) || !restarted.Denied(cert("ff", idA)) || !restarted.Denied(cert("b1", idB)) {
		t.Fatal("the restarted agent lost entries")
	}

	// After the first expiry only that entry is gone, and a restart then keeps only what is needed.
	e.now = soon.Add(time.Second)
	if restarted.Denied(cert("a1", idB)) || !restarted.Denied(cert("ff", idA)) {
		t.Fatal("expiry did not remove exactly the expired entry")
	}
	if err := restarted.Apply(e.signedList(t, e.config, epoch2, 2, serial("b1", later))); err != nil {
		t.Fatal(err)
	}
	again := e.list()
	if err := again.Load(); err != nil || !again.Denied(cert("ff", idA)) || !again.Denied(cert("b1", idB)) {
		t.Fatalf("after pruning and a restart: %v", err)
	}
	e.now = later.Add(time.Second)
	if again.Denied(cert("ff", idA)) || again.Digest() != nil {
		t.Fatal("entries outlived their expiry")
	}
}

// TestDenyList_Refused: a list that does not verify, that the audit-checkpoint key signed or whose
// entry lacks an expiry changes nothing.
func TestDenyList_Refused(t *testing.T) {
	e := newDenyEnv(t)
	d := e.list()
	later := e.now.Add(time.Hour)
	tampered := e.signedList(t, e.config, epoch1, 1, serial("a1", later))
	tampered.Payload[len(tampered.Payload)-1] ^= 1
	for name, s := range map[string]*agentv1.Signed{
		"tampered":   tampered,
		"audit key":  e.signedList(t, e.audit, epoch1, 1, serial("a1", later)),
		"no expiry":  e.signedList(t, e.config, epoch1, 1, &agentv1.DenyEntry{Subject: &agentv1.DenyEntry_Serial{Serial: "a1"}}),
		"no subject": e.signedList(t, e.config, epoch1, 1, &agentv1.DenyEntry{NotAfter: timestamppb.New(later)}),
	} {
		if err := d.Apply(s); err == nil {
			t.Errorf("%s: applied", name)
		}
	}
	if d.Denied(cert("a1", idA)) {
		t.Fatal("a refused list was applied")
	}
	if _, err := os.Stat(filepath.Join(e.stateDir, agent.DenyListFile)); !os.IsNotExist(err) {
		t.Fatal("a refused list was stored")
	}
}

// TestDenyList_DamagedFile: of a damaged file, the lists that verify are kept.
func TestDenyList_DamagedFile(t *testing.T) {
	e := newDenyEnv(t)
	d := e.list()
	later := e.now.Add(time.Hour)
	if err := d.Apply(e.signedList(t, e.config, epoch1, 1, serial("a1", later))); err != nil {
		t.Fatal(err)
	}
	if err := d.Apply(e.signedList(t, e.config, epoch2, 1, serial("b1", later))); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(e.stateDir, agent.DenyListFile)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// The newest list comes first; flip a byte of its signature region near its end.
	n := int(b[0]) + 1
	b[n-2] ^= 1
	if err := os.WriteFile(path, b, 0o600); err != nil { //nolint:gosec // G703: the test's own directory
		t.Fatal(err)
	}
	loaded := e.list()
	if err := loaded.Load(); !errors.Is(err, agent.ErrBadDenyList) {
		t.Fatalf("a damaged list: %v", err)
	}
	if !loaded.Denied(cert("a1", idA)) || loaded.Denied(cert("b1", idA)) {
		t.Fatal("not exactly the list that verifies was kept")
	}
	if err := os.WriteFile(path, append(b[:n], 0xff, 0xff, 0xff), 0o600); err != nil { //nolint:gosec // G703: the test's own directory
		t.Fatal(err)
	}
	if err := e.list().Load(); !errors.Is(err, agent.ErrBadDenyList) {
		t.Fatalf("a truncated file: %v", err)
	}
	if err := agent.NewDenyList(agent.DenyListOptions{StateDir: t.TempDir()}).Load(); err != nil {
		t.Fatalf("no stored list: %v", err)
	}
}
