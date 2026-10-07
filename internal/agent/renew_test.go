// SPDX-License-Identifier: Apache-2.0

package agent_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/agent"
	"github.com/felix-homelab/rpmgr/internal/pki"
)

// TestRenewAt: the renewal falls within 45–55 % of the lifetime.
func TestRenewAt(t *testing.T) {
	nb := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
	leaf := &x509.Certificate{NotBefore: nb, NotAfter: nb.Add(100 * time.Hour)}
	for _, tt := range []struct {
		jitter float64
		want   time.Duration
	}{{0, 45 * time.Hour}, {0.5, 50 * time.Hour}, {0.999999, 55 * time.Hour}} {
		got := agent.RenewAt(leaf, tt.jitter).Sub(nb)
		if (got - tt.want).Abs() > time.Second {
			t.Errorf("jitter %v: after %v, want %v", tt.jitter, got, tt.want)
		}
	}
}

// TestSaveCertificate: a renewed key and chain replace the current ones; a start between the two
// moves of SaveCertificate finishes the second; a pending chain that matches nothing changes
// nothing.
func TestSaveCertificate(t *testing.T) {
	e := newRTEnv(t)
	dir := enrolledDir(t, e)
	key, chain := e.issue(t)
	if err := agent.SaveCertificate(dir, key, chain); err != nil {
		t.Fatal(err)
	}
	l, err := agent.Load(dir)
	if err != nil || !key.PublicKey.Equal(l.Certificate.Leaf.PublicKey) {
		t.Fatalf("after SaveCertificate: %v", err)
	}
	if st, err := os.Stat(filepath.Join(dir, agent.KeyFile)); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode: %v %v", st.Mode(), err)
	}

	// Interrupted after the key was moved: the new key beside the old chain, the new chain pending.
	key2, chain2 := e.issue(t)
	if err := agent.SaveCertificate(dir, key2, chain2); err != nil {
		t.Fatal(err)
	}
	newChain, _ := os.ReadFile(filepath.Join(dir, agent.ChainFile))
	if err := os.WriteFile(filepath.Join(dir, agent.ChainFile+".new"), newChain, 0o644); err != nil { //nolint:gosec // G703: the test's own directory
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, agent.ChainFile), pemChain(chain), 0o644); err != nil {
		t.Fatal(err)
	}
	l, err = agent.Load(dir)
	if err != nil || !key2.PublicKey.Equal(l.Certificate.Leaf.PublicKey) {
		t.Fatalf("after an interrupted save: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, agent.ChainFile+".new")); !os.IsNotExist(err) {
		t.Fatal("the pending chain was not moved into place")
	}

	// A pending chain for another key does not rescue a mismatched pair.
	if err := os.WriteFile(filepath.Join(dir, agent.ChainFile+".new"), pemChain(chain), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, agent.ChainFile), pemChain(chain), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.Load(dir); err == nil {
		t.Fatal("a key and chain that do not match were loaded")
	}
}

// issue returns a new key and a chain for the env's agent.
func (e *rtEnv) issue(t *testing.T) (*ecdsa.PrivateKey, [][]byte) {
	t.Helper()
	key, err := pki.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	csr, _ := x509.ParseCertificateRequest(der)
	leaf, err := e.is.IssueLeaf(csr, e.ident, pki.DefaultLeafLifetime)
	if err != nil {
		t.Fatal(err)
	}
	return key, [][]byte{leaf.Raw, e.inter.Cert.Raw}
}

func pemChain(chain [][]byte) []byte {
	var out []byte
	for _, c := range chain {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c})...)
	}
	return out
}

// enrolledDir writes the env's identity as enrollment does.
func enrolledDir(t *testing.T, e *rtEnv) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "identity")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(e.id.Certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	ident, _ := json.Marshal(agent.Identity{AgentID: e.ident.ID, Kind: "connector", TrustDomain: e.ident.TrustDomain})
	for name, f := range map[string]struct {
		data []byte
		mode os.FileMode
	}{
		agent.KeyFile:     {pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0o600},
		agent.ChainFile:   {pemChain([][]byte{e.id.Certificate.Leaf.Raw, e.inter.Cert.Raw}), 0o644},
		agent.RootsFile:   {pemChain([][]byte{e.root.Cert.Raw}), 0o644},
		agent.SigningFile: {pemChain([][]byte{e.config.Cert.Raw, e.inter.Cert.Raw}), 0o644},
		agent.AgentFile:   {ident, 0o644},
	} {
		if err := os.WriteFile(filepath.Join(dir, name), f.data, f.mode); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}
