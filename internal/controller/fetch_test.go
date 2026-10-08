// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/certs"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// routeCertificate returns a self-signed certificate for name and its key, in PEM.
func routeCertificate(t *testing.T, name string) (chain, key []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	pk, _ := x509.MarshalPKCS8PrivateKey(k)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})
}

// TestFetchResource: an agent fetches a certificate item its snapshot names, by its hash, and
// gets exactly the stored chain and key; another agent, a wrong hash, an unknown item and an item
// changed since the snapshot are all NotFound.
func TestFetchResource(t *testing.T) {
	storetest.ForEachDialect(t, func(t *testing.T, db *store.DB) {
		var (
			mu    sync.Mutex
			owner string
			res   *agentv1.Resource
		)
		// The certificate goes to one agent only, as the real source gives it to gateways only.
		source := func(_ context.Context, _ *ent.Tx, a snapshot.Agent) ([]*agentv1.Resource, error) {
			mu.Lock()
			defer mu.Unlock()
			if a.Identity.ID != owner || res == nil {
				return nil, nil
			}
			return []*agentv1.Resource{proto.Clone(res).(*agentv1.Resource)}, nil
		}
		e := pushEnv(t, db, source)
		chainPEM, keyPEM := routeCertificate(t, "app.example.com")
		var c *ent.Certificate
		if err := store.WriteTx(e.sys, db, func(tx *ent.Tx) error {
			var err error
			c, err = certs.Upload(e.sys, tx, e.sealer, e.org, chainPEM, keyPEM, time.Now())
			return err
		}); err != nil {
			t.Fatal(err)
		}
		certA, a := e.agentCert(t)
		certB, _ := e.agentCert(t)
		mu.Lock()
		owner = a.ID
		res = &agentv1.Resource{Id: c.ID, Kind: &agentv1.Resource_GatewayCertificate{GatewayCertificate: &agentv1.GatewayCertificate{
			ContentSha256: c.ContentSha256, Hostnames: []string{"app.example.com"}}}}
		mu.Unlock()
		st := e.open(t, testCtx(t), certA, hello("0.1.0"))
		recv(t, st) // Welcome
		if _, snap := e.recvSnapshot(t, st, a); len(snap.GetResources()) != 1 {
			t.Fatalf("snapshot %v", snap)
		}

		got, err := e.client(t, certA).FetchResource(testCtx(t), &agentv1.FetchResourceRequest{Id: c.ID, Hash: c.ContentSha256})
		if err != nil {
			t.Fatal(err)
		}
		var item agentv1.CertificateItem
		if sum := sha256.Sum256(got.GetContent()); !bytes.Equal(sum[:], c.ContentSha256) || proto.Unmarshal(got.GetContent(), &item) != nil ||
			len(item.GetChain()) != 1 || len(item.GetPrivateKey()) == 0 {
			t.Fatalf("content %x", got.GetContent())
		}
		block, _ := pem.Decode(chainPEM)
		if !bytes.Equal(item.GetChain()[0], block.Bytes) {
			t.Fatal("not the uploaded certificate")
		}

		for name, tc := range map[string]struct {
			client agentv1.ControlClient
			req    *agentv1.FetchResourceRequest
		}{
			"another agent": {e.client(t, certB), &agentv1.FetchResourceRequest{Id: c.ID, Hash: c.ContentSha256}},
			"a wrong hash":  {e.client(t, certA), &agentv1.FetchResourceRequest{Id: c.ID, Hash: make([]byte, 32)}},
			"no hash":       {e.client(t, certA), &agentv1.FetchResourceRequest{Id: c.ID}},
			"unknown item":  {e.client(t, certA), &agentv1.FetchResourceRequest{Id: "crt_unknown", Hash: c.ContentSha256}},
		} {
			if _, err := tc.client.FetchResource(testCtx(t), tc.req); code(err) != codes.NotFound {
				t.Errorf("%s: %v, want NotFound", name, err)
			}
		}

		// The row changes after the snapshot named it: the old item is gone.
		db.Client().Certificate.UpdateOneID(c.ID).SetContentSha256(make([]byte, 32)).ExecX(e.sys)
		if _, err := e.client(t, certA).FetchResource(testCtx(t), &agentv1.FetchResourceRequest{Id: c.ID, Hash: c.ContentSha256}); code(err) != codes.NotFound {
			t.Errorf("a changed item: %v, want NotFound", err)
		}
	})
}
