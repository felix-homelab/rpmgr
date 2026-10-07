// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestRenewNodeCertificate: the node certificate is renewed with a new key at half its lifetime,
// long before it expires, and not before; new handshakes present the new one.
func TestRenewNodeCertificate(t *testing.T) {
	db := storetest.Migrated(t, store.SQLite)
	e := startSessions(t, db, "0.1.0", 0)
	nodeID := ids.New("ctn")
	first, err := e.ca.NodeCertificate(e.sys, db, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	holder := pki.NewHolder(first)
	run := func(now time.Time, d time.Duration) {
		ctx, cancel := context.WithTimeout(context.Background(), d)
		defer cancel()
		controller.RenewNodeCertificate(ctx, controller.NodeCertOptions{CA: e.ca, DB: db, Sys: e.sys, NodeID: nodeID,
			Holder: holder, Now: func() time.Time { return now }})
	}
	half := first.Leaf.NotBefore.Add(first.Leaf.NotAfter.Sub(first.Leaf.NotBefore) / 2)
	run(half.Add(-time.Hour), 200*time.Millisecond)
	if holder.Certificate().Leaf.SerialNumber.Cmp(first.Leaf.SerialNumber) != 0 {
		t.Fatal("renewed before half the lifetime")
	}
	run(half, 200*time.Millisecond)
	renewed := holder.Certificate()
	if renewed.Leaf.SerialNumber.Cmp(first.Leaf.SerialNumber) == 0 {
		t.Fatal("not renewed at half the lifetime")
	}
	if renewed.Leaf.PublicKey.(*ecdsa.PublicKey).Equal(first.Leaf.PublicKey) {
		t.Fatal("the renewed certificate has the old key")
	}
	if renewed.Leaf.URIs[0].String() != first.Leaf.URIs[0].String() {
		t.Fatal("the renewed certificate is for another identity")
	}
	got, err := holder.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil || got.Leaf != renewed.Leaf {
		t.Fatal("GetCertificate does not return the renewed certificate")
	}
	if _, err := x509.ParseCertificate(renewed.Certificate[1]); err != nil || len(renewed.Certificate) != 2 {
		t.Fatal("the renewed certificate goes out without its intermediate")
	}
}
