// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/pki"
)

// TestExportHeaderTrust: a root of the header is trusted beyond the pinned one only through a cross-certificate
// that a trusted root signed. A self-signed extra root, with itself as its "cross-certificate", is not trusted.
func TestExportHeaderTrust(t *testing.T) {
	now := time.Now()
	r1, err := pki.NewRoot("rpmgr-7f3k2q6m", now)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := pki.NewRoot("rpmgr-7f3k2q6m", now)
	if err != nil {
		t.Fatal(err)
	}
	h := ExportHeader{Root: r1.Cert.Raw, Roots: [][]byte{r1.Cert.Raw, foreign.Cert.Raw}, Intermediates: [][]byte{foreign.Cert.Raw}}
	tr, err := h.trust(pki.RootPin(r1.Cert))
	if err != nil {
		t.Fatal(err)
	}
	if len(tr.Roots) != 1 || !tr.Roots[0].Equal(r1.Cert) {
		t.Fatalf("a self-signed extra root with itself as its cross-certificate was trusted: %d roots", len(tr.Roots))
	}
}
