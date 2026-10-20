// SPDX-License-Identifier: Apache-2.0

package castore

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent/cakey"
)

// SignerCertificates returns what verifies old signatures of purpose p: every certificate a key
// of that purpose has had and every intermediate, retired or expired ones too, with the root.
func SignerCertificates(ctx context.Context, db *store.DB, p pki.Purpose) (signers, intermediates []*x509.Certificate, root *x509.Certificate, err error) {
	kind := map[pki.Purpose]cakey.Kind{pki.PurposeConfigSigning: cakey.KindConfigSigning, pki.PurposeAuditCheckpoint: cakey.KindAuditCheckpoint}[p]
	rows, err := db.ReadClient().CAKey.Query().Where(cakey.KindIn(kind, cakey.KindIntermediate, cakey.KindRoot),
		cakey.StatusNEQ(cakey.StatusNext)).All(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	for _, r := range rows {
		c, err := x509.ParseCertificate(r.Certificate)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("pki: certificate of key %s: %w", r.ID, err)
		}
		switch {
		case r.Kind == kind:
			signers = append(signers, c)
		case r.Kind == cakey.KindIntermediate:
			intermediates = append(intermediates, c)
		case r.Status == cakey.StatusActive:
			root = c
		}
	}
	if root == nil {
		return nil, nil, nil, errors.New("pki: no active root")
	}
	return signers, intermediates, root, nil
}
