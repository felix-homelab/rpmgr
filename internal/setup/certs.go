// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"path/filepath"

	"github.com/felix-homelab/rpmgr/internal/controller"
)

// selfSigned writes a self-signed certificate for host and its key, which only the service user
// reads.
func selfSigned(host, certFile, keyFile string, h Host) error {
	cert, key, err := controller.SelfSignedPEM(host)
	if err != nil {
		return err
	}
	if err := mkdirMode(filepath.Dir(certFile), 0o755); err != nil { // certificates are public
		return err
	}
	if err := writeNew(certFile, cert, 0o644); err != nil {
		return err
	}
	if err := writeNew(keyFile, key, 0o600); err != nil {
		return err
	}
	return h.GiveTo(keyFile)
}
