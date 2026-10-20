// SPDX-License-Identifier: Apache-2.0

// Package serversetup is what `rpmgr setup` needs of the controller and the all-in-one, which only
// the full build links: package setup reaches it through setup.Server (docs/02-architecture.md,
// "Roles").
package serversetup

import (
	"context"

	"github.com/felix-homelab/rpmgr/internal/acme"
	"github.com/felix-homelab/rpmgr/internal/allinone"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/setup"
)

// Server is the full build's setup.Server.
type Server struct{}

var _ setup.Server = Server{}

// Init initialises a controller or an all-in-one.
func (Server) Init(ctx context.Context, o setup.ServerInit) (setup.ServerResult, error) {
	opts := controller.InitOptions{ConfigPath: o.ConfigPath, CredentialsDir: o.CredentialsDir, Getenv: o.Getenv,
		Encrypt: o.Encrypt, SystemdVersion: o.SystemdVersion, ServiceUser: o.ServiceUser, Now: o.Now}
	var r setup.ServerResult
	var ir controller.InitResult
	if o.AllInOne {
		a, err := allinone.Init(ctx, opts)
		if err != nil {
			return r, err
		}
		ir, r.GatewayID, r.ConnectorID = a.InitResult, a.GatewayID, a.ConnectorID
	} else {
		c, err := controller.Init(ctx, opts)
		if err != nil {
			return r, err
		}
		ir = c
	}
	r.TrustDomain, r.RootPin, r.FirstUserLink, r.KEK = ir.TrustDomain, ir.RootPin, ir.FirstUserLink, ir.KEK
	return r, nil
}

// SetACME sets the instance's ACME directory and e-mail address.
func (Server) SetACME(ctx context.Context, boot, directory, email string) error {
	return controller.SetACME(ctx, boot, directory, email)
}

// PublicCA reports whether a public CA can certify host.
func (Server) PublicCA(host string) bool { return acme.Eligible(host) }

// SelfSignedPEM makes a self-signed certificate for host and its key.
func (Server) SelfSignedPEM(host string) (cert, key []byte, err error) {
	return controller.SelfSignedPEM(host)
}
