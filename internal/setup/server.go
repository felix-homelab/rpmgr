// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"context"
	"time"
)

// Server performs what only a controller or an all-in-one host needs: initialising the
// installation, setting the instance's ACME account, and making a self-signed certificate for the
// web UI. The full build supplies it (package serversetup); the connector-only build has none, so
// its setup offers the gateway and connector roles only (docs/02-architecture.md, "Roles").
type Server interface {
	// Init initialises a controller, or with o.AllInOne an all-in-one, as `rpmgr controller
	// init` and `rpmgr all-in-one init` do.
	Init(ctx context.Context, o ServerInit) (ServerResult, error)
	// SetACME sets the instance's ACME directory and e-mail address through the boot file's
	// database.
	SetACME(ctx context.Context, boot, directory, email string) error
	// PublicCA reports whether a public CA can certify host, so that ACME can serve it.
	PublicCA(host string) bool
	// SelfSignedPEM makes a self-signed certificate for host and its key, PEM-encoded.
	SelfSignedPEM(host string) (cert, key []byte, err error)
}

// ServerInit are the inputs of Server.Init.
type ServerInit struct {
	AllInOne       bool
	ConfigPath     string
	CredentialsDir string
	Getenv         func(string) string
	Encrypt        func(ctx context.Context, name, path string, b []byte) error
	SystemdVersion func() int
	ServiceUser    string
	Now            func() time.Time
}

// ServerResult is what Server.Init reports; GatewayID and ConnectorID only for an all-in-one.
type ServerResult struct {
	TrustDomain, RootPin, FirstUserLink, KEK string
	GatewayID, ConnectorID                   string
}
