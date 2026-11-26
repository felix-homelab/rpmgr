// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/store"
)

// BootSource is what GetBootSettings reports: the boot file as the controller loaded it, with the
// secrets of the database that the boot file does not hold in config.Controller.
type BootSource struct {
	Config     config.Controller
	NodeID     string
	ConfigFile string
	LoadedAt   time.Time
	// PasswordFile and PasswordCredential say where the database password comes from. Only their
	// kind is reported; the path and the name of the database password's source are never.
	PasswordFile       string
	PasswordCredential string
}

// Settings builds the response. It copies a field only if it is no secret: it never copies the DSN
// (only its host, port, database, user and sslmode), the path of a password or KEK file, the name
// of a password credential (the KEK's credential name is shown, as docs/07-api.md says), or a token
// (docs/04-security.md, "Secrets at rest and in logs").
func (b BootSource) Settings() *rpmgrv1.BootSettings {
	c := b.Config
	out := &rpmgrv1.BootSettings{
		NodeId: b.NodeID, ConfigFile: b.ConfigFile, PublicUrl: c.PublicURL, ListenHttps: c.Listen.HTTPS,
		ListenAdmin: c.Listen.Admin, Database: b.database(), TlsFilesSet: c.TLS.CertFile != "" || c.TLS.KeyFile != "",
		RevocationLogSink: c.RevocationLog.Sink, LogLevel: c.Log.Level, LogFormat: c.Log.Format,
		TracingEnabled: c.Tracing.OTLPEndpoint != "",
	}
	if c.Listen.HTTP != nil {
		out.ListenHttp = *c.Listen.HTTP
	}
	if !b.LoadedAt.IsZero() {
		out.LoadedAt = timestamppb.New(b.LoadedAt)
	}
	out.Kek = &rpmgrv1.BootKek{}
	switch c.KEK.Source {
	case config.KEKSystemdCredential:
		out.Kek.Source = rpmgrv1.KekSource_KEK_SOURCE_SYSTEMD_CREDENTIAL
		out.Kek.CredentialName = c.KEK.Name
	case config.KEKFile:
		out.Kek.Source = rpmgrv1.KekSource_KEK_SOURCE_FILE
	case "kms":
		out.Kek.Source = rpmgrv1.KekSource_KEK_SOURCE_KMS
	}
	return out
}

func (b BootSource) database() *rpmgrv1.BootDatabase {
	switch b.Config.Database.Driver {
	case "sqlite":
		return &rpmgrv1.BootDatabase{Driver: rpmgrv1.DatabaseDriver_DATABASE_DRIVER_SQLITE}
	case "postgres":
		d := dsnSummary(b.Config.Database.DSN)
		d.Driver = rpmgrv1.DatabaseDriver_DATABASE_DRIVER_POSTGRES
		switch {
		case b.PasswordFile != "":
			d.PasswordSource = rpmgrv1.PasswordSource_PASSWORD_SOURCE_FILE
		case b.PasswordCredential != "":
			d.PasswordSource = rpmgrv1.PasswordSource_PASSWORD_SOURCE_CREDENTIAL
		case d.PasswordSource == rpmgrv1.PasswordSource_PASSWORD_SOURCE_UNSPECIFIED:
			d.PasswordSource = rpmgrv1.PasswordSource_PASSWORD_SOURCE_NONE
		}
		return d
	}
	return &rpmgrv1.BootDatabase{}
}

// dsnSummary reads the host, port, database, user and sslmode of a PostgreSQL DSN with the parser
// of the database opener (store.SummarizeDSN), and whether it carries a password. Everything else
// is dropped, so a password or a credential in another parameter cannot reach the response. A DSN
// it cannot read gives nothing.
func dsnSummary(dsn string) *rpmgrv1.BootDatabase {
	d := &rpmgrv1.BootDatabase{}
	p, ok := store.SummarizeDSN(dsn)
	if !ok {
		return d
	}
	d.Host, d.Port, d.Database, d.User, d.Sslmode = p.Host, p.Port, p.Database, p.User, p.SSLMode
	if p.HasPassword {
		d.PasswordSource = rpmgrv1.PasswordSource_PASSWORD_SOURCE_DSN
	}
	return d
}
