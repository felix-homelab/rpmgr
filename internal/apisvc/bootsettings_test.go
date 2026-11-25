// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/apisvc"
	"github.com/felix-homelab/rpmgr/internal/config"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// The secrets that no response may hold: each is a canary, searched for in the JSON of every
// response.
const (
	bootCanaryPassword = "canary-dsn-password" //nolint:gosec // G101: a test canary
	bootCanaryQuery    = "canary-query-secret"
	bootCanaryFile     = "/run/secrets/canary-db-password-file"
	bootCanaryKEK      = "/etc/rpmgr/canary-kek-file"
	bootCanaryCred     = "canary-credential-name" //nolint:gosec // G101: a test canary
	bootCanaryTLSKey   = "/etc/rpmgr/canary-tls-key.pem"
	bootCanaryOTLP     = "https://canary-otlp.example.com/v1/traces"
)

var bootTestSource = apisvc.BootSource{
	Config: bootConfig("postgres", "postgres://rpmgr:"+bootCanaryPassword+"@db.example.com:5433/rpmgr?sslmode=verify-full&application_name="+bootCanaryQuery,
		config.KEKFile, ""),
	NodeID: "node-1", ConfigFile: "/etc/rpmgr/controller.yaml", LoadedAt: time.Unix(1700000000, 0),
	PasswordFile: bootCanaryFile,
}

func bootConfig(driver, dsn, kek, sink string) config.Controller {
	var c config.Controller
	http := ":80"
	c.PublicURL = "https://rpmgr.example.com"
	c.Listen.HTTPS, c.Listen.HTTP, c.Listen.Admin = ":443", &http, "127.0.0.1:7381"
	c.Database.Driver, c.Database.DSN = driver, dsn
	c.KEK.Source = kek
	switch kek {
	case config.KEKFile:
		c.KEK.Path = bootCanaryKEK
	case config.KEKSystemdCredential:
		c.KEK.Name = "rpmgr-kek"
	}
	c.RevocationLog.Sink = sink
	c.TLS.CertFile, c.TLS.KeyFile = "/etc/rpmgr/cert.pem", bootCanaryTLSKey
	c.Tracing.OTLPEndpoint = bootCanaryOTLP
	return c
}

// TestBootSettings_Access (docs/07-api.md, "Services"): only the Instance Admin reads the boot
// settings; an Owner of an org, a Viewer and a caller without a session are refused.
func TestBootSettings_Access(t *testing.T) {
	e, ada, org, _ := gatewayEnv(t)
	ctx := context.Background()
	get := func(b *browser) (*rpmgrv1.GetBootSettingsResponse, error) {
		r, err := b.set.GetBootSettings(ctx, connect.NewRequest(&rpmgrv1.GetBootSettingsRequest{}))
		if err != nil {
			return nil, err
		}
		return r.Msg, nil
	}
	got, err := get(ada)
	if err != nil || got.GetSettings().GetNodeId() != "node-1" || got.GetSettings().GetPublicUrl() != "https://rpmgr.example.com" {
		t.Fatalf("the Instance Admin: %v %v", got, err)
	}
	orgB := storetest.Org(t, e.db, "org-b")
	owner, _ := e.addOwner(t, orgB, "bob@example.com")
	vwr, _ := e.join(t, ada, org, "vwr@example.com", "viewer")
	for name, b := range map[string]*browser{"an Owner": owner, "a Viewer": vwr} {
		if r, err := get(b); code(err) != connect.CodePermissionDenied || r != nil {
			t.Errorf("%s: %v %v", name, r, err)
		}
	}
	if _, err := get(e.browser()); code(err) != connect.CodeUnauthenticated {
		t.Errorf("without a session: %v", err)
	}
}

// TestBootSettings_NoSecret (docs/04-security.md, "Secrets at rest and in logs"): no response
// holds the DSN's password, a credential in its query, the path of the password file or of the
// KEK file, for either driver and either KEK source.
func TestBootSettings_NoSecret(t *testing.T) {
	t.Setenv("PGPASSFILE", "/nonexistent/pgpass")
	t.Setenv("PGPASSWORD", "")
	canaries := []string{bootCanaryPassword, bootCanaryQuery, bootCanaryFile, bootCanaryKEK, bootCanaryCred, bootCanaryTLSKey, bootCanaryOTLP, "postgres://"}
	dsns := []string{
		bootTestSource.Config.Database.DSN,
		"host=db.example.com port=5433 dbname=rpmgr user=rpmgr password=" + bootCanaryPassword + " sslmode=verify-full sslpassword=" + bootCanaryQuery,
		"postgres://rpmgr:" + bootCanaryPassword + "@db.example.com/rpmgr?password=" + bootCanaryQuery,
		"postgres://rpmgr:p%zz" + bootCanaryPassword + "@db.example.com/rpmgr", // unparsable
		// a quoted keyword password that holds other keywords, and an escaped quote
		"host=db password='x host=" + bootCanaryPassword + "' dbname=rpmgr",
		"password='x port=" + bootCanaryPassword + "' host=db",
		"password='x user=" + bootCanaryPassword + "' host=db",
		"password='it\\'s dbname=" + bootCanaryPassword + "' host=db",
		"password='x sslmode=" + bootCanaryPassword + "' host=db",
		"host=db password='a b " + bootCanaryPassword + "' user=rpmgr",
		"host = db password = " + bootCanaryPassword,
		// a raw slash, question mark or hash in a URL password, a user fallback, a multi-host list
		"postgres://rpmgr:12/" + bootCanaryPassword + "@db/rpmgr",
		"postgres://rpmgr:12#" + bootCanaryPassword + "@db/rpmgr",
		"postgres://rpmgr:12?user=" + bootCanaryPassword + "@db/rpmgr",
		"postgres://db/rpmgr?user=u&password=" + bootCanaryPassword,
		"postgres://rpmgr:" + bootCanaryPassword + "@a:1,b:2/rpmgr",
		"postgres://db/rpmgr?sslmode=" + bootCanaryPassword,
		"host=db sslpassword=" + bootCanaryPassword + " sslkey=/keys/" + bootCanaryPassword + " passfile=/pw/" + bootCanaryPassword,
	}
	var all []*rpmgrv1.BootSettings
	for _, dsn := range dsns {
		for _, kek := range []string{config.KEKFile, config.KEKSystemdCredential} {
			all = append(all, apisvc.BootSource{Config: bootConfig("postgres", dsn, kek, "/mnt/share/revlog"), PasswordFile: bootCanaryFile}.Settings())
			all = append(all, apisvc.BootSource{Config: bootConfig("postgres", dsn, kek, ""), PasswordCredential: bootCanaryCred}.Settings())
		}
	}
	all = append(all, apisvc.BootSource{Config: bootConfig("sqlite", "/var/lib/rpmgr/"+bootCanaryQuery+".db", config.KEKFile, "")}.Settings())
	for i, s := range all {
		for _, out := range []string{protojson.Format(s), wire(t, s)} {
			for _, c := range canaries {
				if strings.Contains(out, c) {
					t.Errorf("response %d holds %q: %s", i, c, protojson.Format(s))
				}
			}
		}
	}
}

func wire(t *testing.T, m proto.Message) string {
	t.Helper()
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestBootSettings_Content: what the response shows, for both drivers, both KEK sources, with and
// without a sink.
func TestBootSettings_Content(t *testing.T) {
	t.Setenv("PGPASSFILE", "/nonexistent/pgpass")
	t.Setenv("PGPASSWORD", "")
	pg := apisvc.BootSource{Config: bootConfig("postgres", bootTestSource.Config.Database.DSN, config.KEKFile, "/mnt/share/revlog"),
		PasswordFile: bootCanaryFile}.Settings()
	d := pg.GetDatabase()
	if d.GetDriver() != rpmgrv1.DatabaseDriver_DATABASE_DRIVER_POSTGRES || d.GetHost() != "db.example.com" || d.GetPort() != "5433" ||
		d.GetDatabase() != "rpmgr" || d.GetUser() != "rpmgr" || d.GetSslmode() != "verify-full" ||
		d.GetPasswordSource() != rpmgrv1.PasswordSource_PASSWORD_SOURCE_FILE {
		t.Errorf("postgres: %v", d)
	}
	if pg.GetKek().GetSource() != rpmgrv1.KekSource_KEK_SOURCE_FILE || pg.GetRevocationLogSink() != "/mnt/share/revlog" || !pg.GetTlsFilesSet() {
		t.Errorf("kek file, sink: %v", pg)
	}
	lite := apisvc.BootSource{Config: bootConfig("sqlite", "/var/lib/rpmgr/controller.db", config.KEKSystemdCredential, "")}.Settings()
	if lite.GetDatabase().GetDriver() != rpmgrv1.DatabaseDriver_DATABASE_DRIVER_SQLITE || lite.GetDatabase().GetHost() != "" ||
		lite.GetKek().GetSource() != rpmgrv1.KekSource_KEK_SOURCE_SYSTEMD_CREDENTIAL || lite.GetKek().GetCredentialName() != "rpmgr-kek" ||
		lite.GetRevocationLogSink() != "" || lite.GetListenHttp() != ":80" || lite.GetListenHttps() != ":443" {
		t.Errorf("sqlite: %v", lite)
	}
	kw := apisvc.BootSource{Config: bootConfig("postgres", "host=/run/postgresql dbname=rpmgr user=rpmgr", config.KEKFile, "")}.Settings()
	if kw.GetDatabase().GetHost() != "/run/postgresql" || kw.GetDatabase().GetPasswordSource() != rpmgrv1.PasswordSource_PASSWORD_SOURCE_NONE {
		t.Errorf("keyword DSN: %v", kw.GetDatabase())
	}
	dsnPW := apisvc.BootSource{Config: bootConfig("postgres", bootTestSource.Config.Database.DSN, config.KEKFile, "")}.Settings()
	if dsnPW.GetDatabase().GetPasswordSource() != rpmgrv1.PasswordSource_PASSWORD_SOURCE_DSN {
		t.Errorf("a DSN with a password: %v", dsnPW.GetDatabase())
	}
	// the user fallback in the query and a multi-host list: the first host, with its port
	q := apisvc.BootSource{Config: bootConfig("postgres", "postgres://db/rpmgr?user=u&password="+bootCanaryPassword, config.KEKFile, "")}.Settings()
	if q.GetDatabase().GetUser() != "u" || q.GetDatabase().GetHost() != "db" || q.GetDatabase().GetPasswordSource() != rpmgrv1.PasswordSource_PASSWORD_SOURCE_DSN {
		t.Errorf("?user=: %v", q.GetDatabase())
	}
	mh := apisvc.BootSource{Config: bootConfig("postgres", "postgres://u@a:1,b:2/db", config.KEKFile, "")}.Settings()
	if mh.GetDatabase().GetHost() != "a" || mh.GetDatabase().GetPort() != "1" {
		t.Errorf("multi-host: %v", mh.GetDatabase())
	}
	if kms := (apisvc.BootSource{Config: bootConfig("sqlite", "/x.db", "kms", "")}).Settings(); kms.GetKek().GetSource() != rpmgrv1.KekSource_KEK_SOURCE_KMS {
		t.Errorf("kms: %v", kms.GetKek())
	}
}

// TestBootSettings_NoBootFile: a controller without a boot source answers FAILED_PRECONDITION.
func TestBootSettings_NoBootFile(t *testing.T) {
	_, err := (&apisvc.Settings{}).GetBootSettings(context.Background(), connect.NewRequest(&rpmgrv1.GetBootSettingsRequest{}))
	if code(err) != connect.CodeFailedPrecondition {
		t.Errorf("no boot source: %v", err)
	}
}
