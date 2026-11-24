// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/felix-homelab/rpmgr/internal/store"
)

// testCA is a generated certificate authority for the TLS tests.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "rpmgr test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// server returns a certificate for names, signed by the CA.
func (ca *testCA) server(t *testing.T, names ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// tlsServer is a minimal PostgreSQL server that only answers SSLRequest and performs the TLS
// handshake; handshakes reports the result of each.
func tlsServer(t *testing.T, cert tls.Certificate) (addr string, handshakes <-chan error) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	res := make(chan error, 8)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				var req [8]byte
				if _, err := c.Read(req[:]); err != nil {
					return
				}
				_, _ = c.Write([]byte("S"))
				res <- tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}).Handshake()
			}()
		}
	}()
	return l.Addr().String(), res
}

// connect connects to the test server at addr as the DSN names it, under the host name in the DSN.
func connect(t *testing.T, dsn, addr string) error {
	t.Helper()
	cfg, err := store.PostgresConfig(dsn, store.PostgresOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cfg.LookupFunc = func(context.Context, string) ([]string, error) { return []string{"127.0.0.1"}, nil }
	cfg.DialFunc = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err == nil {
		_ = conn.Close(ctx)
	}
	return err
}

func isCertError(err error) bool {
	var h x509.HostnameError
	var u x509.UnknownAuthorityError
	return errors.As(err, &h) || errors.As(err, &u) || (err != nil && strings.Contains(err.Error(), "x509:"))
}

func TestPostgres_TLSServerNameAndAuthorityAreChecked(t *testing.T) {
	noPGEnv(t)
	ca := newTestCA(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, ca.pem, 0o600); err != nil {
		t.Fatal(err)
	}
	other := newTestCA(t)
	otherFile := filepath.Join(t.TempDir(), "other.pem")
	if err := os.WriteFile(otherFile, other.pem, 0o600); err != nil {
		t.Fatal(err)
	}
	const host = "pg.test.example"
	for _, mode := range []string{"verify-full", "verify-ca", "require"} {
		dsn := func(root string) string {
			return "postgres://rpmgr@" + host + "/rpmgr?sslmode=" + mode + "&sslrootcert=" + root
		}
		t.Run(mode+"/right name and authority", func(t *testing.T) {
			addr, hs := tlsServer(t, ca.server(t, host))
			err := connect(t, dsn(caFile), addr)
			if isCertError(err) {
				t.Fatalf("the certificate was refused: %v", err)
			}
			select {
			case err := <-hs:
				if err != nil {
					t.Fatalf("the handshake failed: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("no handshake; the client got: %v", err)
			}
		})
		t.Run(mode+"/certificate names another host", func(t *testing.T) {
			addr, _ := tlsServer(t, ca.server(t, "other.test.example"))
			if err := connect(t, dsn(caFile), addr); !isCertError(err) {
				t.Fatalf("err = %v, want a certificate name error", err)
			}
		})
		t.Run(mode+"/authority not trusted", func(t *testing.T) {
			addr, _ := tlsServer(t, ca.server(t, host))
			if err := connect(t, dsn(otherFile), addr); !isCertError(err) {
				t.Fatalf("err = %v, want an unknown authority error", err)
			}
		})
	}
	t.Run("system authorities, none given", func(t *testing.T) {
		addr, _ := tlsServer(t, ca.server(t, host))
		if err := connect(t, "postgres://rpmgr@"+host+"/rpmgr?sslmode=verify-full", addr); !isCertError(err) {
			t.Fatalf("err = %v, want an unknown authority error", err)
		}
	})
}

// logBuffer captures the default slog logger for a test.
func logBuffer(t *testing.T) *bytes.Buffer {
	t.Helper()
	var b bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&b, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &b
}

func TestPostgres_PasswordNeverLogged(t *testing.T) {
	noPGEnv(t)
	logs := logBuffer(t)
	const pw = "l0gg3d-Passw0rd-value"
	file := writeFile(t, pw+"\n", 0o600)
	// a refused DSN, a server that is down, and one that is not TLS
	for _, dsn := range []string{
		"postgres://rpmgr@db.example/rpmgr?sslmode=disable",
		"postgres://rpmgr@127.0.0.1:1/rpmgr?sslmode=disable",
		"postgres://rpmgr:" + pw + "@127.0.0.1:1/rpmgr?sslmode=disable",
	} {
		_, err := store.OpenPostgres(context.Background(), dsn, store.PostgresOptions{PasswordFile: file})
		if err != nil && strings.Contains(err.Error(), pw) {
			t.Fatalf("the error names the password: %v", err)
		}
	}
	// the wrong password against the real server, with the lock, as the controller opens it
	u := pgDSN(t)
	if _, err := store.OpenPostgres(context.Background(), stripPassword(t, u), store.PostgresOptions{PasswordFile: file, Lock: true}); err == nil {
		t.Skip("the test server accepts any password")
	} else if strings.Contains(err.Error(), pw) {
		t.Fatalf("the error names the password: %v", err)
	}
	if strings.Contains(logs.String(), pw) {
		t.Fatalf("the log names the password:\n%s", logs)
	}
}

func TestPostgres_PasswordFileBoundaries(t *testing.T) {
	noPGEnv(t)
	const local = "postgres://rpmgr@127.0.0.1/rpmgr?sslmode=disable"
	open := func(path string) error {
		return store.PostgresConfigErr(local, store.PostgresOptions{PasswordFile: path})
	}
	if err := open(writeFile(t, strings.Repeat("a", 4095)+"\n", 0o600)); err != nil {
		t.Errorf("4096 bytes: %v", err)
	}
	if err := open(writeFile(t, strings.Repeat("a", 4096)+"\n", 0o600)); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("4097 bytes: err = %v", err)
	}
	if err := open(writeFile(t, "pw", 0o640)); err == nil || !strings.Contains(err.Error(), "mode 0640") {
		t.Errorf("mode 0640: err = %v", err)
	}
	good, bad := writeFile(t, "pw", 0o600), writeFile(t, "pw", 0o644)
	link := func(target string) string {
		l := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(target, l); err != nil {
			t.Skip("no symlinks: ", err)
		}
		return l
	}
	if err := open(link(good)); err != nil {
		t.Errorf("a symlink to a 0600 file: %v", err)
	}
	if err := open(link(bad)); err == nil {
		t.Error("a symlink to a 0644 file was accepted")
	}
	if err := open(t.TempDir()); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("a directory: err = %v", err)
	}
}
