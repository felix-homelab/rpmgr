// SPDX-License-Identifier: Apache-2.0

package mail_test

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"math/big"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/mail"
	"github.com/felix-homelab/rpmgr/internal/secret"
)

// relay is a minimal SMTP server: EHLO, STARTTLS, AUTH PLAIN, MAIL, RCPT, DATA and QUIT.
type relay struct {
	addr     string
	pool     *x509.CertPool
	implicit bool // TLS from the start
	plain    bool // offers no STARTTLS
	user     string
	pass     string

	mu   sync.Mutex
	got  []string // the DATA of each delivered message
	auth []string // user names that authenticated
}

func newRelay(t *testing.T, configure func(*relay)) *relay {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	leaf, _ := x509.ParseCertificate(der)
	r := &relay{pool: x509.NewCertPool(), user: "rpmgr", pass: "relay-password"}
	r.pool.AddCert(leaf)
	if configure != nil {
		configure(r)
	}
	conf := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	r.addr = ln.Addr().String()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if r.implicit {
				c = tls.Server(c, conf)
			}
			go r.serve(c, conf)
		}
	}()
	return r
}

func (r *relay) serve(c net.Conn, conf *tls.Config) {
	defer func() { _ = c.Close() }()
	tp := textproto.NewConn(c)
	_ = tp.PrintfLine("220 test relay")
	_, secure := c.(*tls.Conn)
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		verb, arg, _ := strings.Cut(line, " ")
		switch strings.ToUpper(verb) {
		case "EHLO":
			ext := []string{"250-test relay"}
			if !secure && !r.plain {
				ext = append(ext, "250-STARTTLS")
			}
			if secure {
				ext = append(ext, "250-AUTH PLAIN")
			}
			_ = tp.PrintfLine("%s\r\n250 8BITMIME", strings.Join(ext, "\r\n"))
		case "STARTTLS":
			_ = tp.PrintfLine("220 go ahead")
			tc := tls.Server(c, conf)
			if tc.Handshake() != nil {
				return
			}
			c, secure, tp = tc, true, textproto.NewConn(tc)
		case "AUTH":
			b, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(arg, "PLAIN "))
			parts := strings.Split(string(b), "\x00")
			if len(parts) != 3 || parts[1] != r.user || parts[2] != r.pass {
				_ = tp.PrintfLine("535 authentication failed")
				continue
			}
			r.mu.Lock()
			r.auth = append(r.auth, parts[1])
			r.mu.Unlock()
			_ = tp.PrintfLine("235 ok")
		case "MAIL":
			_ = tp.PrintfLine("250 ok")
		case "RCPT":
			if strings.Contains(arg, "refused@") {
				_ = tp.PrintfLine("550 no such mailbox")
				continue
			}
			_ = tp.PrintfLine("250 ok")
		case "DATA":
			_ = tp.PrintfLine("354 go ahead")
			// Raw lines, so the test sees the CRLFs on the wire.
			var b strings.Builder
			for {
				l, err := tp.R.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			r.mu.Lock()
			r.got = append(r.got, b.String())
			r.mu.Unlock()
			_ = tp.PrintfLine("250 queued")
		case "QUIT":
			_ = tp.PrintfLine("221 bye")
			return
		default:
			_ = tp.PrintfLine("502 not implemented")
		}
	}
}

func (r *relay) messages() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.got...)
}

func (r *relay) settings(security rpmgrv1.SmtpSecurity) mail.Relay {
	return mail.Relay{Settings: &rpmgrv1.SmtpSettings{Server: r.addr, From: "rpmgr@example.com", Username: "rpmgr", Security: security},
		Password: secret.New(r.pass), RootCAs: r.pool}
}

var msg = mail.Message{To: "ada@example.com", Subject: "Your invitation – rpmgr", Body: "Line one\nLine two\n"}

// TestSend: STARTTLS and implicit TLS both deliver, authenticated, with the headers and the body
// in CRLF lines and the subject encoded.
func TestSend(t *testing.T) {
	for _, mode := range []rpmgrv1.SmtpSecurity{rpmgrv1.SmtpSecurity_SMTP_SECURITY_STARTTLS, rpmgrv1.SmtpSecurity_SMTP_SECURITY_TLS} {
		r := newRelay(t, func(r *relay) { r.implicit = mode == rpmgrv1.SmtpSecurity_SMTP_SECURITY_TLS })
		if err := mail.Send(context.Background(), r.settings(mode), msg); err != nil {
			t.Fatalf("%v: %v", mode, err)
		}
		got := r.messages()
		r.mu.Lock()
		logins := len(r.auth)
		r.mu.Unlock()
		if len(got) != 1 || logins != 1 {
			t.Fatalf("%v: %d messages, %d logins", mode, len(got), logins)
		}
		for _, want := range []string{"From: rpmgr@example.com\r\n", "To: ada@example.com\r\n", "Subject: =?utf-8?q?Your_invitation_",
			"Content-Type: text/plain; charset=utf-8\r\n", "Message-ID: <", "\r\n\r\nLine one\r\nLine two\r\n"} {
			if !strings.Contains(got[0], want) {
				t.Errorf("%v: the message lacks %q:\n%s", mode, want, got[0])
			}
		}
	}
}

// TestSend_Refusals: no relay, a relay without STARTTLS, a certificate the controller does not
// trust, wrong credentials, a refused recipient, a relay that does not answer, and a recipient or
// subject with a line break all fail, and no mail goes out in plain text.
func TestSend_Refusals(t *testing.T) {
	ctx := context.Background()
	starttls := rpmgrv1.SmtpSecurity_SMTP_SECURITY_STARTTLS
	if err := mail.Send(ctx, mail.Relay{Settings: &rpmgrv1.SmtpSettings{}}, msg); !errors.Is(err, mail.ErrNotConfigured) {
		t.Errorf("no relay: %v", err)
	}
	plain := newRelay(t, func(r *relay) { r.plain = true })
	if err := mail.Send(ctx, plain.settings(starttls), msg); err == nil || !strings.Contains(err.Error(), "STARTTLS") ||
		len(plain.messages()) != 0 {
		t.Errorf("no STARTTLS: %v", err)
	}
	r := newRelay(t, nil)
	untrusted := r.settings(starttls)
	untrusted.RootCAs = x509.NewCertPool()
	if err := mail.Send(ctx, untrusted, msg); err == nil {
		t.Error("an untrusted relay certificate")
	}
	wrong := r.settings(starttls)
	wrong.Password = secret.New("wrong")
	if err := mail.Send(ctx, wrong, msg); err == nil || !strings.Contains(err.Error(), "credentials") {
		t.Errorf("wrong credentials: %v", err)
	}
	if err := mail.Send(ctx, r.settings(starttls), mail.Message{To: "refused@example.com", Subject: "x", Body: "x"}); err == nil {
		t.Error("a refused recipient")
	}
	for name, m := range map[string]mail.Message{
		"a line break in the recipient": {To: "ada@example.com\r\nBcc: eve@example.com", Subject: "x"},
		"a line break in the subject":   {To: "ada@example.com", Subject: "x\nBcc: eve@example.com"},
		"no address":                    {To: "ada", Subject: "x"},
	} {
		if err := mail.Send(ctx, r.settings(starttls), m); err == nil {
			t.Errorf("%s: sent", name)
		}
	}
	if len(r.messages()) != 0 {
		t.Fatalf("%d messages went out", len(r.messages()))
	}

	silent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = silent.Close() })
	go func() {
		for {
			c, err := silent.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = bufio.NewReader(c).ReadString(0) }()
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := mail.Send(ctx, mail.Relay{Settings: &rpmgrv1.SmtpSettings{Server: silent.Addr().String(), From: "rpmgr@example.com",
		Security: starttls}}, msg); err == nil || time.Since(start) > 5*time.Second {
		t.Errorf("a silent relay: %v after %v", err, time.Since(start))
	}
}
