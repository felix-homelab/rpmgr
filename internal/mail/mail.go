// SPDX-License-Identifier: Apache-2.0

// Package mail sends the controller's few e-mails, invitations and password-reset links, through
// the configured relay (docs/04-security.md, "Human authentication and sessions"). It never sends
// in plain text: the relay must offer STARTTLS, or speak TLS from the start. The connection goes
// through ALL_PROXY, as all controller egress does (R44).
package mail

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strings"
	"time"

	"golang.org/x/net/proxy"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/secret"
)

// The time limits of a delivery (docs/03-connections.md, "Timeouts, keepalive and backoff").
const (
	DialTimeout = 10 * time.Second
	SendTimeout = 30 * time.Second
)

// ErrNotConfigured is returned when no relay is set.
var ErrNotConfigured = errors.New("mail: no mail relay is configured")

// Relay is a mail relay and how to reach it.
type Relay struct {
	Settings *rpmgrv1.SmtpSettings
	Password secret.Value
	// RootCAs, if set, replaces the system roots for the relay's certificate (tests).
	RootCAs *x509.CertPool
	// Dial, if set, replaces the proxy-aware dialer (tests).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Message is one plain-text e-mail.
type Message struct {
	To, Subject, Body string
}

// Send delivers a message through the relay.
func Send(ctx context.Context, r Relay, m Message) error {
	s := r.Settings
	if s.GetServer() == "" {
		return ErrNotConfigured
	}
	if strings.ContainsAny(m.To+m.Subject, "\r\n") || !strings.Contains(m.To, "@") {
		return errors.New("mail: a recipient or subject with a line break, or no address")
	}
	host, _, err := net.SplitHostPort(s.GetServer())
	if err != nil {
		return fmt.Errorf("mail: the relay %q: %w", s.GetServer(), err)
	}
	ctx, cancel := context.WithTimeout(ctx, SendTimeout)
	defer cancel()
	dial := r.Dial
	if dial == nil {
		dial = proxyDial
	}
	conn, err := dial(ctx, "tcp", s.GetServer())
	if err != nil {
		return fmt.Errorf("mail: cannot reach the relay: %w", err)
	}
	defer func() { _ = conn.Close() }()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	tlsConf := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, RootCAs: r.RootCAs}
	if s.GetSecurity() == rpmgrv1.SmtpSecurity_SMTP_SECURITY_TLS {
		conn = tls.Client(conn, tlsConf)
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("mail: %w", err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Hello("rpmgr"); err != nil {
		return fmt.Errorf("mail: %w", err)
	}
	if s.GetSecurity() != rpmgrv1.SmtpSecurity_SMTP_SECURITY_TLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("mail: the relay does not offer STARTTLS; the controller sends no mail in plain text")
		}
		if err := c.StartTLS(tlsConf); err != nil {
			return fmt.Errorf("mail: STARTTLS: %w", err)
		}
	}
	if s.GetUsername() != "" {
		if err := c.Auth(smtp.PlainAuth("", s.GetUsername(), r.Password.Reveal(), host)); err != nil {
			return fmt.Errorf("mail: the relay refused the credentials: %w", err)
		}
	}
	if err := c.Mail(s.GetFrom()); err != nil {
		return fmt.Errorf("mail: %w", err)
	}
	if err := c.Rcpt(m.To); err != nil {
		return fmt.Errorf("mail: the relay refused the recipient: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("mail: %w", err)
	}
	if _, err := w.Write(compose(s.GetFrom(), m)); err != nil {
		return fmt.Errorf("mail: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("mail: the relay did not accept the message: %w", err)
	}
	return c.Quit()
}

// compose writes the message with its headers, lines ending in CRLF.
func compose(from string, m Message) []byte {
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	domain := from[strings.LastIndex(from, "@")+1:]
	var b strings.Builder
	for _, h := range [][2]string{
		{"From", from}, {"To", m.To}, {"Subject", mime.QEncoding.Encode("utf-8", m.Subject)},
		{"Date", time.Now().UTC().Format(time.RFC1123Z)}, {"Message-ID", "<" + hex.EncodeToString(id) + "@" + domain + ">"},
		{"MIME-Version", "1.0"}, {"Content-Type", "text/plain; charset=utf-8"}, {"Content-Transfer-Encoding", "8bit"},
	} {
		b.WriteString(h[0] + ": " + h[1] + "\r\n")
	}
	b.WriteString("\r\n")
	b.WriteString(strings.ReplaceAll(strings.ReplaceAll(m.Body, "\r\n", "\n"), "\n", "\r\n"))
	return []byte(b.String())
}

// proxyDial dials through ALL_PROXY unless NO_PROXY exempts the address.
func proxyDial(ctx context.Context, network, addr string) (net.Conn, error) {
	d := proxy.FromEnvironmentUsing(&net.Dialer{Timeout: DialTimeout})
	if cd, ok := d.(proxy.ContextDialer); ok {
		return cd.DialContext(ctx, network, addr)
	}
	return d.Dial(network, addr)
}
