// SPDX-License-Identifier: Apache-2.0

package auditsink

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/felix-homelab/rpmgr/internal/egress"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// The limits of the syslog sink (docs/03-connections.md, "Timeouts, keepalive and backoff"): the
// dial with its handshake, each write and the drain that ends a batch each have a deadline, and
// no message is longer than MaxSyslogMessage, which every receiver of RFC 5425 must accept at the
// least (it asks for 2048 octets and recommends 8192).
const (
	SyslogDialTimeout  = 10 * time.Second
	SyslogWriteTimeout = 10 * time.Second
	SyslogDrainTimeout = 5 * time.Second
	MaxSyslogMessage   = 8192
)

// The header of every message (RFC 5424, section 6): facility 13 (log audit), severity 6 (info),
// version 1.
const (
	syslogPri     = 13*8 + 6
	syslogAppName = "rpmgr"
)

// syslogSink ships each item as one RFC 5424 message, framed by octet counting as RFC 5425 asks
// and sent over TLS 1.2 or later, to a server whose certificate is verified against the sink's CA
// bundle, or the system roots without one. It is set by the Instance Admin, so it may reach
// private ranges and loopback; the egress guard refuses link-local, metadata, multicast and
// broadcast addresses at dial time, for the address actually dialled (D145, E5).
//
// Syslog over TLS has no acknowledgement of a message. A write is not one; Flush, which ends a
// batch, is: it closes the connection in order and reads until the server closes it, so a
// connection that the server dropped before it read the batch fails the batch, which then goes
// again from the cursor.
type syslogSink struct {
	address  string
	host     string
	roots    *x509.CertPool
	hostname string
	policy   egress.Policy
	conn     *tls.Conn
	// failed is a connection that broke while a batch was written: what it carried is unconfirmed.
	failed error
}

// parseSyslogAddress splits "host:port" and checks the port.
func parseSyslogAddress(address string) (host, port string, err error) {
	host, port, err = net.SplitHostPort(address)
	if err != nil || host == "" {
		return "", "", errors.New("the address is not host:port")
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", "", errors.New("the port is not a number from 1 to 65535")
	}
	return host, port, nil
}

// CheckSyslogSettings reports why an address and a CA bundle cannot be used by a syslog sink, or
// nil. An empty bundle means the system roots.
func CheckSyslogSettings(address, ca string) error {
	if _, _, err := parseSyslogAddress(address); err != nil {
		return err
	}
	if ca == "" {
		return nil
	}
	if _, err := rootsOf(ca); err != nil {
		return err
	}
	return nil
}

// rootsOf is the pool of a PEM bundle, which must hold at least one certificate and nothing else
// that would be skipped silently.
func rootsOf(ca string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(ca)) {
		return nil, errors.New("the CA bundle holds no certificate in PEM form")
	}
	return pool, nil
}

func openSyslog(s *ent.AuditSink) (Sink, error) {
	address := s.Settings["address"]
	host, _, err := parseSyslogAddress(address)
	if err != nil {
		return nil, fmt.Errorf("the syslog sink has no usable address: %w", err)
	}
	k := &syslogSink{address: address, host: host, hostname: syslogHostname(), policy: egress.Policy{Internal: true}}
	if ca := s.Settings["ca"]; ca != "" {
		if k.roots, err = rootsOf(ca); err != nil {
			return nil, fmt.Errorf("the syslog sink's %w", err)
		}
	}
	return k, nil
}

// syslogHostname is the controller's host name as RFC 5424 writes it: printable ASCII without
// spaces, at most 255 octets, "-" when unknown.
func syslogHostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "-"
	}
	var b strings.Builder
	for _, r := range h {
		if r > 32 && r < 127 {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "-"
	}
	return b.String()[:min(b.Len(), 255)]
}

// Ship writes the item as one message, dialling first if no connection is open.
func (k *syslogSink) Ship(ctx context.Context, it Item) error {
	msg, err := k.message(it)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if k.conn == nil {
		if err := k.dial(ctx); err != nil {
			return err
		}
	}
	frame := append([]byte(strconv.Itoa(len(msg))+" "), msg...)
	_ = k.conn.SetWriteDeadline(time.Now().Add(SyslogWriteTimeout))
	if _, err := k.conn.Write(frame); err != nil {
		k.drop()
		k.failed = syslogFailure("writing to the syslog server failed", err)
		return k.failed
	}
	return nil
}

// dial connects, checks the address with the egress policy as it is dialled, and verifies the
// server.
func (k *syslogSink) dial(ctx context.Context) error {
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: SyslogDialTimeout, Control: k.policy.Control},
		Config:    &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: k.roots, ServerName: k.host},
	}
	ctx, cancel := context.WithTimeout(ctx, SyslogDialTimeout)
	defer cancel()
	c, err := d.DialContext(ctx, "tcp", k.address)
	if err != nil {
		return syslogFailure("connecting to the syslog server failed", err)
	}
	k.conn = c.(*tls.Conn)
	return nil
}

func (k *syslogSink) drop() {
	if k.conn != nil {
		_ = k.conn.Close()
		k.conn = nil
	}
}

// Flush ends a batch: it sends close_notify and waits for the server to close its side. Only a
// failure of the connection fails the batch; a server that keeps the connection open past the
// drain timeout has not dropped it.
func (k *syslogSink) Flush(ctx context.Context) error {
	if failed := k.failed; failed != nil {
		k.failed = nil
		return failed
	}
	if k.conn == nil {
		return nil
	}
	defer k.drop()
	if err := ctx.Err(); err != nil {
		return err
	}
	_ = k.conn.SetDeadline(time.Now().Add(SyslogDrainTimeout))
	if err := k.conn.CloseWrite(); err != nil {
		return syslogFailure("the syslog server dropped the connection", err)
	}
	if _, err := io.Copy(io.Discard, k.conn); err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return nil
		}
		return syslogFailure("the syslog server dropped the connection", err)
	}
	return nil
}

// Close drops an open connection.
func (k *syslogSink) Close() error {
	k.drop()
	return nil
}

// message is the RFC 5424 record of an item: PRI, version, timestamp, host name, app name, no
// process ID, the item's type as the message ID, no structured data, then the item's JSON. A
// record over MaxSyslogMessage loses what can be spared and is marked "truncated": an entry's
// diff first, then its user agent and reason. A checkpoint is never that long.
func (k *syslogSink) message(it Item) ([]byte, error) {
	body := it.Body
	if len(k.header(it))+len(body) > MaxSyslogMessage {
		var m map[string]any
		if err := json.Unmarshal(body, &m); err != nil {
			return nil, fmt.Errorf("an item of the audit log is no JSON: %w", err)
		}
		m["truncated"] = true
		for _, drop := range []string{"diff", "user_agent", "reason"} {
			if _, ok := m[drop]; !ok {
				continue
			}
			m[drop] = ""
			body, _ = json.Marshal(m)
			if len(k.header(it))+len(body) <= MaxSyslogMessage {
				break
			}
		}
		if len(k.header(it))+len(body) > MaxSyslogMessage {
			return nil, errors.New("an item of the audit log does not fit one syslog message")
		}
	}
	return append(k.header(it), body...), nil
}

func (k *syslogSink) header(it Item) []byte {
	msgID := "-"
	if t := strings.Map(func(r rune) rune {
		if r > 32 && r < 127 {
			return r
		}
		return -1
	}, it.Type); t != "" {
		msgID = t[:min(len(t), 32)]
	}
	return fmt.Appendf(nil, "<%d>1 %s %s %s - %s - ", syslogPri, it.Time.UTC().Format("2006-01-02T15:04:05.000000Z"), k.hostname, syslogAppName, msgID)
}

// syslogFailure names what failed and why, without the server's address: the status of a sink
// is read by more than the Instance Admin.
func syslogFailure(what string, err error) error {
	var re *egress.RefusedError
	if errors.As(err, &re) {
		return err
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Err != nil {
		err = op.Err
	}
	var ua x509.UnknownAuthorityError
	var hn x509.HostnameError
	var ci x509.CertificateInvalidError
	switch {
	case errors.As(err, &ua):
		return fmt.Errorf("%s: the server's certificate is not signed by a CA of the sink's bundle", what)
	case errors.As(err, &hn):
		return fmt.Errorf("%s: the server's certificate is not valid for the address's host name", what)
	case errors.As(err, &ci):
		return fmt.Errorf("%s: the server's certificate is not valid (%s)", what, ci.Error())
	}
	return fmt.Errorf("%s: %w", what, err)
}
