// SPDX-License-Identifier: Apache-2.0

package auditsink_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/auditsink"
	"github.com/felix-homelab/rpmgr/internal/auditsink/syslogtest"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

func syslogRow(address, ca string) *ent.AuditSink {
	return &ent.AuditSink{ID: "ask_1", Kind: "syslog", Name: "log", Settings: map[string]string{"address": address, "ca": ca}}
}

func runner() *auditsink.Runner {
	return auditsink.NewRunner(auditsink.Options{Now: time.Now, Logger: slog.New(slog.DiscardHandler)})
}

// TestSyslogSink_Test (#936; RFC 5424, RFC 5425): the test item arrives as one RFC 5424 message,
// octet-counted, over TLS to a server whose certificate chains to the sink's CA.
func TestSyslogSink_Test(t *testing.T) {
	srv := syslogtest.New(t, 0)
	if err := runner().Test(context.Background(), syslogRow(srv.Addr, srv.CA)); err != nil {
		t.Fatal(err)
	}
	msgs := srv.Messages()
	if len(msgs) != 1 {
		t.Fatalf("%d messages", len(msgs))
	}
	if !regexp.MustCompile(`^<110>1 \d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z \S+ rpmgr - audit\.test - \{`).MatchString(msgs[0]) {
		t.Fatalf("not an RFC 5424 record: %q", msgs[0])
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(msgs[0][strings.Index(msgs[0], "{"):]), &body); err != nil || body["type"] != "audit.test" {
		t.Fatalf("the JSON: %v %v", body, err)
	}
}

// TestSyslogSink_Refusals (#936): a server of another CA, a host name the certificate does not
// name, a closed port, an address the egress guard refuses and unusable settings all fail the
// item, in words that never name the address.
func TestSyslogSink_Refusals(t *testing.T) {
	srv := syslogtest.New(t, 0)
	other := syslogtest.OtherCA(t)
	for name, c := range map[string]struct {
		row  *ent.AuditSink
		want string
	}{
		"another CA":          {syslogRow(srv.Addr, other), "not signed by a CA of the sink's bundle"},
		"the system roots":    {syslogRow(srv.Addr, ""), "not signed by a CA"},
		"link-local":          {syslogRow("169.254.169.254:6514", srv.CA), "egress guard refused"},
		"metadata":            {syslogRow("[fd00:ec2::254]:6514", srv.CA), "egress guard refused"},
		"no address":          {syslogRow("", srv.CA), "no usable address"},
		"no port":             {syslogRow("127.0.0.1", srv.CA), "no usable address"},
		"port 0":              {syslogRow("127.0.0.1:0", srv.CA), "no usable address"},
		"a port too high":     {syslogRow("127.0.0.1:70000", srv.CA), "no usable address"},
		"a bundle of no CA":   {syslogRow(srv.Addr, "not a certificate"), "no certificate"},
		"a closed port":       {syslogRow("127.0.0.1:1", srv.CA), "connecting to the syslog server failed"},
		"a name nobody holds": {syslogRow("localhost:"+srv.Addr[strings.LastIndex(srv.Addr, ":")+1:], srv.CA), "not valid for the address"},
	} {
		err := runner().Test(context.Background(), c.row)
		if err == nil {
			t.Errorf("%s: shipped", name)
			continue
		}
		text := auditsink.Describe(err)
		if !strings.Contains(text, c.want) {
			t.Errorf("%s: %q, want %q", name, text, c.want)
		}
		for _, leak := range []string{"127.0.0.1", "169.254", "fd00:ec2"} {
			if strings.Contains(text, leak) {
				t.Errorf("%s: the text names the address: %q", name, text)
			}
		}
	}
	if n := len(srv.Messages()); n != 0 {
		t.Errorf("%d messages reached the server of another CA", n)
	}
}

// TestSyslogSettings (#936): what the API accepts as a syslog sink's address and CA bundle.
func TestSyslogSettings(t *testing.T) {
	srv := syslogtest.New(t, 0)
	for name, c := range map[string]struct {
		address, ca string
		ok          bool
	}{
		"a name and a port":    {"logs.example.com:6514", "", true},
		"an IPv6 literal":      {"[2001:db8::1]:6514", srv.CA, true},
		"no port":              {"logs.example.com", "", false},
		"an empty host":        {":6514", "", false},
		"a text port":          {"logs.example.com:syslog-tls", "", false},
		"a negative port":      {"logs.example.com:-1", "", false},
		"a bundle that is not": {"logs.example.com:6514", "garbage", false},
		"a valid bundle":       {"logs.example.com:6514", srv.CA, true},
		"two certificates":     {"logs.example.com:6514", srv.CA + srv.CA, true},
		"a non-certificate":    {"logs.example.com:6514", srv.CA + privateKeyBlock, false},
	} {
		if err := auditsink.CheckSyslogSettings(c.address, c.ca); (err == nil) != c.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// privateKeyBlock is a well-formed PEM block that is no certificate; its body is no key.
const privateKeyBlock = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"

// TestSyslogSettings_CABundle (#936): a CA bundle is accepted only if every block in it is a valid
// CERTIFICATE and nothing else is in it; nothing is skipped silently.
func TestSyslogSettings_CABundle(t *testing.T) {
	srv := syslogtest.New(t, 0)
	other := syslogtest.OtherCA(t)
	truncated := srv.CA[:len(srv.CA)/2]
	badCert := "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
	for name, c := range map[string]struct {
		ca   string
		want string // "" accepts
	}{
		"valid":                        {srv.CA, ""},
		"valid with blank lines":       {"\n\n" + srv.CA + "\n  \n", ""},
		"two valid":                    {srv.CA + other, ""},
		"only whitespace":              {"  \n\t\n", "no certificate"},
		"garbage":                      {"garbage", "no certificate"},
		"a private key only":           {privateKeyBlock, "not a certificate"},
		"a key after a certificate":    {srv.CA + privateKeyBlock, "not a certificate"},
		"a key before a certificate":   {privateKeyBlock + srv.CA, "not a certificate"},
		"a certificate that is no DER": {srv.CA + badCert, "cannot be parsed"},
		"trailing garbage":             {srv.CA + "trailing garbage", "not a PEM block"},
		"garbage between blocks":       {srv.CA + "garbage\n" + other, "not a PEM block"},
		"leading garbage":              {"garbage\n" + srv.CA, "no certificate"},
		"a cut-off block":              {truncated, "cannot be read"},
		"a cut-off block after a good": {srv.CA + truncated, "cannot be read"},
	} {
		err := auditsink.CheckSyslogSettings("logs.example.com:6514", c.ca)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: refused: %v", name, err)
		case c.want != "" && err == nil:
			t.Errorf("%s: accepted", name)
		case c.want != "" && !strings.Contains(err.Error(), c.want):
			t.Errorf("%s: %q, want %q", name, err, c.want)
		}
	}
}
