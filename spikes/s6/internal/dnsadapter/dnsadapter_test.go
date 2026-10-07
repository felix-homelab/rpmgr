// SPDX-License-Identifier: Apache-2.0

package dnsadapter

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/libdns/libdns"

	"github.com/felix-homelab/rpmgr/spikes/s6/internal/cfclient"
	"github.com/felix-homelab/rpmgr/spikes/s6/internal/fakecf"
)

const marker = "rpmgr rpmgr-7f3k2q9m dnr_01JA2Z8Q6W7Y3V9K4M5N6P7Q8R"

func setup(t *testing.T, token string) (*fakecf.Server, *Provider) {
	t.Helper()
	fake := fakecf.New("good-token", "managed.test")
	for i := range 120 { // more than two pages of 50
		fake.AddZone(fakecf.Zone{Name: fmt.Sprintf("z%03d.test", i), Status: "active", Type: "full"})
	}
	fake.AddZone(fakecf.Zone{Name: "pending.test", Status: "pending", Type: "full"})
	fake.AddZone(fakecf.Zone{Name: "partial.test", Status: "active", Type: "partial"})
	srv := httptest.NewServer(fake.Handler())
	t.Cleanup(srv.Close)
	return fake, &Provider{Client: cfclient.New(srv.URL+"/client/v4", token, srv.Client()), Marker: marker}
}

func txt(name, text string) libdns.Record { return libdns.TXT{Name: name, Text: text} }

func TestAppendAndDeleteChallengeRecords(t *testing.T) {
	ctx := context.Background()
	fake, p := setup(t, "good-token")
	// A zone on the third page is found: all pages are read.
	if _, err := p.AppendRecords(ctx, "z119.test.", []libdns.Record{txt("_acme-challenge", "v0")}); err != nil {
		t.Fatalf("zone on the last page: %v", err)
	}
	recs := []libdns.Record{txt("_acme-challenge.apps", "v1"), txt("_acme-challenge.apps", "v2")}
	got, err := p.AppendRecords(ctx, "managed.test.", recs)
	if err != nil || len(got) != 2 {
		t.Fatalf("AppendRecords = %v, %v", got, err)
	}
	if v := fake.TXT("_acme-challenge.apps.managed.test"); len(v) != 2 {
		t.Fatalf("TXT at the provider = %v, want two values", v)
	}
	for _, r := range fake.Records() {
		if r.Comment != marker || r.TTL < 60 {
			t.Fatalf("record without marker or with a TTL below 60 s: %+v", r)
		}
	}
	// A foreign TXT record with the same name and content is never deleted.
	foreign, err := p.Client.CreateRecord(ctx, zoneIDOf(t, p, "managed.test"),
		cfclient.Record{Type: "TXT", Name: "_acme-challenge.apps.managed.test", Content: "v1", TTL: 60})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.DeleteRecords(ctx, "managed.test.", recs); err != nil {
		t.Fatal(err)
	}
	left := fake.TXT("_acme-challenge.apps.managed.test")
	if len(left) != 1 || left[0] != "v1" {
		t.Fatalf("after delete: %v; only the foreign record may remain", left)
	}
	foundForeign := false
	for _, r := range fake.Records() {
		foundForeign = foundForeign || r.ID == foreign.ID
	}
	if !foundForeign {
		t.Fatal("the foreign record was deleted")
	}
	// Deleting again is a no-op, not an error.
	if _, err := p.DeleteRecords(ctx, "managed.test.", recs); err != nil {
		t.Fatalf("second delete = %v", err)
	}
}

func TestAdapterRefusals(t *testing.T) {
	ctx := context.Background()
	_, p := setup(t, "good-token")
	for _, tc := range []struct {
		zone string
		rec  libdns.Record
		want error
	}{
		{"unknown.test.", txt("_acme-challenge", "v"), ErrZoneNotManaged},
		{"pending.test.", txt("_acme-challenge", "v"), ErrZoneNotManaged},
		{"partial.test.", txt("_acme-challenge", "v"), ErrZoneNotManaged},
		{"managed.test.", txt("www", "v"), nil},                                                // not a challenge name
		{"managed.test.", libdns.RR{Name: "_acme-challenge", Type: "A", Data: "1.2.3.4"}, nil}, // not TXT
	} {
		_, err := p.AppendRecords(ctx, tc.zone, []libdns.Record{tc.rec})
		if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
			t.Errorf("AppendRecords(%s, %v) = %v, want refusal %v", tc.zone, tc.rec.RR(), err, tc.want)
		}
	}
	long := *p
	long.Marker = strings.Repeat("x", 101)
	if _, err := long.AppendRecords(ctx, "managed.test.", []libdns.Record{txt("_acme-challenge", "v")}); err == nil {
		t.Error("a marker above 100 characters was accepted")
	}
}

func TestBadTokenIsAnAPIError(t *testing.T) {
	_, p := setup(t, "wrong-token")
	_, err := p.AppendRecords(context.Background(), "managed.test.", []libdns.Record{txt("_acme-challenge", "v")})
	var ae *cfclient.APIError
	if !errors.As(err, &ae) || ae.Status != 403 {
		t.Fatalf("AppendRecords with a wrong token = %v, want HTTP 403 APIError", err)
	}
}

func TestTokenFileMustBePrivate(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "token")
	if err := os.WriteFile(f, []byte("secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := cfclient.NewFromTokenFile(cfclient.DefaultBaseURL, f, nil); err == nil {
		t.Fatal("a world-readable token file was accepted")
	}
	if err := os.Chmod(f, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := cfclient.NewFromTokenFile(cfclient.DefaultBaseURL, f, nil); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte(" \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := cfclient.NewFromTokenFile(cfclient.DefaultBaseURL, empty, nil); err == nil {
		t.Fatal("an empty token file was accepted")
	}
}

func zoneIDOf(t *testing.T, p *Provider, name string) string {
	t.Helper()
	id, _, err := p.zoneID(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
