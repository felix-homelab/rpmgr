// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/api"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/storetest"
)

// TestCSRF: a POST from another origin, one a browser marks cross-site, and one with a content
// type a form can send never reach the method; the controller's own origin and its aliases, and
// requests without an Origin (the CLI), do; an unreadable origin list refuses.
func TestCSRF(t *testing.T) {
	sd := testFile(t, "csrf", method{name: "Do", authz: &rpmgrv1.Authz{Permission: authz.PermPublic}})
	var failOrigins bool
	srv, err := api.New(api.Options{DB: storetest.Migrated(t, store.SQLite), Sys: storetest.SystemCtx(t), Sealer: testSealer(t),
		Resolver:           func(context.Context, string) (string, error) { return "", api.ErrNotFound },
		OperatorsMayEnroll: func(context.Context, string) (bool, error) { return false, nil },
		Origins: func(context.Context) ([]string, error) {
			if failOrigins {
				return nil, errors.New("the database is down")
			}
			return []string{"https://panel.example.com", "https://alias.example.com:8443"}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	if err := srv.Mount(mux, sd, handlers(sd)); err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewServer(mux)
	t.Cleanup(hs.Close)
	post := func(contentType string, header map[string]string) int {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, hs.URL+"/"+string(sd.FullName())+"/Do", strings.NewReader("{}"))
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		for k, v := range header {
			req.Header.Set(k, v)
		}
		// A browser sends the host it was given, which is the Origin's for a same-origin call.
		if o, err := url.Parse(header["Origin"]); err == nil && o.Host != "" {
			req.Host = o.Host
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	for name, c := range map[string]struct {
		contentType string
		header      map[string]string
		want        int
	}{
		"the CLI":           {"application/json", nil, http.StatusOK},
		"own origin":        {"application/json", map[string]string{"Origin": "https://panel.example.com"}, http.StatusOK},
		"an alias":          {"application/json; charset=utf-8", map[string]string{"Origin": "https://alias.example.com:8443"}, http.StatusOK},
		"same-origin fetch": {"application/json", map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "https://panel.example.com"}, http.StatusOK},
		"another origin":    {"application/json", map[string]string{"Origin": "https://evil.example"}, http.StatusForbidden},
		"another scheme":    {"application/json", map[string]string{"Origin": "http://panel.example.com"}, http.StatusForbidden},
		"another port":      {"application/json", map[string]string{"Origin": "https://alias.example.com"}, http.StatusForbidden},
		"marked cross-site": {"application/json", map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
		"a form":            {"application/x-www-form-urlencoded", nil, http.StatusUnsupportedMediaType},
		"a multipart form":  {"multipart/form-data; boundary=x", nil, http.StatusUnsupportedMediaType},
		"plain text":        {"text/plain", nil, http.StatusUnsupportedMediaType},
		"no content type":   {"", nil, http.StatusUnsupportedMediaType},
	} {
		if got := post(c.contentType, c.header); got != c.want {
			t.Errorf("%s: %d, want %d", name, got, c.want)
		}
	}
	failOrigins = true
	if got := post("application/json", map[string]string{"Origin": "https://panel.example.com"}); got != http.StatusForbidden {
		t.Errorf("origins unreadable: %d", got)
	}
}
