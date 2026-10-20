// SPDX-License-Identifier: Apache-2.0

package release_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/felix-homelab/rpmgr/internal/release"
)

// TestGitHubReleases: the listing asks for one page and returns the published releases with their
// pre-release flag, newest first, leaving out drafts and tags that are no release version.
func TestGitHubReleases(t *testing.T) {
	var asked string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = r.URL.RequestURI()
		_, _ = w.Write([]byte(`[{"tag_name":"v1.6.0-rc.1","prerelease":true},{"tag_name":"v1.5.0"},{"tag_name":"v1.4.9","draft":true},
			{"tag_name":"spike/s9"},{"tag_name":"1.4.8"},{"tag_name":"v1.4.7+build"},{"tag_name":"v1.4.2","extra":{"x":1}}]`))
	}))
	defer srv.Close()
	got, err := release.GitHubReleases{API: srv.URL + "/repos/x/releases", Client: srv.Client()}.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if asked != "/repos/x/releases?per_page=30" {
		t.Errorf("asked %s", asked)
	}
	want := []release.Listed{{Version: "1.6.0-rc.1", Prerelease: true}, {Version: "1.5.0"}, {Version: "1.4.2"}}
	if len(got) != len(want) {
		t.Fatalf("listed %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("listed %+v, want %+v", got, want)
		}
	}
}

// TestGitHubReleasesRefusals: rate limits are reported with when the source accepts requests
// again; other failures, a malformed answer and an oversized one are errors.
func TestGitHubReleasesRefusals(t *testing.T) {
	now := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	reset := now.Add(37 * time.Minute)
	for name, tc := range map[string]struct {
		handler func(w http.ResponseWriter)
		until   time.Time // zero: no rate limit
	}{
		"429 with Retry-After": {func(w http.ResponseWriter) {
			w.Header().Set("Retry-After", "120")
			w.WriteHeader(http.StatusTooManyRequests)
		}, now.Add(2 * time.Minute)},
		"403 with no requests left": {func(w http.ResponseWriter) {
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(reset.Unix(), 10))
			w.WriteHeader(http.StatusForbidden)
		}, reset},
		"429 without a hint": {func(w http.ResponseWriter) { w.WriteHeader(http.StatusTooManyRequests) }, now.Add(time.Hour)},
		"403 otherwise":      {func(w http.ResponseWriter) { w.WriteHeader(http.StatusForbidden) }, time.Time{}},
		"500":                {func(w http.ResponseWriter) { w.WriteHeader(http.StatusInternalServerError) }, time.Time{}},
		"malformed":          {func(w http.ResponseWriter) { _, _ = w.Write([]byte(`{"message":"x"}`)) }, time.Time{}},
		"oversized": {func(w http.ResponseWriter) {
			_, _ = w.Write([]byte("[" + strings.Repeat(" ", 4<<20) + "]"))
		}, time.Time{}},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { tc.handler(w) }))
		_, err := release.GitHubReleases{API: srv.URL, Client: srv.Client(), Now: func() time.Time { return now }}.List(context.Background())
		srv.Close()
		var rl *release.RateLimitedError
		switch {
		case err == nil:
			t.Errorf("%s: no error", name)
		case tc.until.IsZero() && errors.As(err, &rl):
			t.Errorf("%s: a rate limit: %v", name, err)
		case !tc.until.IsZero() && (!errors.As(err, &rl) || !rl.Until.Equal(tc.until)):
			t.Errorf("%s: %v, want a rate limit until %s", name, err, tc.until)
		}
	}
}

// TestGitHubRateLimited: a download the source refuses for its rate limit says so.
func TestGitHubRateLimited(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	_, err := release.GitHub{Base: srv.URL, Version: "1.4.2", Client: srv.Client()}.Open(context.Background(), "manifest.json")
	var rl *release.RateLimitedError
	if !errors.As(err, &rl) || time.Until(rl.Until) <= 0 {
		t.Errorf("%v", err)
	}
}
