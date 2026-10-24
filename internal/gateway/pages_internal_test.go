// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// TestWantsHTML: HTML goes to a client whose Accept names text/html with a quality above zero,
// in any case and position; others, and a client without Accept, get text.
func TestWantsHTML(t *testing.T) {
	for _, tc := range []struct {
		accept []string
		want   bool
	}{
		{nil, false},
		{[]string{""}, false},
		{[]string{"*/*"}, false},
		{[]string{"application/json"}, false},
		{[]string{"text/plain, text/*"}, false},
		{[]string{"text/html"}, true},
		{[]string{"TEXT/HTML; charset=utf-8"}, true},
		{[]string{"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}, true},
		{[]string{"application/json, text/html;q=0.1"}, true},
		{[]string{"text/html;q=0"}, false},
		{[]string{"text/html;q=0.000"}, false},
		{[]string{"text/html;q=bogus"}, false},
		{[]string{"text/html;;;"}, false},
		{[]string{"application/json", "text/html"}, true},
	} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		for _, a := range tc.accept {
			r.Header.Add("Accept", a)
		}
		if got := wantsHTML(r); got != tc.want {
			t.Errorf("Accept %q: %v, want %v", tc.accept, got, tc.want)
		}
	}
}

// pageFor answers one request with writePage and returns the recorder.
func pageFor(method, host, accept string, status int, kind string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "/", nil)
	r.Host = host
	if accept != "" {
		r.Header.Set("Accept", accept)
	}
	w := httptest.NewRecorder()
	(*Pages)(nil).writePage(w, r, status, kind, "plain answer")
	return w
}

// TestWritePage: a page carries its status, a CSP that allows exactly its inline style, no-store
// and nosniff, and the hostname without its port, escaped and bounded; HEAD gets the headers
// alone; a client that does not ask for HTML gets the text.
func TestWritePage(t *testing.T) {
	w := pageFor(http.MethodGet, "app.example.com:8443", "text/html", http.StatusNotFound, pageNotFound)
	body := w.Body.String()
	h := w.Header()
	if w.Code != http.StatusNotFound || h.Get("Content-Type") != "text/html; charset=utf-8" || h.Get("Cache-Control") != "no-store" ||
		h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Content-Length") != strconv.Itoa(len(body)) {
		t.Fatalf("%d %v", w.Code, h)
	}
	if !strings.Contains(body, "<title>Site not available</title>") || !strings.Contains(body, ">app.example.com</span>") ||
		!strings.Contains(body, "404 · Not Found") || strings.Contains(body, "8443") || strings.Contains(body, "SPDX") {
		t.Errorf("body: %s", body)
	}
	_, rest, _ := strings.Cut(body, "<style>")
	style, _, ok := strings.Cut(rest, "</style>")
	sum := sha256.Sum256([]byte(style))
	want := "default-src 'none'; style-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) +
		"'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
	if !ok || h.Get("Content-Security-Policy") != want {
		t.Errorf("CSP %q, want %q", h.Get("Content-Security-Policy"), want)
	}
	if strings.Count(body, "<style>") != 1 || strings.Contains(body, "<script") || strings.Contains(body, "style=") {
		t.Error("the page has more than its one inline style")
	}

	// Whatever the Host says is text.
	w = pageFor(http.MethodGet, `"><script>alert(1)</script>&'`, "text/html", http.StatusServiceUnavailable, pageUnavailable)
	if body := w.Body.String(); strings.Contains(body, "<script>alert") || !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;&amp;&#39;") ||
		!strings.Contains(body, "<title>Service unavailable</title>") || !strings.Contains(body, "503 · Service Unavailable") {
		t.Errorf("escaping: %s", body)
	}
	long := strings.Repeat("a", 300) + ".example.com"
	if body := pageFor(http.MethodGet, long, "text/html", http.StatusNotFound, pageNotFound).Body.String(); strings.Contains(body, long[:254]) ||
		!strings.Contains(body, long[:253]) {
		t.Error("a long hostname is not cut at 253 characters")
	}

	// HEAD: the same headers, no body.
	w = pageFor(http.MethodHead, "app.example.com", "text/html", http.StatusNotFound, pageNotFound)
	if w.Code != http.StatusNotFound || w.Body.Len() != 0 || w.Header().Get("Content-Length") == "0" ||
		w.Header().Get("Content-Security-Policy") == "" {
		t.Errorf("HEAD: %d %q %v", w.Code, w.Body.String(), w.Header())
	}

	// No HTML wanted: the text, as before.
	for _, accept := range []string{"", "application/json", "text/html;q=0"} {
		w = pageFor(http.MethodGet, "app.example.com", accept, http.StatusBadGateway, pageUnavailable)
		if w.Code != http.StatusBadGateway || w.Body.String() != "plain answer\n" || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain") ||
			w.Header().Get("Content-Security-Policy") != "" {
			t.Errorf("Accept %q: %d %q %v", accept, w.Code, w.Body.String(), w.Header())
		}
	}
}
