// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
)

// customPageFor answers one request that asks for HTML with p's page of a kind.
func customPageFor(p *Pages, host string, status int, kind, message string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = host
	r.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	p.writePageMessage(w, r, status, kind, "plain answer", message)
	return w
}

// pagesWith returns Pages that fetch from items, by ID, and the refs of those items.
func pagesWith(t *testing.T, items map[string]string, kinds map[string]string, fetches *atomic.Int32) (*Pages, []PageRef) {
	t.Helper()
	p := NewPages(PagesOptions{Fetch: func(_ context.Context, id string, _ []byte) ([]byte, error) {
		if fetches != nil {
			fetches.Add(1)
		}
		page, ok := items[id]
		if !ok {
			return nil, errors.New("controller unreachable")
		}
		return []byte(page), nil
	}})
	var refs []PageRef
	for id, kind := range kinds {
		sum := sha256.Sum256([]byte(items[id]))
		refs = append(refs, PageRef{ID: id, Kind: kind, ContentSHA256: sum[:]})
	}
	return p, refs
}

// TestPages_CustomPageCannotRunScript (docs/12, security regression tests): a custom page goes out
// with a CSP that forbids script and every load from elsewhere; a hostile hostname or maintenance
// message, and placeholder text inside them, are filled in as escaped text, never markup or a
// placeholder; an oversized page or one that does not match its hash is refused, and the
// built-in page serves until a custom one is fetched.
func TestPages_CustomPageCannotRunScript(t *testing.T) {
	const page = `<!doctype html><html><head><style>body{color:red}</style></head><body>` +
		`<h1>{{status}} at {{hostname}}</h1><p>{{message}}</p><p>ID {{request_id}}</p><p>{{other}}</p></body></html>`
	p, refs := pagesWith(t, map[string]string{"gwp_1": page}, map[string]string{"gwp_1": pageMaintenance}, nil)
	if st := p.Apply(context.Background(), refs); len(st) != 0 {
		t.Fatalf("status %v", st)
	}
	w := customPageFor(p, `<img src=x onerror=alert(1)>.example.com`, http.StatusServiceUnavailable, pageMaintenance,
		`<script>alert("x")</script> {{hostname}} & {{status}}`)
	body, h := w.Body.String(), w.Header()
	if h.Get("Content-Security-Policy") != customPageCSP || !strings.HasPrefix(customPageCSP, "default-src 'none'; style-src 'unsafe-inline'; img-src data:") ||
		strings.Contains(customPageCSP, "script-src") || h.Get("Cache-Control") != "no-store" || h.Get("X-Content-Type-Options") != "nosniff" ||
		h.Get("Content-Type") != "text/html; charset=utf-8" || w.Code != http.StatusServiceUnavailable {
		t.Fatalf("%d %v", w.Code, h)
	}
	for _, want := range []string{"<h1>503 at &lt;img src=x onerror=alert(1)&gt;.example.com</h1>",
		"<p>&lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt; {{hostname}} &amp; {{status}}</p>", "<p>{{other}}</p>", "<style>body{color:red}</style>"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "<script") || strings.Contains(body, "<img") {
		t.Errorf("markup of a value reached the page:\n%s", body)
	}
	_, id, _ := strings.Cut(body, "<p>ID ")
	if id, _, _ = strings.Cut(id, "</p>"); len(id) != 16 {
		t.Errorf("request ID %q", id)
	}
	// A kind the group did not replace serves the built-in page under its own policy.
	if w := customPageFor(p, "app.example.com", http.StatusNotFound, pageNotFound, ""); w.Header().Get("Content-Security-Policy") != pageCSP ||
		!strings.Contains(w.Body.String(), "Site not available") {
		t.Errorf("a kind without a custom page: %v", w.Header())
	}

	// Refused pages: too large, not UTF-8, not the hashed content; the built-in page serves.
	big := strings.Repeat("a", maxCustomPage+1)
	for name, item := range map[string]string{"oversized": big, "not UTF-8": "<p>\xff</p>"} {
		p, refs := pagesWith(t, map[string]string{"gwp_2": item}, map[string]string{"gwp_2": pageNotFound}, nil)
		if st := p.Apply(context.Background(), refs); len(st) != 1 || st[0].GetReason() != agentv1.NotReadyReason_NOT_READY_REASON_ENVIRONMENT {
			t.Errorf("%s: status %v", name, st)
		}
		if w := customPageFor(p, "app.example.com", http.StatusNotFound, pageNotFound, ""); w.Header().Get("Content-Security-Policy") != pageCSP {
			t.Errorf("%s: a refused page served", name)
		}
	}
	p, refs = pagesWith(t, map[string]string{"gwp_3": "<p>one</p>"}, map[string]string{"gwp_3": pageNotFound}, nil)
	refs[0].ContentSHA256 = make([]byte, 32)
	if st := p.Apply(context.Background(), refs); len(st) != 1 || !strings.Contains(st[0].GetDetail(), "hash") {
		t.Errorf("a page that does not match its hash: %v", st)
	}
}

// TestPages_FetchedLater: a page the controller cannot give yet is not ready, the built-in page
// serves meanwhile, Run fetches it, and a snapshot without it serves the built-in page again.
func TestPages_FetchedLater(t *testing.T) {
	items := map[string]string{}
	var fetches atomic.Int32
	p, _ := pagesWith(t, items, nil, &fetches)
	page := "<p>{{status}} is ours</p>"
	sum := sha256.Sum256([]byte(page))
	refs := []PageRef{{ID: "gwp_1", Kind: pageUnavailable, ContentSHA256: sum[:]}}
	if st := p.Apply(context.Background(), refs); len(st) != 1 || len(p.Status()) != 1 {
		t.Fatalf("an unreachable page: %v", st)
	}
	if w := customPageFor(p, "app.example.com", http.StatusBadGateway, pageUnavailable, ""); !strings.Contains(w.Body.String(), "Service unavailable") {
		t.Fatal("the built-in page did not serve while the custom one was missing")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	items["gwp_1"] = page // the controller answers from now on; nothing fetches before Run starts
	go p.Run(ctx)
	deadline := time.Now().Add(10 * time.Second)
	for len(p.Status()) != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if w := customPageFor(p, "app.example.com", http.StatusBadGateway, pageUnavailable, ""); w.Body.String() != "<p>502 is ours</p>" {
		t.Fatalf("after the retry: %q", w.Body.String())
	}
	n := fetches.Load()
	p.Apply(context.Background(), refs) // the same page again: no fetch
	if fetches.Load() != n {
		t.Error("a page in memory was fetched again")
	}
	p.Apply(context.Background(), nil)
	if w := customPageFor(p, "app.example.com", http.StatusBadGateway, pageUnavailable, ""); !strings.Contains(w.Body.String(), "Service unavailable") {
		t.Error("a page the snapshot dropped still serves")
	}
}

// TestRenderCustom: placeholders are filled in one pass, so a value that holds a placeholder stays
// text, and an unknown placeholder stays as it is.
func TestRenderCustom(t *testing.T) {
	got := renderCustom("{{hostname}}|{{status}}|{{message}}|{{request_id}}|{{nope}}|{{ hostname }}", `a"b`, 404, "{{request_id}}<b>", "id1")
	if want := "a&#34;b|404|{{request_id}}&lt;b&gt;|id1|{{nope}}|{{ hostname }}"; got != want {
		t.Errorf("%q, want %q", got, want)
	}
}
