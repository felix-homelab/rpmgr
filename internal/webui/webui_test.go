// SPDX-License-Identifier: Apache-2.0

package webui_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/felix-homelab/rpmgr/internal/webui"
)

const index = `<!doctype html><html><head><meta property="csp-nonce" nonce="RPMGR_CSP_NONCE">` +
	`<script type="module" nonce="RPMGR_CSP_NONCE" src="/assets/index-AbC123.js"></script></head><body></body></html>`

var nonceOf = regexp.MustCompile(`'nonce-([A-Za-z0-9+/=]+)'`)

func app() fstest.MapFS {
	return fstest.MapFS{
		"app/index.html":             {Data: []byte(index)},
		"app/assets/index-AbC123.js": {Data: []byte("console.log(1)")},
		"app/favicon.svg":            {Data: []byte("<svg/>")},
		"placeholder.html":           {Data: []byte("<style nonce=RPMGR_CSP_NONCE></style>placeholder")},
	}
}

// reply is a handler's response.
type reply struct {
	StatusCode int
	Status     string
	Header     http.Header
}

func get(t *testing.T, h http.Handler, method, target string) (reply, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
	resp := rec.Result()
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return reply{resp.StatusCode, resp.Status, resp.Header}, string(body)
}

// checkPage checks that a response is the index page with a fresh nonce in its CSP and body, and
// returns the nonce.
func checkPage(t *testing.T, resp reply, body string) string {
	t.Helper()
	csp := resp.Header.Get("Content-Security-Policy")
	m := nonceOf.FindStringSubmatch(csp)
	if resp.StatusCode != http.StatusOK || m == nil {
		t.Fatalf("%s, CSP %q", resp.Status, csp)
	}
	want := "default-src 'self'; script-src 'self'; style-src 'self' 'nonce-" + m[1] + "'; img-src 'self' data:; " +
		"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
	if csp != want {
		t.Fatalf("CSP %q, want %q", csp, want)
	}
	if strings.Contains(body, webui.NoncePlaceholder) || strings.Count(body, `nonce="`+m[1]+`"`) != 2 {
		t.Fatalf("the page does not carry the response's nonce: %s", body)
	}
	for k, v := range map[string]string{"Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store",
		"X-Content-Type-Options": "nosniff", "Referrer-Policy": "same-origin"} {
		if got := resp.Header.Get(k); got != v {
			t.Errorf("%s: %q, want %q", k, got, v)
		}
	}
	return m[1]
}

func TestHandler_App(t *testing.T) {
	h, err := webui.New(app())
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, target := range []string{"/", "/index.html", "/routes/rt_1", "/domains/example.com", "/a/../../../etc/passwd",
		"/assets/../routes?x=1"} {
		resp, body := get(t, h, http.MethodGet, target)
		n := checkPage(t, resp, body)
		if seen[n] {
			t.Fatalf("%s: nonce %s used twice", target, n)
		}
		seen[n] = true
	}

	resp, body := get(t, h, http.MethodGet, "/assets/index-AbC123.js")
	if resp.StatusCode != http.StatusOK || body != "console.log(1)" || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/javascript") ||
		resp.Header.Get("Cache-Control") != "public, max-age=31536000, immutable" || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("asset: %s %v %q", resp.Status, resp.Header, body)
	}
	resp, body = get(t, h, http.MethodGet, "/favicon.svg")
	if resp.StatusCode != http.StatusOK || body != "<svg/>" || resp.Header.Get("Cache-Control") != "no-cache" {
		t.Fatalf("favicon: %s %v %q", resp.Status, resp.Header, body)
	}
	resp, body = get(t, h, http.MethodHead, "/routes")
	if resp.StatusCode != http.StatusOK || body != "" || resp.Header.Get("Content-Security-Policy") == "" {
		t.Fatalf("HEAD: %s %q", resp.Status, body)
	}

	for _, target := range []string{"/assets/missing.js", "/assets", "/assets/", "/rpmgr.v1.NoService/Get",
		"/.well-known/acme-challenge/x"} {
		if resp, body := get(t, h, http.MethodGet, target); resp.StatusCode != http.StatusNotFound || strings.Contains(body, "<html") {
			t.Errorf("%s: %s %q", target, resp.Status, body)
		}
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		if resp, _ := get(t, h, method, "/"); resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Allow") != "GET, HEAD" {
			t.Errorf("%s: %s", method, resp.Status)
		}
	}
}

func TestHandler_Placeholder(t *testing.T) {
	fsys := app()
	for name := range fsys {
		if strings.HasPrefix(name, "app/") {
			delete(fsys, name)
		}
	}
	h, err := webui.New(fsys)
	if err != nil {
		t.Fatal(err)
	}
	resp, body := get(t, h, http.MethodGet, "/routes")
	m := nonceOf.FindStringSubmatch(resp.Header.Get("Content-Security-Policy"))
	if resp.StatusCode != http.StatusOK || m == nil || body != "<style nonce="+m[1]+"></style>placeholder" {
		t.Fatalf("%s %q", resp.Status, body)
	}
	if resp, _ := get(t, h, http.MethodGet, "/assets/index-AbC123.js"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("an asset without a build: %s", resp.Status)
	}
}

func TestNew_Refusals(t *testing.T) {
	noNonce := app()
	noNonce["app/index.html"] = &fstest.MapFile{Data: []byte("<html></html>")}
	if _, err := webui.New(noNonce); err == nil || !strings.Contains(err.Error(), webui.NoncePlaceholder) {
		t.Fatalf("an index without the nonce placeholder: %v", err)
	}
	if _, err := webui.New(fstest.MapFS{}); err == nil {
		t.Fatal("neither a build nor a placeholder: no error")
	}
}

// TestHandler_Embedded: the embedded files make a working handler, with the committed placeholder
// or with the web build, whose page loads nothing the CSP refuses: no inline script, no style
// attribute, nothing from another origin (docs/09-web-ui.md, "Security of the frontend").
func TestHandler_Embedded(t *testing.T) {
	h, err := webui.Handler()
	if err != nil {
		t.Fatal(err)
	}
	resp, body := get(t, h, http.MethodGet, "/")
	if m := nonceOf.FindStringSubmatch(resp.Header.Get("Content-Security-Policy")); m == nil || !strings.Contains(body, m[1]) {
		t.Fatalf("%s %q", resp.Status, body)
	}
	for _, tag := range regexp.MustCompile(`<script\b[^>]*>`).FindAllString(body, -1) {
		if !strings.Contains(tag, " src=") {
			t.Errorf("the page has an inline script, which the CSP refuses: %s", tag)
		}
	}
	for _, bad := range []*regexp.Regexp{
		regexp.MustCompile(`<script\b[^>]*>[^<]`),                 // a script with a body
		regexp.MustCompile(`\sstyle\s*=`),                         // a style attribute
		regexp.MustCompile(`(?:src|href)\s*=\s*"?(?:https?:)?//`), // another origin
	} {
		if m := bad.FindString(body); m != "" {
			t.Errorf("the page has %q, which the CSP refuses", m)
		}
	}
}
