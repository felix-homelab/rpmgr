// SPDX-License-Identifier: Apache-2.0

// Package webui serves the web UI (docs/09-web-ui.md, "Frontend architecture"): the single-page
// app that `npm run build` in web/ writes to ui/app, embedded in the binary, or a placeholder page
// in a binary built without it.
package webui

import (
	"bytes"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

//go:embed all:ui
var embedded embed.FS

// NoncePlaceholder is what the build writes where each response's CSP nonce goes
// (web/vite.config.ts, html.cspNonce).
const NoncePlaceholder = "RPMGR_CSP_NONCE"

// policy is the Content Security Policy of every response (docs/09-web-ui.md, "Security of the
// frontend"); %s is the response's nonce.
const policy = "default-src 'self'; script-src 'self'; style-src 'self' 'nonce-%s'; img-src 'self' data:; " +
	"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

// Handler serves the embedded UI.
func Handler() (http.Handler, error) {
	ui, err := fs.Sub(embedded, "ui")
	if err != nil {
		return nil, err
	}
	return New(ui)
}

// New serves the UI in fsys: the build in app/, or placeholder.html without one. Every path that is
// not a file of the build gets index.html, for the SPA's router to show; paths of the API and of
// /.well-known/ that reach it are not found.
func New(fsys fs.FS) (http.Handler, error) {
	app, err := fs.Sub(fsys, "app")
	if err != nil {
		return nil, err
	}
	index, err := fs.ReadFile(app, "index.html")
	if errors.Is(err, fs.ErrNotExist) {
		app = nil
		index, err = fs.ReadFile(fsys, "placeholder.html")
	}
	if err != nil {
		return nil, err
	}
	if !bytes.Contains(index, []byte(NoncePlaceholder)) {
		return nil, fmt.Errorf("webui: index.html has no %s placeholder for the CSP nonce", NoncePlaceholder)
	}
	return &handler{app: app, index: index}, nil
}

type handler struct {
	app   fs.FS // nil without a build
	index []byte
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	nonce, err := newNonce()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	hd := w.Header()
	hd.Set("Content-Security-Policy", fmt.Sprintf(policy, nonce))
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("Referrer-Policy", "same-origin")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		hd.Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	switch {
	case strings.HasPrefix(name, "rpmgr.") || strings.HasPrefix(name, ".well-known/"):
		http.NotFound(w, r)
	case h.serveFile(w, r, name):
	case name == "assets" || strings.HasPrefix(name, "assets/"):
		http.NotFound(w, r) // a missing build file is never the app
	default:
		hd.Set("Content-Type", "text/html; charset=utf-8")
		hd.Set("Cache-Control", "no-store")
		page := bytes.ReplaceAll(h.index, []byte(NoncePlaceholder), []byte(nonce))
		http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(page))
	}
}

// serveFile serves the build's file name, if it is one other than index.html, and reports whether
// it did. Files under assets/ have content hashes in their names and are cached for a year.
func (h *handler) serveFile(w http.ResponseWriter, r *http.Request, name string) bool {
	if h.app == nil || name == "" || name == "index.html" {
		return false
	}
	f, err := h.app.Open(name)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return false
	}
	rs, ok := f.(io.ReadSeeker)
	if !ok {
		return false
	}
	if strings.HasPrefix(name, "assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	http.ServeContent(w, r, name, st.ModTime(), rs)
	return true
}

// newNonce returns 128 random bits for a response's CSP nonce.
func newNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}
