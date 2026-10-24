// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed" // the page template
	"encoding/base64"
	"html/template"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// The gateway's own pages (docs/03-connections.md, "HTTP routes"), which a browser gets instead of bare
// text for a name no route serves and for the errors the gateway makes itself (D87). They are
// self-contained: one inline style, allowed by its hash, and nothing else.

//go:embed page.html
var pageSource string

var (
	pageTemplate = template.Must(template.New("page").Parse(pageSource))
	pageCSP      = "default-src 'none'; style-src 'sha256-" + styleHash(pageSource) +
		"'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)

// styleHash is the base64 SHA-256 of the one inline style of a page, as a CSP source names it.
func styleHash(page string) string {
	_, rest, _ := strings.Cut(page, "<style>")
	style, _, _ := strings.Cut(rest, "</style>")
	sum := sha256.Sum256([]byte(style))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// The kinds of page, which the template words differently.
const (
	pageNotFound    = "not-found"   // a name, or a path of it, that no route serves
	pageUnavailable = "unavailable" // the gateway's own 502, 503 or 504: no live target, refused, too slow
	pageMaintenance = "maintenance" // the 503 of a route in maintenance (D88)
)

// pageTitles are the pages' headings, by kind.
var pageTitles = map[string]string{pageNotFound: "Site not available", pageUnavailable: "Service unavailable",
	pageMaintenance: "Down for maintenance"}

// The plain-text answer for a name without a route, kept for clients that do not ask for HTML.
const noRouteText = "no route for this host and path"

// page is what the template shows.
type page struct {
	Kind, Title, StatusText, Host, Message string
	Status                                 int
}

// pageRequest is what a page answers to: the client's host and whether it asked for HTML. The
// proxy calls its error handler with the request it sent upstream, whose Host and headers the
// route may have rewritten; proxy keeps the client's in the context.
type pageRequest struct {
	host string
	html bool
}

type pageRequestKey struct{}

// withPageRequest keeps r's own host and Accept in ctx for a page answered later.
func withPageRequest(ctx context.Context, r *http.Request) context.Context {
	return context.WithValue(ctx, pageRequestKey{}, pageRequest{host: r.Host, html: wantsHTML(r)})
}

// pageRequestOf is the client's host and Accept: those kept in r's context, or else r's own.
func pageRequestOf(r *http.Request) pageRequest {
	if p, ok := r.Context().Value(pageRequestKey{}).(pageRequest); ok {
		return p
	}
	return pageRequest{host: r.Host, html: wantsHTML(r)}
}

// maxShownHost bounds the hostname a page repeats: a DNS name is at most 253 characters.
const maxShownHost = 253

// writeMaintenance answers a request to a route in maintenance: 503 with the maintenance page and
// the route's message, or the message as text.
func (p *Pages) writeMaintenance(w http.ResponseWriter, r *http.Request, message string) {
	text := "Service Unavailable: down for maintenance"
	if message != "" {
		text += "\n\n" + message
	}
	p.writePageMessage(w, r, http.StatusServiceUnavailable, pageMaintenance, text, message)
}

// writePage answers a request with one of the gateway's pages if the client asks for HTML, and with
// text, as before the pages existed, if it does not. The page is the group's own of the kind, if p
// holds one (D132), or else the built-in one; p may be nil.
func (p *Pages) writePage(w http.ResponseWriter, r *http.Request, status int, kind, text string) {
	p.writePageMessage(w, r, status, kind, text, "")
}

// writePageMessage is writePage with a message the page shows as text.
func (p *Pages) writePageMessage(w http.ResponseWriter, r *http.Request, status int, kind, text, message string) {
	client := pageRequestOf(r)
	if !client.html {
		http.Error(w, text, status)
		return
	}
	host := hostOnly(client.host)
	if len(host) > maxShownHost {
		host = host[:maxShownHost]
	}
	host, message = strings.ToValidUTF8(host, "�"), strings.ToValidUTF8(message, "�")
	var b bytes.Buffer
	csp := pageCSP
	if custom, ok := p.page(kind); ok {
		id := ""
		if strings.Contains(custom, "{{request_id}}") {
			id = newRequestID()
			p.o.Logger.Info("custom page", "request_id", id, "host", host, "status", status, "page", kind)
		}
		b.WriteString(renderCustom(custom, host, status, message, id))
		csp = customPageCSP
	} else if err := pageTemplate.Execute(&b, page{Kind: kind, Title: pageTitles[kind], Status: status, StatusText: http.StatusText(status),
		Host: host, Message: message}); err != nil {
		http.Error(w, text, status)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", csp)
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Length", strconv.Itoa(b.Len()))
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(b.Bytes())
	}
}

// wantsHTML reports whether a request's Accept header names text/html with a quality above zero:
// browsers send it when they load a page; API clients and curl do not, and keep getting text.
func wantsHTML(r *http.Request) bool {
	for _, v := range r.Header.Values("Accept") {
		for part := range strings.SplitSeq(v, ",") {
			mt, params, err := mime.ParseMediaType(strings.TrimSpace(part))
			if err != nil || mt != "text/html" {
				continue
			}
			if q, ok := params["q"]; ok {
				if f, err := strconv.ParseFloat(q, 64); err != nil || f <= 0 {
					continue
				}
			}
			return true
		}
	}
	return false
}

// hostOnly returns a Host header without its port, and an IPv6 literal without its brackets.
func hostOnly(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return host[1 : len(host)-1]
	}
	return host
}
