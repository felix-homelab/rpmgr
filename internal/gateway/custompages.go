// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
)

// maxCustomPage is the largest custom page (docs/03-connections.md, "Timeouts, keepalive and
// backoff"); a fetched page above it is refused.
const maxCustomPage = 64 << 10

// customPageCSP is the policy of a custom page (docs/03-connections.md, "HTTP routes"): its own
// styles and data: images, no script, and nothing loaded from elsewhere.
const customPageCSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

// pageKinds are the built-in page each kind of custom page replaces.
var pageKinds = map[rpmgrv1.GatewayPageKind]string{
	rpmgrv1.GatewayPageKind_GATEWAY_PAGE_KIND_NOT_FOUND:   pageNotFound,
	rpmgrv1.GatewayPageKind_GATEWAY_PAGE_KIND_UNAVAILABLE: pageUnavailable,
	rpmgrv1.GatewayPageKind_GATEWAY_PAGE_KIND_MAINTENANCE: pageMaintenance,
}

// PageRef is a custom page of the gateway's group as its snapshot names it.
type PageRef struct {
	ID            string
	Kind          string // pageNotFound, pageUnavailable or pageMaintenance
	ContentSHA256 []byte
}

// PagesOptions configure Pages.
type PagesOptions struct {
	// Fetch fetches a page by ID and content hash, normally agent.Control.Fetch.
	Fetch func(ctx context.Context, id string, hash []byte) ([]byte, error)
	// OnChange is told that a page became ready without a new snapshot: a retry fetched it. It
	// must not block; it may be nil.
	OnChange func()
	Logger   *slog.Logger
}

// Pages holds the custom pages of the gateway's group (D132): the HTML of each kind its snapshot
// names, fetched by hash and kept in memory. A kind without a page, or whose page is not fetched
// yet, serves the built-in page; a page the gateway cannot fetch is retried in the background.
type Pages struct {
	o     PagesOptions
	retry chan struct{}

	mu      sync.Mutex
	want    []PageRef
	byKind  map[string]string // the HTML served, by kind
	loaded  map[string]string // by hex content hash
	missing map[string]missingPage
}

// missingPage is a page that could not be fetched yet, and why.
type missingPage struct {
	ref PageRef
	err string
}

// NewPages returns an empty set; Run retries what Apply could not fetch.
func NewPages(o PagesOptions) *Pages {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	return &Pages{o: o, retry: make(chan struct{}, 1), byKind: map[string]string{}, loaded: map[string]string{},
		missing: map[string]missingPage{}}
}

// Apply makes refs the pages served: each from memory or from Fetch, checked against its hash and
// size. Those it cannot fetch are returned not ready and retried by Run; their kinds serve the
// built-in page meanwhile.
func (p *Pages) Apply(ctx context.Context, refs []PageRef) []*agentv1.ResourceStatus {
	p.mu.Lock()
	p.want = refs
	keep := map[string]bool{}
	for _, r := range refs {
		keep[hex.EncodeToString(r.ContentSHA256)] = true
	}
	for key := range p.loaded {
		if !keep[key] {
			delete(p.loaded, key)
		}
	}
	for key := range p.missing {
		if !keep[key] {
			delete(p.missing, key)
		}
	}
	p.mu.Unlock()
	var status []*agentv1.ResourceStatus
	for _, r := range refs {
		if err := p.load(ctx, r); err != nil {
			status = append(status, pageNotLoaded(r.ID, err.Error()))
		}
	}
	p.rebuild()
	return status
}

func pageNotLoaded(id, err string) *agentv1.ResourceStatus {
	return &agentv1.ResourceStatus{ResourceId: id, Reason: agentv1.NotReadyReason_NOT_READY_REASON_ENVIRONMENT,
		Detail: "page not loaded: " + err}
}

// load fetches one page, or records it as missing.
func (p *Pages) load(ctx context.Context, r PageRef) error {
	key := hex.EncodeToString(r.ContentSHA256)
	p.mu.Lock()
	_, ok := p.loaded[key]
	p.mu.Unlock()
	if ok {
		return nil
	}
	err := errors.New("no fetch")
	var page []byte
	if p.o.Fetch != nil {
		fctx, cancel := context.WithTimeout(ctx, fetchTimeout)
		page, err = p.o.Fetch(fctx, r.ID, r.ContentSHA256)
		cancel()
	}
	if err == nil {
		err = checkPage(page, r.ContentSHA256)
	}
	p.mu.Lock()
	if err != nil {
		p.missing[key] = missingPage{ref: r, err: err.Error()}
		p.mu.Unlock()
		select {
		case p.retry <- struct{}{}:
		default:
		}
		return err
	}
	_, was := p.missing[key]
	delete(p.missing, key)
	p.loaded[key] = string(page)
	p.mu.Unlock()
	if was && p.o.OnChange != nil {
		p.o.OnChange()
	}
	return nil
}

// checkPage checks a fetched page against its hash, the size limit and UTF-8.
func checkPage(page, hash []byte) error {
	sum := sha256.Sum256(page)
	switch {
	case !bytes.Equal(sum[:], hash):
		return errors.New("the page does not match its hash")
	case len(page) > maxCustomPage:
		return fmt.Errorf("the page has %d bytes, more than %d", len(page), maxCustomPage)
	case !utf8.Valid(page):
		return errors.New("the page is not UTF-8")
	}
	return nil
}

// rebuild maps each kind of the snapshot to its page, if fetched.
func (p *Pages) rebuild() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.byKind = map[string]string{}
	for _, r := range p.want {
		if page, ok := p.loaded[hex.EncodeToString(r.ContentSHA256)]; ok {
			p.byKind[r.Kind] = page
		}
	}
}

// Run retries the pages Apply could not fetch, with backoff, until ctx ends.
func (p *Pages) Run(ctx context.Context) {
	wait := fetchRetryMin
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.retry:
		}
		for {
			p.mu.Lock()
			var missing []PageRef
			for _, m := range p.missing {
				missing = append(missing, m.ref)
			}
			p.mu.Unlock()
			if len(missing) == 0 {
				wait = fetchRetryMin
				break
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			for _, r := range missing {
				if err := p.load(ctx, r); err != nil {
					p.o.Logger.Debug("custom page still not loaded", "page", r.ID, "error", err)
				}
			}
			p.rebuild()
			wait = min(2*wait, fetchRetryMax)
			select {
			case <-p.retry:
			default:
			}
		}
	}
}

// Status returns the pages of the snapshot that are not fetched, as not ready.
func (p *Pages) Status() []*agentv1.ResourceStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []*agentv1.ResourceStatus
	for _, r := range p.want {
		if m, ok := p.missing[hex.EncodeToString(r.ContentSHA256)]; ok {
			out = append(out, pageNotLoaded(r.ID, m.err))
		}
	}
	return out
}

// page returns the custom page of a kind, if the group has one and it is fetched.
func (p *Pages) page(kind string) (string, bool) {
	if p == nil {
		return "", false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	page, ok := p.byKind[kind]
	return page, ok
}

// renderCustom fills in a custom page's placeholders, each as escaped HTML text, in one pass, so
// that a value never brings a placeholder or markup of its own; any other {{…}} stays as it is.
func renderCustom(page, host string, status int, message, requestID string) string {
	return strings.NewReplacer("{{hostname}}", html.EscapeString(host), "{{status}}", strconv.Itoa(status),
		"{{message}}", html.EscapeString(message), "{{request_id}}", requestID).Replace(page)
}

// newRequestID is a random ID a custom page shows and the gateway logs, so that a visitor's report
// finds the log line.
func newRequestID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
