// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/gateway"
	"github.com/felix-homelab/rpmgr/internal/routes"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/gatewaypage"
)

// PreviewPath is where the controller serves previews of gateway pages (D136).
const PreviewPath = "/gateway-page-preview/"

// previewLifetime is how long a preview link works (docs/03-connections.md, "Timeouts, keepalive
// and backoff").
const previewLifetime = 5 * time.Minute

// The sample values a preview fills in, as a visitor's request would.
const (
	sampleMessage   = "Back soon: the service is being updated."
	sampleRequestID = "0123456789abcdef"
	sampleHost      = "www.example.com"
)

// PagePreviews serves the previews of gateway pages (D136). PreviewGatewayPage, which the API
// authorizes, hands out a link that names the group, the kind and the page's hash and ends a few
// minutes later, signed with Key; the link alone then shows the page, rendered by the gateways' own
// code with sample values, under the page's CSP and a sandbox. A link of a page that changed since
// shows nothing.
type PagePreviews struct {
	DB *store.DB
	// Sys is the controller's system scope, in which the handler reads the page.
	Sys context.Context
	// Key signs the links; the controller derives it from the KEK, so every replica accepts them.
	Key []byte
	Now func() time.Time
}

// errPagePreview is every refused preview link: unsigned, expired, or of a page that changed.
var errPagePreview = errors.New("this preview has expired or its page changed; open the preview again")

// link returns the signed path of a preview of a group's page of a kind whose content hash is sum,
// or "-" for the built-in page, and when it ends.
func (p *PagePreviews) link(group string, kind gatewaypage.Kind, sum string) (string, time.Time) {
	end := p.Now().Add(previewLifetime).Truncate(time.Second)
	payload := strings.Join([]string{group, string(kind), sum, strconv.FormatInt(end.Unix(), 10)}, ".")
	mac := hmac.New(sha256.New, p.Key)
	mac.Write([]byte(payload))
	enc := base64.RawURLEncoding
	return PreviewPath + enc.EncodeToString([]byte(payload)) + "." + enc.EncodeToString(mac.Sum(nil)), end
}

// verify checks a link's signature and end and returns what it names.
func (p *PagePreviews) verify(token string) (group string, kind gatewaypage.Kind, sum string, err error) {
	enc := base64.RawURLEncoding
	b64, sig, ok := strings.Cut(token, ".")
	payload, err1 := enc.DecodeString(b64)
	got, err2 := enc.DecodeString(sig)
	if !ok || err1 != nil || err2 != nil {
		return "", "", "", errPagePreview
	}
	mac := hmac.New(sha256.New, p.Key)
	mac.Write(payload)
	parts := strings.Split(string(payload), ".")
	if !hmac.Equal(got, mac.Sum(nil)) || len(parts) != 4 {
		return "", "", "", errPagePreview
	}
	end, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil || !p.Now().Before(time.Unix(end, 0)) {
		return "", "", "", errPagePreview
	}
	return parts[0], gatewaypage.Kind(parts[1]), parts[2], nil
}

// PreviewGatewayPage implements GatewayService.
func (g *Gateways) PreviewGatewayPage(ctx context.Context, req *connect.Request[rpmgrv1.PreviewGatewayPageRequest]) (
	*connect.Response[rpmgrv1.PreviewGatewayPageResponse], error) {
	if g.Previews == nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("apisvc: this controller shows no previews"))
	}
	kind, err := pageKindOf(req.Msg.GetKind())
	if err != nil {
		return nil, err
	}
	c := g.DB.ReadClient()
	group, err := c.GatewayGroup.Get(ctx, req.Msg.GetGatewayGroupId())
	if err != nil {
		return nil, storeError(err)
	}
	sum := "-"
	switch page, err := c.GatewayPage.Query().Where(gatewaypage.GatewayGroupID(group.ID), gatewaypage.KindEQ(kind)).Only(ctx); {
	case err == nil:
		sum = hex.EncodeToString(page.ContentSha256)
	case !ent.IsNotFound(err):
		return nil, storeError(err)
	}
	url, end := g.Previews.link(group.ID, kind, sum)
	return connect.NewResponse(&rpmgrv1.PreviewGatewayPageResponse{Url: url, ExpireTime: timestamppb.New(end)}), nil
}

// ServeHTTP shows the page a preview link names, as the group's gateways send it: with sample
// values, under the page's own CSP, which may only be framed by the web UI, plus a sandbox, so that
// the page has an opaque origin and runs no script even when opened on its own.
func (p *PagePreviews) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	body, csp, err := p.render(strings.TrimPrefix(r.URL.Path, PreviewPath))
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Referrer-Policy", "no-referrer")
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", strings.Replace(csp, "frame-ancestors 'none'", "frame-ancestors 'self'", 1)+"; sandbox")
	h.Set("Content-Length", strconv.Itoa(len(body)))
	if r.Method != http.MethodHead {
		_, _ = w.Write(body) //nolint:gosec // G705: the group's own page, served under its CSP that allows no script, and a sandbox
	}
}

// render makes the page a link names, if the link is good and the page unchanged.
func (p *PagePreviews) render(token string) ([]byte, string, error) {
	group, kind, sum, err := p.verify(token)
	if err != nil {
		return nil, "", err
	}
	var (
		row   *ent.GatewayGroup
		page  *ent.GatewayPage
		pages []*ent.GatewayPage
	)
	err = store.ReadTx(p.Sys, p.DB, func(tx *ent.Tx, _ store.Revision) error {
		var err error
		if row, err = tx.GatewayGroup.Get(p.Sys, group); err != nil {
			return err
		}
		pages, err = tx.GatewayPage.Query().Where(gatewaypage.GatewayGroupID(group), gatewaypage.KindEQ(kind)).All(p.Sys)
		return err
	})
	switch {
	case ent.IsNotFound(err):
		return nil, "", errPagePreview
	case err != nil:
		return nil, "", fmt.Errorf("the preview cannot be read now: %w", err)
	}
	if len(pages) > 0 {
		page = pages[0]
	}
	if page == nil && sum != "-" || page != nil && hex.EncodeToString(page.ContentSha256) != sum {
		return nil, "", errPagePreview
	}
	host := sampleHost
	if len(row.PublicHostnames) > 0 {
		host = row.PublicHostnames[0]
	}
	status, message := http.StatusServiceUnavailable, ""
	switch kind {
	case gatewaypage.KindNotFound:
		status = http.StatusNotFound
	case gatewaypage.KindMaintenance:
		message = sampleMessage
	}
	html := ""
	if page != nil {
		html = page.HTML
	}
	return gateway.RenderPage(routes.PageKinds[kind], html, page != nil, host, status, message, sampleRequestID)
}
