// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/felix-homelab/rpmgr/internal/dns"
	"github.com/felix-homelab/rpmgr/internal/proxyenv"
	"github.com/felix-homelab/rpmgr/internal/secret"
)

// Levels of an output line. A check the probe expects to fail, such as the under-scoped token, is
// a PASS when it fails.
const (
	pass = "PASS"
	fail = "FAIL"
	info = "INFO"
)

// report prints one line per finding and scrubs every token from it.
type report struct {
	w                  io.Writer
	secrets            []string
	passes, fails, inf int
}

// hide registers a token that must never appear in the output.
func (r *report) hide(v secret.Value) {
	if s := v.Reveal(); s != "" {
		r.secrets = append(r.secrets, s)
	}
}

func (r *report) add(level, vb, format string, a ...any) {
	line := fmt.Sprintf(format, a...)
	for _, s := range r.secrets {
		line = strings.ReplaceAll(line, s, "[redacted]")
	}
	line = oneLine.Replace(line)
	switch level {
	case pass:
		r.passes++
	case fail:
		r.fails++
	default:
		r.inf++
	}
	_, _ = fmt.Fprintf(r.w, "%s %s %s\n", level, vb, line)
}

// config is what the command line decided.
type config struct {
	zone         string
	token        secret.Value
	underScoped  secret.Value
	accountToken secret.Value
	accountID    string
	apexCNAME    bool
}

// env holds what tests replace.
type env struct {
	newProvider func(tok secret.Value, account string) (dns.Provider, error)
	raw         *rawClient
	sleep       func(context.Context, time.Duration)
	now         func() time.Time
}

// rawClient sends the few requests that need the raw answer, headers included.
type rawClient struct {
	base string
	hc   *http.Client
}

// newRaw returns a client for base; a nil transport is the production one: TLS 1.2 or later
// against the system roots, through the proxy of the environment, no redirects.
func newRaw(base string, tr *http.Transport) *rawClient {
	if tr == nil {
		tr = &http.Transport{
			Proxy:               proxyenv.FromEnvironment,
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout: 30 * time.Second,
			ForceAttemptHTTP2:   true,
		}
	}
	return &rawClient{base: base, hc: &http.Client{
		Transport: tr, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

type rawAnswer struct {
	status int
	header http.Header
	body   []byte
}

// errorText returns the first error of a Cloudflare envelope, if any.
func (a rawAnswer) errorText() string {
	var env struct {
		Errors []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if json.Unmarshal(a.body, &env) != nil || len(env.Errors) == 0 {
		return ""
	}
	return fmt.Sprintf("%d %s", env.Errors[0].Code, env.Errors[0].Message)
}

func (c *rawClient) get(ctx context.Context, tok secret.Value, path string) (rawAnswer, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return rawAnswer{}, errors.New("cannot build the request")
	}
	req.Header.Set("Authorization", "Bearer "+tok.Reveal())
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "rpmgr-cfprobe")
	resp, err := c.hc.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return rawAnswer{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return rawAnswer{resp.StatusCode, resp.Header, b}, nil
}

var oneLine = strings.NewReplacer("\n", " ", "\r", " ")

var idPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

type probe struct {
	cfg   config
	env   env
	rep   *report
	prov  dns.Provider
	zone  dns.Zone
	label string
	// created holds the IDs of the records the probe made, which cleanup deletes; so does the
	// label: every record at or below the label is the probe's.
	created  map[string]bool
	dirty    bool // a record may exist that cleanup has not removed
	left     []dns.Record
	seenIDs  int // identifiers checked for VB-26
	badIDs   int
	finished bool
}

// run executes every check and returns the exit status: 0 no FAIL and nothing left behind, 1
// otherwise.
func run(ctx context.Context, cfg config, e env, rep *report) int {
	rep.hide(cfg.token)
	rep.hide(cfg.underScoped)
	rep.hide(cfg.accountToken)
	p := &probe{cfg: cfg, env: e, rep: rep, created: map[string]bool{}}
	var b [5]byte
	_, _ = rand.Read(b[:])
	p.label = "_rpmgr-probe-" + hex.EncodeToString(b[:])
	var err error
	if p.prov, err = e.newProvider(cfg.token, ""); err != nil {
		rep.add(fail, "SETUP", "cannot build the client: %v", err)
		return 1
	}
	rep.add(info, "SETUP", "zone %s, probe label %s", cfg.zone, p.label)
	defer func() { // only a panic gets here with records left
		if !p.finished {
			p.cleanup(ctx, true)
		}
	}()
	if p.checkToken(ctx) && p.findZone(ctx) {
		p.checkUnderScoped(ctx)
		var before []dns.Record
		if rs, err := p.prov.ListRecords(ctx, p.zone.ID); err != nil {
			rep.add(fail, "VB-10", "cannot list the records of the zone: %s", errText(err))
		} else {
			before = p.foreign(rs)
		}
		p.checkComments(ctx)
		p.checkCNAME(ctx)
		p.checkForeignUntouched(ctx, before)
		p.cleanup(ctx, false)
		rep.add(info, "VB-09", "the rate-limit burst is not part of this version of cfprobe")
	}
	p.cleanup(ctx, true)
	p.finished = true
	p.notCovered()
	rep.add(info, "SUMMARY", "pass=%d fail=%d info=%d leftover-records=%d", rep.passes, rep.fails, rep.inf, len(p.left))
	if rep.fails > 0 || len(p.left) > 0 {
		return 1
	}
	return 0
}

// vb26 checks that an identifier has the format the client relies on.
func (p *probe) vb26(what, id string) bool {
	p.seenIDs++
	if !idPattern.MatchString(id) {
		p.badIDs++
		p.rep.add(fail, "VB-26", "%s identifier is not 32 lower-case hex characters (%d characters)", what, len(id))
		return false
	}
	return true
}

func (p *probe) fqdn(sub string) string {
	if sub == "" {
		return p.label + "." + p.cfg.zone
	}
	return sub + "." + p.label + "." + p.cfg.zone
}

// errText describes a provider error without a token (report scrubs the rest).
func errText(err error) string {
	var pe *dns.ProviderError
	if errors.As(err, &pe) {
		return pe.Error()
	}
	return err.Error()
}

// checkToken is VB-12 (token verification) and the account-owned token.
func (p *probe) checkToken(ctx context.Context) bool {
	ti, err := p.prov.Verify(ctx)
	if err != nil {
		p.rep.add(fail, "VB-12", "token verify failed: %s", errText(err))
		return false
	}
	if ti.ID != "" {
		p.vb26("token", ti.ID)
	}
	if !ti.Active() {
		p.rep.add(fail, "VB-12", "the token's status is %q, not active", ti.Status)
		return false
	}
	exp := "does not expire"
	if !ti.ExpiresAt.IsZero() {
		exp = "expires " + ti.ExpiresAt.UTC().Format(time.RFC3339)
	}
	p.rep.add(pass, "VB-12", "user token verifies at /user/tokens/verify, status active, %s", exp)
	if p.cfg.accountToken.IsZero() {
		p.rep.add(info, "VB-12", "no account-owned token given; not probed")
		return true
	}
	p.vb26("account", p.cfg.accountID)
	acct, err := p.env.newProvider(p.cfg.accountToken, p.cfg.accountID)
	if err != nil {
		p.rep.add(fail, "VB-12", "cannot build the account-token client: %s", errText(err))
		return true
	}
	if ai, err := acct.Verify(ctx); err != nil {
		p.rep.add(fail, "VB-12", "account-owned token does not verify at /accounts/{id}/tokens/verify: %s", errText(err))
	} else if !ai.Active() {
		p.rep.add(fail, "VB-12", "account-owned token status is %q, not active", ai.Status)
	} else {
		p.rep.add(pass, "VB-12", "account-owned token verifies at /accounts/{id}/tokens/verify, status active")
	}
	return true
}

// outcome names the result of a call in one phrase.
func outcome(err error) string {
	if err == nil {
		return "accepted"
	}
	return "refused (" + errText(err) + ")"
}

// findZone is VB-12 (zone status and type).
func (p *probe) findZone(ctx context.Context) bool {
	zs, err := p.prov.ListZones(ctx)
	if err != nil {
		p.rep.add(fail, "VB-12", "cannot list zones: %s", errText(err))
		return false
	}
	kinds := map[string]int{}
	for _, z := range zs {
		kinds[z.Status+"/"+z.Type]++
	}
	names := make([]string, 0, len(kinds))
	for k, n := range kinds {
		names = append(names, fmt.Sprintf("%s x%d", k, n))
	}
	sort.Strings(names)
	p.rep.add(info, "VB-12", "token sees %d zone(s) (status/type: %s); a token scoped to one zone sees exactly 1",
		len(zs), strings.Join(names, ", "))
	for _, z := range zs {
		if z.Name != p.cfg.zone {
			continue
		}
		if !p.vb26("zone", z.ID) {
			return false
		}
		p.zone = z
		if z.Status != "active" || z.Type != "full" {
			p.rep.add(fail, "VB-12", "zone %s has status %q and type %q; the probe needs active/full", z.Name, z.Status, z.Type)
			return false
		}
		p.rep.add(pass, "VB-12", "zone %s has status active and type full", z.Name)
		return true
	}
	p.rep.add(fail, "VB-12", "zone %s is not among the zones of the token", p.cfg.zone)
	return false
}

// checkUnderScoped expects the under-scoped token to be refused.
func (p *probe) checkUnderScoped(ctx context.Context) {
	u, err := p.env.newProvider(p.cfg.underScoped, "")
	if err != nil {
		p.rep.add(fail, "VB-12", "cannot build the under-scoped client: %s", errText(err))
		return
	}
	_, err = u.ListRecords(ctx, p.zone.ID)
	p.rep.add(info, "VB-12", "under-scoped token reads records of the zone: %s", outcome(err))
	p.dirty = true
	err = u.Apply(ctx, p.zone.ID, dns.Batch{Posts: []dns.Record{{
		Type: "TXT", Name: p.fqdn("underscoped"), Content: "probe", TTL: 120, Comment: "rpmgr-probe",
	}}})
	switch {
	case err == nil:
		p.rep.add(fail, "VB-12", "the under-scoped token WROTE a record: it is not under-scoped; cleanup removes the record")
	case errors.Is(err, dns.ErrForbidden), errors.Is(err, dns.ErrUnauthorized), errors.Is(err, dns.ErrNotFound):
		p.rep.add(pass, "VB-12", "under-scoped token cannot write the zone: %s", errText(err))
	default:
		p.rep.add(fail, "VB-12", "under-scoped token failed in an unexpected way: %s", errText(err))
	}
}

// isProbe reports whether a record is at or below the probe's label.
func isProbe(label, zone string, r dns.Record) bool {
	n := strings.ToLower(r.Name)
	return n == label+"."+zone || strings.HasSuffix(n, "."+label+"."+zone)
}

func (p *probe) foreign(rs []dns.Record) []dns.Record {
	var out []dns.Record
	for _, r := range rs {
		if !isProbe(p.label, p.cfg.zone, r) && !p.created[r.ID] {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// post creates one record and returns it as listed, with its ID, which it records for cleanup.
func (p *probe) post(ctx context.Context, r dns.Record) (dns.Record, error) {
	p.dirty = true
	if err := p.prov.Apply(ctx, p.zone.ID, dns.Batch{Posts: []dns.Record{r}}); err != nil {
		return dns.Record{}, err
	}
	return p.find(ctx, r.Type, r.Name)
}

// find returns the record of a type and name, and registers it for cleanup.
func (p *probe) find(ctx context.Context, typ, name string) (dns.Record, error) {
	rs, err := p.prov.ListRecords(ctx, p.zone.ID)
	if err != nil {
		return dns.Record{}, err
	}
	for _, r := range rs {
		if r.Type == typ && strings.EqualFold(r.Name, name) {
			p.created[r.ID] = true
			p.vb26("record", r.ID)
			return r, nil
		}
	}
	return dns.Record{}, fmt.Errorf("the record %s %s is not listed after it was created", typ, name)
}

// marker builds a comment of the shape docs/15 gives ("rpmgr <trust domain> <ledger ID>", 51
// characters), but with a trust domain that says it is a probe.
func marker() string {
	const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	b := make([]byte, 26)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = crockford[int(b[i])%len(crockford)]
	}
	var d [4]byte
	_, _ = rand.Read(d[:])
	return "rpmgr probe-" + hex.EncodeToString(d[:]) + " dnr_" + string(b)
}

// checkComments is VB-10.
func (p *probe) checkComments(ctx context.Context) {
	const vb = "VB-10"
	m := marker()
	rec, err := p.post(ctx, dns.Record{Type: "TXT", Name: p.fqdn("owned"), Content: "probe-owned", TTL: 120, Comment: m})
	if err != nil {
		p.rep.add(fail, vb, "cannot create a record with a comment: %s", errText(err))
		return
	}
	if rec.Comment == m {
		p.rep.add(pass, vb, "the marker (%d characters) round-trips unchanged through create and list", len(m))
	} else {
		p.rep.add(fail, vb, "the marker did not round-trip: sent %q, listed %q", m, rec.Comment)
	}
	// A foreign record: no comment, as another tool or a person would have made it.
	foreign, err := p.post(ctx, dns.Record{Type: "TXT", Name: p.fqdn("foreign"), Content: "probe-foreign", TTL: 120})
	if err != nil {
		p.rep.add(fail, vb, "cannot create the stand-in foreign record: %s", errText(err))
		return
	}
	// A patch that changes the comment alone.
	m2 := marker()
	patch := rec
	patch.Comment = m2
	if err := p.prov.Apply(ctx, p.zone.ID, dns.Batch{Patches: []dns.Record{patch}}); err != nil {
		p.rep.add(fail, vb, "a batch patch that changes the comment alone failed: %s", errText(err))
	} else if got, err := p.find(ctx, rec.Type, rec.Name); err != nil {
		p.rep.add(fail, vb, "cannot read the patched record: %s", errText(err))
	} else if got.Comment != m2 || got.Content != rec.Content || got.TTL != rec.TTL || got.ID != rec.ID {
		p.rep.add(fail, vb, "after the patch the record is %+v, expected only the comment to change", got)
	} else {
		p.rep.add(pass, vb, "a batch patch changes the comment alone; content, TTL and ID stay")
	}
	if got, err := p.find(ctx, foreign.Type, foreign.Name); err != nil || got.Comment != foreign.Comment || got.Content != foreign.Content {
		p.rep.add(fail, vb, "the foreign record changed while another record was patched: %+v (%v)", got, err)
	} else {
		p.rep.add(pass, vb, "a record without a marker is untouched by a batch that patches another")
	}
	// The longest comment the client sends.
	long := strings.Repeat("c", 100)
	if lr, err := p.post(ctx, dns.Record{Type: "TXT", Name: p.fqdn("long"), Content: "probe-long", TTL: 120, Comment: long}); err != nil {
		p.rep.add(fail, vb, "a comment of 100 characters was refused: %s", errText(err))
	} else if lr.Comment != long {
		p.rep.add(fail, vb, "a comment of 100 characters came back as %d characters", len(lr.Comment))
	} else {
		p.rep.add(pass, vb, "a comment of 100 characters round-trips")
	}
	// A failed batch: one valid post and one invalid; all-or-nothing, and which operation is named.
	err = p.prov.Apply(ctx, p.zone.ID, dns.Batch{Posts: []dns.Record{
		{Type: "TXT", Name: p.fqdn("batch-ok"), Content: "probe-batch-ok", TTL: 120},
		{Type: "A", Name: p.fqdn("batch-bad"), Content: "", TTL: 120},
	}})
	p.dirty = true
	if err == nil {
		p.rep.add(fail, vb, "a batch with an invalid record was accepted")
	} else {
		p.rep.add(info, vb, "a batch of [valid post, invalid post] fails with: %s (does it name the failing operation?)", errText(err))
		if rs, lerr := p.prov.ListRecords(ctx, p.zone.ID); lerr == nil && slices.ContainsFunc(rs, func(r dns.Record) bool {
			return strings.EqualFold(r.Name, p.fqdn("batch-ok"))
		}) {
			p.rep.add(fail, vb, "the failed batch was applied in part: the valid record exists (not all-or-nothing)")
		} else if lerr == nil {
			p.rep.add(pass, vb, "a failed batch changes nothing (all-or-nothing)")
		}
	}
	// Listing by comment (a raw request: the client does not filter).
	q := "/zones/" + p.zone.ID + "/dns_records?per_page=50&comment.exact=" + url.QueryEscape(m2)
	ans, err := p.env.raw.get(ctx, p.cfg.token, q)
	switch {
	case err != nil:
		p.rep.add(info, vb, "listing by comment: request failed: %v", err)
	case ans.status != http.StatusOK:
		p.rep.add(info, vb, "listing by comment: HTTP %d %s", ans.status, ans.errorText())
	default:
		var env struct {
			Result []dns.Record `json:"result"`
		}
		_ = json.Unmarshal(ans.body, &env)
		onlyOurs := len(env.Result) == 1
		p.rep.add(info, vb, "listing by comment.exact returned %d record(s); the filter is honoured: %t", len(env.Result), onlyOurs)
	}
}

// checkCNAME is VB-11.
func (p *probe) checkCNAME(ctx context.Context) {
	const vb = "VB-11"
	target := p.fqdn("target") // never created: the API does not resolve CNAME targets
	for _, c := range []struct {
		sub     string
		proxied bool
	}{{"plain", false}, {"proxied", true}} {
		ttl := 120
		if c.proxied {
			ttl = 1
		}
		r, err := p.post(ctx, dns.Record{Type: "CNAME", Name: p.fqdn(c.sub), Content: target, TTL: ttl, Proxied: c.proxied,
			Comment: marker()})
		switch {
		case err != nil:
			p.rep.add(fail, vb, "cannot create a CNAME with proxied=%t: %s", c.proxied, errText(err))
		case r.Proxied != c.proxied:
			p.rep.add(fail, vb, "a CNAME created with proxied=%t is listed with proxied=%t", c.proxied, r.Proxied)
		case c.proxied && r.TTL != 1:
			p.rep.add(fail, vb, "a proxied CNAME has TTL %d, expected 1 (automatic)", r.TTL)
		default:
			p.rep.add(pass, vb, "CNAME with proxied=%t is accepted and listed as sent (TTL %d)", c.proxied, r.TTL)
		}
	}
	// A proxied wildcard.
	w, err := p.post(ctx, dns.Record{Type: "CNAME", Name: "*." + p.fqdn("wild"), Content: target, TTL: 1, Proxied: true})
	switch {
	case err != nil:
		p.rep.add(info, vb, "proxied wildcard CNAME on this plan: refused (%s)", errText(err))
	default:
		p.rep.add(info, vb, "proxied wildcard CNAME on this plan: accepted, proxied=%t", w.Proxied)
	}
	// A CNAME at the apex, opt-in, only if nothing else is at the apex.
	if !p.cfg.apexCNAME {
		p.rep.add(info, vb, "apex CNAME not probed; pass -apex-cname for a zone without records at its apex")
		return
	}
	rs, err := p.prov.ListRecords(ctx, p.zone.ID)
	if err != nil {
		p.rep.add(fail, vb, "cannot list the zone before the apex probe: %s", errText(err))
		return
	}
	if slices.ContainsFunc(rs, func(r dns.Record) bool { return strings.EqualFold(r.Name, p.cfg.zone) }) {
		p.rep.add(info, vb, "apex CNAME not probed: the apex already has records, which a CNAME cannot share")
		return
	}
	a, err := p.post(ctx, dns.Record{Type: "CNAME", Name: p.cfg.zone, Content: target, TTL: 1, Comment: marker()})
	if err != nil {
		p.rep.add(fail, vb, "a CNAME at the apex was refused: %s", errText(err))
		return
	}
	p.rep.add(pass, vb, "a CNAME at the zone apex is accepted (flattened by Cloudflare at query time; proxied=%t)", a.Proxied)
}

// checkForeignUntouched compares the records outside the probe's namespace before and after.
func (p *probe) checkForeignUntouched(ctx context.Context, before []dns.Record) {
	rs, err := p.prov.ListRecords(ctx, p.zone.ID)
	if err != nil {
		p.rep.add(fail, "VB-10", "cannot list the records after the checks: %s", errText(err))
		return
	}
	after := p.foreign(rs)
	if slices.Equal(before, after) {
		p.rep.add(pass, "VB-10", "the %d pre-existing record(s) of the zone are unchanged", len(before))
	} else {
		p.rep.add(fail, "VB-10", "pre-existing records changed: %d before, %d after, or a field differs", len(before), len(after))
	}
}

// cleanup deletes every record the probe made and reports what it could not delete. It is safe to
// call again (final: report what is left), runs on a context that outlives a cancelled one, and waits out a rate limit.
func (p *probe) cleanup(ctx context.Context, final bool) {
	if !p.dirty || p.zone.ID == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 12*time.Minute)
	defer cancel()
	deleted := 0
	var err error
	for attempt := 0; attempt < 5 && p.dirty; attempt++ {
		var rs []dns.Record
		if rs, err = p.prov.ListRecords(ctx, p.zone.ID); err == nil {
			p.left = slices.DeleteFunc(rs, func(r dns.Record) bool { return !p.created[r.ID] && !isProbe(p.label, p.cfg.zone, r) })
			if p.dirty = len(p.left) > 0; !p.dirty {
				break
			}
			for chunk := range slices.Chunk(p.left, 100) {
				var ids []string
				for _, r := range chunk {
					ids = append(ids, r.ID)
				}
				if err = p.prov.Apply(ctx, p.zone.ID, dns.Batch{Deletes: ids}); err != nil {
					break
				}
				deleted += len(chunk)
			}
		}
		wait := time.Second
		var rl dns.RateLimited
		if errors.As(err, &rl) {
			wait = min(max(rl.Until.Sub(p.env.now()), 0), 6*time.Minute)
		} else if err == nil {
			wait = 0
		}
		p.env.sleep(ctx, wait)
	}
	if deleted > 0 {
		p.rep.add(info, "CLEANUP", "deleted %d record(s) the probe created", deleted)
	}
	if p.dirty && !final {
		return
	}
	if p.dirty {
		reason := "records remain"
		if err != nil {
			reason = errText(err)
		}
		for _, r := range p.left {
			p.rep.add(fail, "CLEANUP", "LEFTOVER %s %s (record %s) could not be deleted; remove it by hand", r.Type, r.Name, r.ID)
		}
		p.rep.add(fail, "CLEANUP", "%d record(s) left behind: %s", len(p.left), reason)
		return
	}
	p.left = nil
}

// notCovered lists what the probe cannot check, so the run sheet is not read as covering it.
func (p *probe) notCovered() {
	p.rep.add(info, "VB-11", "not covered here: a proxied CNAME to another account's name (error 1014), request-size and timeout limits, ACME HTTP-01 through the proxy")
	p.rep.add(info, "VB-12", "not covered here: partial, secondary and child zones, paging with more than 50 zones, moved zones, scoping below a zone")
	if p.badIDs == 0 && p.seenIDs > 0 {
		p.rep.add(pass, "VB-26", "all %d identifier(s) seen (zone, records, token, account) are 32 lower-case hex characters", p.seenIDs)
	} else if p.seenIDs == 0 {
		p.rep.add(info, "VB-26", "no identifier was seen")
	}
}
