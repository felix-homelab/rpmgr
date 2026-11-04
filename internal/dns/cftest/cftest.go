// SPDX-License-Identifier: Apache-2.0

// Package cftest is an in-memory fake of the Cloudflare v4 API for tests (R8): zones, records,
// the batch endpoint, paging, both token-verify endpoints, and injectable failures (401, 403, 429
// with and without Retry-After, malformed bodies). It serves TLS with a certificate of a generated
// test CA, which RootCAs returns, so clients verify it as they would the real API. It is not
// linked into rpmgr itself.
package cftest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Zone is a zone of the fake account.
type Zone struct{ ID, Name, Status, Type string }

// Record is a record of the fake.
type Record struct {
	ID      string `json:"id"`
	ZoneID  string `json:"zone_id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
	Comment string `json:"comment,omitempty"`
}

// Fault is an answer injected in place of the real one.
type Fault struct {
	Status     int    // HTTP status
	RetryAfter string // Retry-After header, if not empty
	Body       string // raw body; empty: a Cloudflare error envelope
}

// Server is the fake API.
type Server struct {
	srv *httptest.Server
	ca  *x509.CertPool

	mu       sync.Mutex
	token    string
	account  string // non-empty: an account-owned token of this account
	status   string
	expires  string
	zones    []Zone
	records  []Record
	next     int
	faults   []Fault
	requests []string
}

// New starts the fake with a user token and stops it when the test ends.
func New(tb testing.TB, token string) *Server {
	tb.Helper()
	s := &Server{token: token, status: "active"}
	cert, pool := certificate(tb)
	s.ca = pool
	s.srv = httptest.NewUnstartedServer(http.HandlerFunc(s.serve))
	s.srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	s.srv.Config.ErrorLog = log.New(io.Discard, "", 0) // a client that rejects the test CA is a test case
	s.srv.StartTLS()
	tb.Cleanup(s.srv.Close)
	return s
}

// URL is the base URL, as BaseURL of the real API.
func (s *Server) URL() string { return s.srv.URL + "/client/v4" }

// RootCAs holds the test CA that signed the server's certificate.
func (s *Server) RootCAs() *x509.CertPool { return s.ca }

// SetAccountToken makes the token an account-owned one: only /accounts/{id}/tokens/verify of that
// account accepts it, and /user/tokens/verify answers 401.
func (s *Server) SetAccountToken(accountID string) { s.lock(func() { s.account = accountID }) }

// SetTokenStatus sets the status and expiry (RFC 3339, may be empty) that verify reports.
func (s *Server) SetTokenStatus(status, expiresOn string) {
	s.lock(func() { s.status, s.expires = status, expiresOn })
}

// AddZone adds a zone with the given name, active and full.
func (s *Server) AddZone(name string) Zone {
	var z Zone
	s.lock(func() {
		z = Zone{ID: s.id("zone"), Name: strings.ToLower(name), Status: "active", Type: "full"}
		s.zones = append(s.zones, z)
	})
	return z
}

// AddRecord adds a record to a zone and returns it with its ID.
func (s *Server) AddRecord(zoneID string, r Record) Record {
	s.lock(func() {
		r.ID, r.ZoneID, r.Name = s.id("rec"), zoneID, strings.ToLower(r.Name)
		r.TTL = max(r.TTL, 1)
		s.records = append(s.records, r)
	})
	return r
}

// Records returns the records of a zone in creation order.
func (s *Server) Records(zoneID string) []Record {
	var out []Record
	s.lock(func() {
		for _, r := range s.records {
			if r.ZoneID == zoneID {
				out = append(out, r)
			}
		}
	})
	return out
}

// Fail queues faults: each answers one of the next requests, in order, before any real handling.
func (s *Server) Fail(f ...Fault) { s.lock(func() { s.faults = append(s.faults, f...) }) }

// Requests returns "METHOD path?query" of every request received, in order.
func (s *Server) Requests() []string {
	var out []string
	s.lock(func() { out = append(out, s.requests...) })
	return out
}

// Count returns how many requests so far started with prefix, such as "GET /client/v4/zones".
func (s *Server) Count(prefix string) int {
	n := 0
	for _, r := range s.Requests() {
		if strings.HasPrefix(r, prefix) {
			n++
		}
	}
	return n
}

func (s *Server) lock(f func()) { s.mu.Lock(); defer s.mu.Unlock(); f() }

func (s *Server) id(string) string { s.next++; return fmt.Sprintf("%032x", s.next) }

type message struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type envelope struct {
	Success    bool           `json:"success"`
	Errors     []message      `json:"errors"`
	Messages   []message      `json:"messages"`
	Result     any            `json:"result"`
	ResultInfo map[string]int `json:"result_info,omitempty"`
}

func writeErr(w http.ResponseWriter, status, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(envelope{Errors: []message{{code, msg}}, Messages: []message{}})
}

func writeOK(w http.ResponseWriter, result any, info map[string]int) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(envelope{Success: true, Errors: []message{}, Messages: []message{},
		Result: result, ResultInfo: info})
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.requests = append(s.requests, r.Method+" "+r.URL.RequestURI())
	var fault *Fault
	if len(s.faults) > 0 {
		fault, s.faults = &s.faults[0], s.faults[1:]
	}
	s.mu.Unlock()
	if fault != nil {
		if fault.RetryAfter != "" {
			w.Header().Set("Retry-After", fault.RetryAfter)
		}
		if fault.Body != "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(fault.Status)
			_, _ = w.Write([]byte(fault.Body))
			return
		}
		writeErr(w, fault.Status, 10000, http.StatusText(fault.Status))
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+s.token {
		writeErr(w, http.StatusUnauthorized, 10000, "Authentication error")
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /client/v4/user/tokens/verify", s.verify(""))
	mux.HandleFunc("GET /client/v4/accounts/{account}/tokens/verify", s.verify("account"))
	mux.HandleFunc("GET /client/v4/zones", s.listZones)
	mux.HandleFunc("GET /client/v4/zones/{zone}/dns_records", s.listRecords)
	mux.HandleFunc("POST /client/v4/zones/{zone}/dns_records/batch", s.batch)
	mux.ServeHTTP(w, r)
}

func (s *Server) verify(scope string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if (scope == "") != (s.account == "") || (scope != "" && r.PathValue("account") != s.account) {
			writeErr(w, http.StatusUnauthorized, 1000, "Invalid API Token")
			return
		}
		res := map[string]any{"id": "tok-0001", "status": s.status}
		if s.expires != "" {
			res["expires_on"] = s.expires
		}
		writeOK(w, res, nil)
	}
}

// paging applies Cloudflare's paging: per_page defaults to 20 and is at most limit.
func paging(r *http.Request, total, limit int) (from, to int, info map[string]int, ok bool) {
	p, per := 1, 20
	if v := r.URL.Query().Get("page"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return 0, 0, nil, false
		}
		p = n
	}
	if v := r.URL.Query().Get("per_page"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 5 || n > limit {
			return 0, 0, nil, false
		}
		per = n
	}
	from = min((p-1)*per, total)
	to = min(from+per, total)
	return from, to, map[string]int{"page": p, "per_page": per, "count": to - from, "total_count": total,
		"total_pages": (total + per - 1) / per}, true
}

func (s *Server) listZones(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	zs := append([]Zone(nil), s.zones...)
	s.mu.Unlock()
	from, to, info, ok := paging(r, len(zs), 50)
	if !ok {
		writeErr(w, http.StatusBadRequest, 1001, "invalid paging parameters")
		return
	}
	out := []map[string]string{}
	for _, z := range zs[from:to] {
		out = append(out, map[string]string{"id": z.ID, "name": z.Name, "status": z.Status, "type": z.Type})
	}
	writeOK(w, out, info)
}

func (s *Server) hasZone(id string) bool {
	for _, z := range s.zones {
		if z.ID == id {
			return true
		}
	}
	return false
}

func (s *Server) listRecords(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	ok := s.hasZone(r.PathValue("zone"))
	rs := []Record{}
	for _, rec := range s.records {
		if rec.ZoneID == r.PathValue("zone") {
			rs = append(rs, rec)
		}
	}
	s.mu.Unlock()
	if !ok {
		writeErr(w, http.StatusNotFound, 7003, "Could not route to the zone")
		return
	}
	from, to, info, okp := paging(r, len(rs), 5000)
	if !okp {
		writeErr(w, http.StatusBadRequest, 1001, "invalid paging parameters")
		return
	}
	writeOK(w, rs[from:to], info)
}

// batch applies deletes, patches, puts and posts all-or-nothing, as Cloudflare does: any invalid
// operation fails the whole batch and changes nothing.
func (s *Server) batch(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Deletes []struct {
			ID string `json:"id"`
		} `json:"deletes"`
		Patches, Puts, Posts []Record
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, 9207, "Request body is invalid.")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	zone := r.PathValue("zone")
	if !s.hasZone(zone) {
		writeErr(w, http.StatusNotFound, 7003, "Could not route to the zone")
		return
	}
	if len(in.Deletes)+len(in.Patches)+len(in.Puts)+len(in.Posts) > 200 {
		writeErr(w, http.StatusBadRequest, 9013, "too many operations in the batch")
		return
	}
	work := append([]Record(nil), s.records...)
	find := func(id string) int {
		for i, rec := range work {
			if rec.ID == id && rec.ZoneID == zone {
				return i
			}
		}
		return -1
	}
	bad := func(code int, f string, a ...any) { writeErr(w, http.StatusBadRequest, code, fmt.Sprintf(f, a...)) }
	for _, d := range in.Deletes {
		i := find(d.ID)
		if i < 0 {
			bad(81044, "Record does not exist.")
			return
		}
		work = append(work[:i], work[i+1:]...)
	}
	check := func(rec Record) bool {
		if len(rec.Comment) > 100 {
			bad(9100, "DNS record comment is invalid: maximum length is 100")
			return false
		}
		if rec.Type == "" || rec.Name == "" || rec.Content == "" {
			bad(9005, "Record type, name and content are required.")
			return false
		}
		return true
	}
	var done []Record
	for _, list := range []struct {
		recs   []Record
		create bool
	}{{in.Patches, false}, {in.Puts, false}, {in.Posts, true}} {
		for _, rec := range list.recs {
			if !check(rec) {
				return
			}
			rec.Name, rec.ZoneID, rec.TTL = strings.ToLower(rec.Name), zone, max(rec.TTL, 1)
			if list.create {
				s.next++
				rec.ID = fmt.Sprintf("%032x", s.next)
				work = append(work, rec)
			} else if i := find(rec.ID); i < 0 {
				bad(81044, "Record does not exist.")
				return
			} else {
				work[i] = rec
			}
			if list.create {
				done = append(done, rec)
			}
		}
	}
	s.records = work
	writeOK(w, map[string]any{"deletes": in.Deletes, "patches": in.Patches, "puts": in.Puts, "posts": done}, nil)
}

// certificate returns a server certificate for 127.0.0.1 and localhost, signed by a new test CA,
// and a pool that trusts that CA.
func certificate(tb testing.TB) (tls.Certificate, *x509.CertPool) {
	tb.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "cftest CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		tb.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		tb.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "cftest"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}, DNSNames: []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		tb.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}
