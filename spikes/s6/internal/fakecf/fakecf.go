// SPDX-License-Identifier: Apache-2.0

// Package fakecf is an in-process fake of the subset of the Cloudflare v4 API that DNS-01 needs:
// listing zones (paginated), listing, creating and deleting TXT records, with bearer-token
// authentication, Cloudflare's response envelope, and the 100-character comment limit of the
// Free plan (docs/15-dns.md, "Cloudflare specifics"). Records it holds are what the test DNS
// server answers, so a record exists in DNS exactly while it exists at the "provider".
package fakecf

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// Zone is a zone of the fake account.
type Zone struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Type   string `json:"type"`
}

// Record is a DNS record of the fake account.
type Record struct {
	ID      string `json:"id"`
	ZoneID  string `json:"zone_id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Comment string `json:"comment,omitempty"`
	Proxied bool   `json:"proxied"`
}

// Server is the fake API. Mount Handler() under any base URL; paths start with /client/v4.
type Server struct {
	Token string

	mu      sync.Mutex
	zones   []Zone
	records map[string]Record // id → record

	Creates, Deletes, AuthFailures atomic.Int64
}

// New returns a fake with the given token and zones (all active, full setup).
func New(token string, zoneNames ...string) *Server {
	s := &Server{Token: token, records: map[string]Record{}}
	for _, n := range zoneNames {
		s.zones = append(s.zones, Zone{ID: newID(), Name: strings.ToLower(n), Status: "active", Type: "full"})
	}
	return s
}

// AddZone adds a zone, e.g. to test pagination or non-active zones.
func (s *Server) AddZone(z Zone) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if z.ID == "" {
		z.ID = newID()
	}
	s.zones = append(s.zones, z)
}

// TXT returns the TXT values at fqdn (no trailing dot), for the DNS server.
func (s *Server) TXT(fqdn string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, r := range s.records {
		if r.Type == "TXT" && r.Name == strings.ToLower(fqdn) {
			out = append(out, r.Content)
		}
	}
	sort.Strings(out)
	return out
}

// Records returns a copy of all records.
func (s *Server) Records() []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Record, 0, len(s.records))
	for _, r := range s.records {
		out = append(out, r)
	}
	return out
}

// Handler returns the HTTP handler of the fake API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /client/v4/zones", s.listZones)
	mux.HandleFunc("GET /client/v4/zones/{zone}/dns_records", s.listRecords)
	mux.HandleFunc("POST /client/v4/zones/{zone}/dns_records", s.createRecord)
	mux.HandleFunc("DELETE /client/v4/zones/{zone}/dns_records/{id}", s.deleteRecord)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+s.Token || s.Token == "" {
			s.AuthFailures.Add(1)
			writeErr(w, http.StatusForbidden, 10000, "Authentication error")
			return
		}
		mux.ServeHTTP(w, r)
	})
}

type envelope struct {
	Success    bool        `json:"success"`
	Errors     []apiError  `json:"errors"`
	Messages   []any       `json:"messages"`
	Result     any         `json:"result"`
	ResultInfo *resultInfo `json:"result_info,omitempty"`
}

type apiError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type resultInfo struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	Count      int `json:"count"`
	TotalCount int `json:"total_count"`
	TotalPages int `json:"total_pages"`
}

func writeErr(w http.ResponseWriter, status, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(envelope{Errors: []apiError{{code, msg}}, Messages: []any{}})
}

func writeOK(w http.ResponseWriter, result any, info *resultInfo) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(envelope{Success: true, Errors: []apiError{}, Messages: []any{},
		Result: result, ResultInfo: info})
}

// page applies Cloudflare's paging: per_page defaults to 20 and is at most 50 for zones.
func page(r *http.Request, total int) (from, to int, info *resultInfo, ok bool) {
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
		if err != nil || n < 5 || n > 50 {
			return 0, 0, nil, false
		}
		per = n
	}
	from = (p - 1) * per
	if from > total {
		from = total
	}
	to = min(from+per, total)
	pages := (total + per - 1) / per
	return from, to, &resultInfo{Page: p, PerPage: per, Count: to - from, TotalCount: total,
		TotalPages: pages}, true
}

func (s *Server) listZones(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	zones := append([]Zone(nil), s.zones...)
	s.mu.Unlock()
	if name := r.URL.Query().Get("name"); name != "" {
		var f []Zone
		for _, z := range zones {
			if z.Name == strings.ToLower(name) {
				f = append(f, z)
			}
		}
		zones = f
	}
	from, to, info, ok := page(r, len(zones))
	if !ok {
		writeErr(w, http.StatusBadRequest, 1001, "invalid paging parameters")
		return
	}
	writeOK(w, zones[from:to], info)
}

func (s *Server) zone(id string) (Zone, bool) {
	for _, z := range s.zones {
		if z.ID == id {
			return z, true
		}
	}
	return Zone{}, false
}

func (s *Server) listRecords(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	_, ok := s.zone(r.PathValue("zone"))
	var out []Record
	for _, rec := range s.records {
		if rec.ZoneID != r.PathValue("zone") {
			continue
		}
		if t := r.URL.Query().Get("type"); t != "" && rec.Type != t {
			continue
		}
		if n := r.URL.Query().Get("name"); n != "" && rec.Name != strings.ToLower(n) {
			continue
		}
		out = append(out, rec)
	}
	s.mu.Unlock()
	if !ok {
		writeErr(w, http.StatusNotFound, 7003, "Could not route to /zones/..., perhaps your object identifier is invalid?")
		return
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	from, to, info, okp := page(r, len(out))
	if !okp {
		writeErr(w, http.StatusBadRequest, 1001, "invalid paging parameters")
		return
	}
	writeOK(w, out[from:to], info)
}

func (s *Server) createRecord(w http.ResponseWriter, r *http.Request) {
	var in Record
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, 9207, "Request body is invalid.")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	z, ok := s.zone(r.PathValue("zone"))
	switch {
	case !ok:
		writeErr(w, http.StatusNotFound, 7003, "Could not route to /zones/..., perhaps your object identifier is invalid?")
		return
	case in.Type != "TXT":
		writeErr(w, http.StatusBadRequest, 9004, "this fake supports only TXT records")
		return
	case in.Content == "":
		writeErr(w, http.StatusBadRequest, 9005, "Content for TXT record is invalid.")
		return
	case len(in.Comment) > 100:
		writeErr(w, http.StatusBadRequest, 9100, "DNS record comment is invalid: maximum length is 100")
		return
	}
	name := strings.ToLower(strings.TrimSuffix(in.Name, "."))
	if name != z.Name && !strings.HasSuffix(name, "."+z.Name) {
		writeErr(w, http.StatusBadRequest, 9007, fmt.Sprintf("record name %q is not in zone %q", name, z.Name))
		return
	}
	rec := Record{ID: newID(), ZoneID: z.ID, Type: in.Type, Name: name, Content: in.Content,
		TTL: max(in.TTL, 1), Comment: in.Comment}
	s.records[rec.ID] = rec
	s.Creates.Add(1)
	writeOK(w, rec, nil)
}

func (s *Server) deleteRecord(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[r.PathValue("id")]
	if !ok || rec.ZoneID != r.PathValue("zone") {
		writeErr(w, http.StatusNotFound, 81044, "Record does not exist.")
		return
	}
	delete(s.records, rec.ID)
	s.Deletes.Add(1)
	writeOK(w, map[string]string{"id": rec.ID}, nil)
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
