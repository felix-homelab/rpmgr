// SPDX-License-Identifier: Apache-2.0

// Package objstoretest is an in-process S3-compatible store for tests: one bucket on a loopback
// address, with versions, a conditional create, Object Lock headers, listing, and switches that
// make it behave like a store that lacks one of them or that fails. It is a test double, not
// evidence for VB-24, which needs real stores.
package objstoretest

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The bucket and the access key a Server accepts. The key is the AWS documentation's example.
const (
	Bucket      = "audit-bucket"
	Region      = "eu-test-1"
	AccessKeyID = "AKIAIOSFODNN7EXAMPLE" //nolint:gosec // G101: AWS documentation example credentials, not secrets
)

// Server is the store. Set its switches before the first request.
type Server struct {
	// URL is the store's endpoint, http on 127.0.0.1.
	URL string
	// RejectConditional makes the store answer 400 to a request with If-None-Match, as one that does
	// not know the header does.
	RejectConditional bool
	// EndlessListing makes every listing truncated with a new continuation token and no keys, as a
	// store that never ends a listing does. RepeatListing makes it answer the same page and token, so that its keys do not rise; RepeatToken a new key and the same token.
	EndlessListing, RepeatListing, RepeatToken bool
	// PutAnswer, if set, is asked about every PUT: a status other than 0 is the answer, with the
	// code, and the write does not take effect.
	PutAnswer func() (status int, code string)
	// NoLock makes the bucket refuse a write that asks for Object Lock, as a bucket without it does.
	NoLock bool
	// NoConditional makes the store ignore If-None-Match, as one without conditional create does.
	NoConditional bool
	// NoEnforce makes the store accept lock headers but delete a locked version, as a store that
	// does not enforce Object Lock does.
	NoEnforce bool
	// NoVersions makes the store answer without a version ID, as an unversioned bucket does.
	NoVersions bool
	// Fault, if set, is asked about every request: a status other than 0 is the answer without
	// the request taking effect, and a delay holds the request that long first.
	Fault func(method, key string) (status int, delay time.Duration)

	srv  *httptest.Server
	mu   sync.Mutex
	objs map[string]*object
	log  []string
	seq  int

	listings int
}

type object struct {
	body    []byte
	version string
	locked  bool
	// mode and retain are the lock headers of the write.
	mode, retain string
}

// New starts a store that closes with the test.
func New(t testing.TB) *Server {
	t.Helper()
	s := &Server{objs: map[string]*object{}}
	s.srv = httptest.NewServer(s)
	t.Cleanup(s.srv.Close)
	s.URL = s.srv.URL
	return s
}

// Close stops the store, as a store that went down.
func (s *Server) Close() { s.srv.Close() }

// Get returns the body under key.
func (s *Server) Get(key string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.objs[key]
	if !ok {
		return nil, false
	}
	return o.body, true
}

// Lock returns the lock mode and the retain-until date the object under key was written with.
func (s *Server) Lock(key string) (mode, retain string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if o, ok := s.objs[key]; ok {
		return o.mode, o.retain
	}
	return "", ""
}

// Keys returns the keys held, in order.
func (s *Server) Keys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.objs))
	for k := range s.objs {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Tamper replaces the body under key behind the store's back, as someone with the store's own
// rights over a bucket without a lock could.
func (s *Server) Tamper(key string, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objs[key] = &object{body: body, version: "tampered"}
}

// Remove deletes key behind the store's back.
func (s *Server) Remove(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.objs, key)
}

// Requests returns the requests so far as "METHOD key".
func (s *Server) Requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.log...)
}

// Count returns how many requests had method.
func (s *Server) Count(method string) int {
	n := 0
	for _, r := range s.Requests() {
		if strings.HasPrefix(r, method+" ") {
			n++
		}
	}
	return n
}

func xmlError(w http.ResponseWriter, status int, code, msg string) {
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "<Error><Code>%s</Code><Message>%s</Message></Error>", code, msg)
}

// ServeHTTP answers one request.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	prefix := "/" + Bucket + "/"
	key := strings.TrimPrefix(r.URL.Path, prefix)
	if r.URL.Path == "/"+Bucket {
		key = ""
	}
	s.mu.Lock()
	s.log = append(s.log, r.Method+" "+key)
	fault := s.Fault
	s.mu.Unlock()
	if fault != nil {
		status, delay := fault(r.Method, key)
		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-r.Context().Done():
				return
			}
		}
		if status != 0 {
			xmlError(w, status, "Fault", "an injected answer")
			return
		}
	}
	if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential="+AccessKeyID+"/") {
		xmlError(w, http.StatusForbidden, "InvalidAccessKeyId", "the access key is not known")
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/"+Bucket) {
		xmlError(w, http.StatusNotFound, "NoSuchBucket", "no such bucket")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch r.Method {
	case http.MethodPut:
		s.put(w, r, key)
	case http.MethodGet:
		if key == "" {
			s.list(w, r)
			return
		}
		o, ok := s.objs[key]
		if !ok {
			xmlError(w, http.StatusNotFound, "NoSuchKey", "no such key")
			return
		}
		_, _ = w.Write(o.body)
	case http.MethodDelete:
		o, ok := s.objs[key]
		if ok && o.locked && !s.NoEnforce && r.URL.Query().Get("versionId") != "" {
			xmlError(w, http.StatusForbidden, "AccessDenied", "the object is locked")
			return
		}
		if ok && r.URL.Query().Get("versionId") != "" {
			delete(s.objs, key)
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		xmlError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "no")
	}
}

func (s *Server) put(w http.ResponseWriter, r *http.Request, key string) {
	body, _ := io.ReadAll(r.Body)
	lock := r.Header.Get("X-Amz-Object-Lock-Mode") != ""
	if lock && s.NoLock {
		xmlError(w, http.StatusBadRequest, "InvalidRequest", "Bucket is missing Object Lock Configuration")
		return
	}
	if s.PutAnswer != nil {
		if status, code := s.PutAnswer(); status != 0 {
			xmlError(w, status, code, "an injected answer")
			return
		}
	}
	if s.RejectConditional && r.Header.Get("If-None-Match") != "" {
		xmlError(w, http.StatusBadRequest, "InvalidArgument", "If-None-Match is not understood")
		return
	}
	if lock {
		// As AWS does: a write with retention headers carries a checksum of its body.
		sum := sha256.Sum256(body)
		if r.Header.Get("X-Amz-Checksum-Sha256") != base64.StdEncoding.EncodeToString(sum[:]) {
			xmlError(w, http.StatusBadRequest, "InvalidRequest", "Content-MD5 or x-amz-checksum-* is required for Object Lock")
			return
		}
	}
	if _, taken := s.objs[key]; taken && r.Header.Get("If-None-Match") == "*" && !s.NoConditional {
		xmlError(w, http.StatusPreconditionFailed, "PreconditionFailed", "the key exists")
		return
	}
	s.seq++
	v := "v" + strconv.Itoa(s.seq)
	s.objs[key] = &object{body: body, version: v, locked: lock, mode: r.Header.Get("X-Amz-Object-Lock-Mode"),
		retain: r.Header.Get("X-Amz-Object-Lock-Retain-Until-Date")}
	if !s.NoVersions {
		w.Header().Set("X-Amz-Version-Id", v)
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	max, _ := strconv.Atoi(q.Get("max-keys"))
	if max <= 0 {
		max = 1000
	}
	after := q.Get("continuation-token")
	if after == "" {
		after = q.Get("start-after")
	}
	if s.EndlessListing || s.RepeatListing || s.RepeatToken {
		s.listings++
		if s.RepeatListing { // the same key and the same token at every page; the key is under prefix p/
			_, _ = io.WriteString(w, "<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>same</NextContinuationToken>"+
				"<Contents><Key>p/00000000000000000001</Key><Size>1</Size></Contents></ListBucketResult>")
			return
		}
		if s.RepeatToken {
			_, _ = io.WriteString(w, "<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>same</NextContinuationToken>"+
				"<Contents><Key>p/"+fmt.Sprintf("%020d", s.listings)+"</Key><Size>1</Size></Contents></ListBucketResult>")
			return
		}
		_, _ = io.WriteString(w, "<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>t"+strconv.Itoa(s.listings)+
			"</NextContinuationToken></ListBucketResult>")
		return
	}
	var keys []string
	for k := range s.objs {
		if strings.HasPrefix(k, q.Get("prefix")) && k > after {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	type content struct {
		Key  string
		Size int
	}
	out := struct {
		XMLName               xml.Name `xml:"ListBucketResult"`
		IsTruncated           bool
		NextContinuationToken string `xml:",omitempty"`
		Contents              []content
	}{}
	if len(keys) > max {
		keys, out.IsTruncated, out.NextContinuationToken = keys[:max], true, keys[max-1]
	}
	for _, k := range keys {
		out.Contents = append(out.Contents, content{k, len(s.objs[k].body)})
	}
	_ = xml.NewEncoder(w).Encode(out)
}
