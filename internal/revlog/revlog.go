// SPDX-License-Identifier: Apache-2.0

// Package revlog is the controller's revocation log (docs/04-security.md, "Revocation log"): an
// append-only, hash-chained file outside the database that records every revocation and credential
// supersession, so that a restore from an older backup can apply them again. Each entry is one
// line of JSON, written and synced before Append returns.
package revlog

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Kind is what an entry records (docs/04-security.md, "Revocation log"; R46).
type Kind string

// The kinds of entry. Subject names what was revoked or superseded.
const (
	CertificateRevoked    Kind = "certificate_revoked"    // Subject: the serial, hexadecimal
	IdentityRevoked       Kind = "identity_revoked"       // Subject: the SPIFFE ID
	CertificateSuperseded Kind = "certificate_superseded" // Subject: the serial, hexadecimal
	APITokenRevoked       Kind = "api_token_revoked"      // Subject: the token ID
	SessionRevoked        Kind = "session_revoked"        // Subject: the session ID
	MemberRemoved         Kind = "member_removed"         // Subject: the user ID; Org
	RoleDowngraded        Kind = "role_downgraded"        // Subject: the user ID; Org; Detail: the new role
	// CredentialSuperseded: Subject is the user ID; Detail is password, mfa or recovery_codes.
	CredentialSuperseded Kind = "credential_superseded" //nolint:gosec // G101: an entry kind, not a credential
	GrantRemoved         Kind = "grant_removed"         // Subject: the grant ID; Detail: shell or visitor
)

var kinds = map[Kind]bool{CertificateRevoked: true, IdentityRevoked: true, CertificateSuperseded: true,
	APITokenRevoked: true, SessionRevoked: true, MemberRemoved: true, RoleDowngraded: true,
	CredentialSuperseded: true, GrantRemoved: true}

// MaxField is the longest Org, Subject, Detail or Actor an entry holds, in bytes.
const MaxField = 512

// Entry is one record of the log.
type Entry struct {
	Seq     uint64    `json:"seq"`
	Time    time.Time `json:"time"`
	Kind    Kind      `json:"kind"`
	Org     string    `json:"org,omitempty"`
	Subject string    `json:"subject"`
	Detail  string    `json:"detail,omitempty"`
	// NotAfter is when a revoked or superseded certificate expires; after it the entry no longer
	// matters to relying parties.
	NotAfter *time.Time `json:"not_after,omitempty"`
	Actor    string     `json:"actor,omitempty"`
	Prev     string     `json:"prev"` // the hash of the previous entry; empty for the first
	Hash     string     `json:"hash"` // hex SHA-256 of this entry encoded with an empty hash
}

// hash returns the entry's hash: SHA-256 over its JSON encoding with Hash empty. The field order
// of Entry fixes the encoding.
func (e Entry) hash() (string, error) {
	e.Hash = ""
	b, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func (e Entry) check() error {
	switch {
	case !kinds[e.Kind]:
		return fmt.Errorf("revlog: unknown kind %q", e.Kind)
	case e.Subject == "":
		return errors.New("revlog: an entry needs a subject")
	case len(e.Org) > MaxField || len(e.Subject) > MaxField || len(e.Detail) > MaxField || len(e.Actor) > MaxField:
		return fmt.Errorf("revlog: a field is longer than %d bytes", MaxField)
	}
	return nil
}

// ErrBroken is returned for a log whose hash chain does not verify.
var ErrBroken = errors.New("revlog: the hash chain is broken")

// Log appends to the revocation log at one path. Appends are serialised within the process by a
// mutex and between processes, such as an admin command beside the running controller, by a file
// lock.
type Log struct {
	path string
	now  func() time.Time
	mu   sync.Mutex
}

// Open opens the log at path, creating it with mode 0640 if it does not exist, and verifies its
// hash chain. now stamps new entries; nil is time.Now.
func Open(path string, now func() time.Time) (*Log, error) {
	if now == nil {
		now = time.Now
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o640) //nolint:gosec // G304: the configured state directory
	if err != nil {
		return nil, err
	}
	_ = f.Close()
	if _, err := Read(path); err != nil {
		return nil, err
	}
	return &Log{path: path, now: now}, nil
}

// Append adds e to the log and returns it with its sequence number, time and hashes. It returns
// after the entry is synced to disk. A line that an interrupted append left incomplete, which was
// never acknowledged, is cut off first.
func (l *Log) Append(e Entry) (Entry, error) {
	if err := e.check(); err != nil {
		return Entry{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.OpenFile(l.path, os.O_RDWR, 0) //nolint:gosec // G304: the configured state directory
	if err != nil {
		return Entry{}, err
	}
	defer func() { _ = f.Close() }()
	unlock, err := lock(f)
	if err != nil {
		return Entry{}, err
	}
	defer unlock()
	last, end, err := tail(f)
	if err != nil {
		return Entry{}, err
	}
	if err := f.Truncate(end); err != nil {
		return Entry{}, err
	}
	e.Seq, e.Prev = 1, ""
	if last != nil {
		e.Seq, e.Prev = last.Seq+1, last.Hash
	}
	if e.Time.IsZero() {
		e.Time = l.now().UTC()
	}
	if e.Hash, err = e.hash(); err != nil {
		return Entry{}, err
	}
	line, err := json.Marshal(e)
	if err != nil {
		return Entry{}, err
	}
	if _, err := f.WriteAt(append(line, '\n'), end); err != nil {
		return Entry{}, err
	}
	return e, f.Sync()
}

// tailWindow is how far from the end tail looks for the last complete line; an entry is far
// shorter, because every field is bounded by MaxField.
const tailWindow = 16 << 10

// tail returns the last complete entry of f, or nil for an empty log, and the offset just after
// it, where the next entry goes.
func tail(f *os.File) (*Entry, int64, error) {
	st, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	start := max(st.Size()-tailWindow, 0)
	buf := make([]byte, st.Size()-start)
	if _, err := f.ReadAt(buf, start); err != nil && !errors.Is(err, io.EOF) {
		return nil, 0, err
	}
	end := bytes.LastIndexByte(buf, '\n')
	if end < 0 {
		if start > 0 {
			return nil, 0, fmt.Errorf("%w: no complete line in the last %d bytes", ErrBroken, tailWindow)
		}
		return nil, 0, nil // empty, or only an incomplete first line
	}
	lineStart := bytes.LastIndexByte(buf[:end], '\n') + 1
	if lineStart == 0 && start > 0 {
		return nil, 0, fmt.Errorf("%w: a line longer than %d bytes", ErrBroken, tailWindow)
	}
	var e Entry
	if err := json.Unmarshal(buf[lineStart:end], &e); err != nil {
		return nil, 0, fmt.Errorf("%w: the last entry: %w", ErrBroken, err)
	}
	return &e, start + int64(end) + 1, nil
}

// Read returns every complete entry of the log at path after verifying the hash chain: sequence
// numbers from 1 without gaps, each entry's hash, and each link to the previous entry. An
// incomplete last line, which an interrupted append leaves, is ignored.
func Read(path string) ([]Entry, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the configured state directory or a restore's input
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	r := bufio.NewReader(f)
	var out []Entry
	prev := ""
	for n := 1; ; n++ {
		line, err := r.ReadBytes('\n')
		if errors.Is(err, io.EOF) {
			return out, nil // a line without its newline was never acknowledged
		}
		if err != nil {
			return nil, err
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, fmt.Errorf("%w: line %d: %w", ErrBroken, n, err)
		}
		h, err := e.hash()
		switch {
		case err != nil:
			return nil, err
		case e.Seq != uint64(n): //nolint:gosec // G115: n counts from 1
			return nil, fmt.Errorf("%w: line %d has sequence number %d", ErrBroken, n, e.Seq)
		case e.Prev != prev:
			return nil, fmt.Errorf("%w: line %d does not follow line %d", ErrBroken, n, n-1)
		case e.Hash != h:
			return nil, fmt.Errorf("%w: line %d was altered", ErrBroken, n)
		}
		if err := e.check(); err != nil {
			return nil, fmt.Errorf("%w: line %d: %w", ErrBroken, n, err)
		}
		prev = e.Hash
		out = append(out, e)
	}
}
