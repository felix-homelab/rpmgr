// SPDX-License-Identifier: Apache-2.0

package revlog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/felix-homelab/rpmgr/internal/objstore"
)

// Backend is where a sink keeps its objects (docs/04-security.md, "Revocation log"). It has three
// operations, so a directory and an object store both fit. Keys are those of Key.
type Backend interface {
	// List returns the keys after the given key, in ascending order; "" lists them all.
	List(after string) ([]string, error)
	// Get returns the object at key.
	Get(key string) ([]byte, error)
	// CreateIfAbsent writes data at key and returns ErrExists, without writing, when the key
	// exists, whatever the content there.
	CreateIfAbsent(key string, data []byte) error
}

// ErrExists is what Backend.CreateIfAbsent returns for a key that exists already.
var ErrExists = errors.New("revlog: the sink key exists")

// keyDigits is the width of a key: a uint64 has at most 20 decimal digits.
const keyDigits = 20

// Key is the object key of sequence number seq: 20 decimal digits with leading zeros, so that the
// order of a listing is the numeric order.
func Key(seq uint64) string { return fmt.Sprintf("%0*d", keyDigits, seq) }

func parseKey(key string) (uint64, bool) {
	if len(key) != keyDigits {
		return 0, false
	}
	n, err := strconv.ParseUint(key, 10, 64)
	return n, err == nil
}

// Sink is the sink of the revocation log: a copy of every replica's entries off the host, behind
// a Backend. Each sink entry is the object named by its sequence number. It is created only when
// the key is absent, so allocating the number and writing the entry are one step: the sink has no
// gaps, and an interrupted write leaves no empty number. Sink entries form their own hash chain
// over the entries of all replicas.
//
// A Sink verifies the chain once and keeps the verified prefix, the last sequence number and
// hash; a later Ship lists only the keys after it. A broken chain stops shipping until an
// operator points the sink at a new directory.
type Sink struct {
	// Now is the clock; nil means time.Now. Tests set it.
	Now     func() time.Time
	backend Backend

	mu         sync.Mutex
	loaded     bool
	verifiedAt time.Time // when the whole sink was last verified from entry 1
	last       uint64
	prev       string
	shipped    map[string]map[string]bool // replica -> hashes of its local entries in the sink
	broken     error
	lagged     int // rounds in a row that found a taken key unlisted
}

// MaxUnlistedRounds is how many rounds in a row may find the key they lost unlisted before the sink
// counts as broken (docs/04-security.md, "Revocation log").
const MaxUnlistedRounds = 3

// ErrListingLags is returned when a create was refused because the key exists and the listing does
// not show it yet. It is not a break: the next round lists again.
var ErrListingLags = errors.New("revlog: the sink's listing lags behind its writes")

// ReverifyEvery is how often a Sink verifies the whole sink again from entry 1, so that a key
// deleted or an object rewritten below the verified prefix is found (docs/03-connections.md,
// "Timeouts and limits").
const ReverifyEvery = time.Hour

// NewSink returns a Sink over b.
func NewSink(b Backend) *Sink { return &Sink{backend: b} }

// SinkEntry is an object of the sink: a replica's local entry as that replica logged it.
type SinkEntry struct {
	Seq     uint64 `json:"seq"`
	Replica string `json:"replica"`
	Entry   Entry  `json:"entry"`
	Prev    string `json:"prev"` // the hash of the previous sink entry; empty for the first
	Hash    string `json:"hash"` // hex SHA-256 of this sink entry encoded with an empty hash
}

func (e SinkEntry) hash() (string, error) {
	e.Hash = ""
	b, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// scan verifies the objects at keys, which follow the entry seq with hash prev: keys in sequence
// without a gap, and each entry's number, link and hash. It returns the entries that verified,
// also when it returns an error.
func (s *Sink) scan(keys []string, seq uint64, prev string) ([]SinkEntry, error) {
	var out []SinkEntry
	for _, key := range keys {
		n, ok := parseKey(key)
		if !ok {
			return out, fmt.Errorf("%w: the sink holds the unexpected key %q", ErrBroken, key)
		}
		if n != seq+1 {
			return out, fmt.Errorf("%w: the sink has no entry %d", ErrBroken, seq+1)
		}
		b, err := s.backend.Get(key)
		if err != nil {
			return out, err
		}
		var e SinkEntry
		if err := json.Unmarshal(b, &e); err != nil {
			return out, fmt.Errorf("%w: sink entry %d: %w", ErrBroken, n, err)
		}
		h, err := e.hash()
		if err != nil {
			return out, err
		}
		if e.Seq != n || e.Prev != prev || e.Hash != h {
			return out, fmt.Errorf("%w: sink entry %d", ErrBroken, n)
		}
		// The sink's hash is unkeyed, so whoever can write the bucket can recompute it. The entry
		// inside must still be the one its own hash names: a restore de-duplicates by that hash,
		// and a forged entry that claimed another's hash would hide it.
		if ih, err := e.Entry.hash(); err != nil {
			return out, err
		} else if ih != e.Entry.Hash {
			return out, fmt.Errorf("%w: sink entry %d holds an entry that was altered", ErrBroken, n)
		}
		if err := e.Entry.checkShape(); err != nil {
			return out, fmt.Errorf("%w: sink entry %d: %w", ErrBroken, n, err)
		}
		out, seq, prev = append(out, e), n, h
	}
	return out, nil
}

// Read returns every entry of the sink after verifying its whole chain. It does not use or change
// the verified prefix.
func (s *Sink) Read() ([]SinkEntry, error) {
	keys, err := s.backend.List("")
	if err != nil {
		return nil, err
	}
	out, err := s.scan(keys, 0, "")
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Sink) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Sink) fail(err error) error {
	s.broken = err
	return err
}

// fullCheck verifies the whole sink from entry 1 and replaces the verified prefix and the shipped
// set by what it found, when the chain reaches the entry the old verified prefix ended at and that
// entry is the one verified. On the first load there is no such anchor, and an empty sink is then
// shipped to from entry 1; on any later check an empty or replaced sink is a break.
func (s *Sink) fullCheck() error {
	keys, err := s.backend.List("")
	if err != nil {
		return err
	}
	got, err := s.scan(keys, 0, "")
	if err != nil {
		if errors.Is(err, ErrBroken) {
			return s.fail(err)
		}
		return err
	}
	if s.last > 0 && (uint64(len(got)) < s.last || got[s.last-1].Hash != s.prev) {
		return s.fail(fmt.Errorf("%w: the sink no longer holds the entry %d that was verified", ErrBroken, s.last))
	}
	s.shipped = map[string]map[string]bool{}
	s.last, s.prev = 0, ""
	s.extend(got)
	s.loaded, s.verifiedAt = true, s.now()
	return nil
}

func (s *Sink) extend(got []SinkEntry) {
	for _, e := range got {
		if s.shipped[e.Replica] == nil {
			s.shipped[e.Replica] = map[string]bool{}
		}
		s.shipped[e.Replica][e.Entry.Hash] = true
		s.last, s.prev = e.Seq, e.Hash
	}
}

// sync extends the verified prefix by the entries that others created and returns them; the
// caller holds s.mu. With checkTip it first confirms that the entry the prefix ends at is still
// there and unchanged, and every ReverifyEvery it verifies the whole sink from entry 1 again,
// anchored at the prefix. A sink that lost the tip, or all its objects, after it was verified is
// a break: an unmounted share would otherwise take the entries as if they were off the host.
func (s *Sink) sync(checkTip bool) ([]SinkEntry, error) {
	if s.broken != nil {
		return nil, s.broken
	}
	if !s.loaded || (checkTip && s.now().Sub(s.verifiedAt) >= ReverifyEvery) {
		return nil, s.fullCheck()
	}
	after := Key(s.last)
	if checkTip && s.last > 0 {
		after = Key(s.last - 1)
	}
	keys, err := s.backend.List(after)
	if err != nil {
		return nil, err
	}
	if checkTip && s.last > 0 {
		if len(keys) == 0 || keys[0] != Key(s.last) {
			return nil, s.fail(fmt.Errorf("%w: the sink has lost its entry %d", ErrBroken, s.last))
		}
		b, err := s.backend.Get(keys[0])
		if err != nil {
			return nil, err
		}
		var tip SinkEntry
		if err := json.Unmarshal(b, &tip); err != nil {
			return nil, s.fail(fmt.Errorf("%w: sink entry %d: %w", ErrBroken, s.last, err))
		}
		h, err := tip.hash()
		if err != nil {
			return nil, err
		}
		if tip.Seq != s.last || tip.Hash != s.prev || h != s.prev {
			return nil, s.fail(fmt.Errorf("%w: sink entry %d is not the one verified", ErrBroken, s.last))
		}
		keys = keys[1:]
	}
	got, err := s.scan(keys, s.last, s.prev)
	s.extend(got)
	if err != nil {
		if errors.Is(err, ErrBroken) {
			return got, s.fail(err)
		}
		return got, err
	}
	return got, nil
}

// Ship copies the entries of the local log at path that the sink does not hold yet for replica
// into the sink, in order. An entry counts as shipped when the sink holds an object with its
// replica and its hash, so a crash between creating an object and anything else ships nothing
// twice, and the entries a restore appended to a restored log are shipped although their numbers
// were taken before. A tick with nothing new lists the keys after the verified prefix and reads
// none. It returns the entries still unshipped, none when it succeeds.
func (s *Sink) Ship(path, replica string) ([]Entry, error) {
	local, err := Read(path)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.sync(true); err != nil {
		return local, err
	}
	var todo []Entry
	for _, e := range local {
		if !s.shipped[replica][e.Hash] {
			todo = append(todo, e)
		}
	}
	tried := map[uint64]string{} // what this call tried to create: sequence number -> hash
	for len(todo) > 0 {
		e := SinkEntry{Seq: s.last + 1, Replica: replica, Entry: todo[0], Prev: s.prev}
		if e.Hash, err = e.hash(); err != nil {
			return todo, err
		}
		b, err := json.Marshal(e)
		if err != nil {
			return todo, err
		}
		tried[e.Seq] = e.Hash
		switch err := s.backend.CreateIfAbsent(Key(e.Seq), append(b, '\n')); {
		case errors.Is(err, ErrExists): // another replica took the number: read it, try the next
			before := s.last
			got, err := s.sync(false)
			if err != nil {
				return todo, err
			}
			// An object that names this replica must be one it tried to create, as when the reply
			// of its own create was lost; anything else is planted.
			for _, g := range got {
				if h, ok := tried[g.Seq]; g.Replica == replica && (!ok || h != g.Hash) {
					return todo, s.fail(fmt.Errorf("%w: sink entry %d names this replica but is not its entry", ErrBroken, g.Seq))
				}
			}
			if s.last == before {
				// A store whose listing lags behind its writes shows the key a moment later, so the
				// first rounds are an error to retry; a key that stays unlisted is planted or hidden.
				if s.lagged++; s.lagged >= MaxUnlistedRounds {
					return todo, s.fail(fmt.Errorf("%w: the sink key %s exists but is not listed", ErrBroken, Key(e.Seq)))
				}
				return todo, fmt.Errorf("%w: the sink key %s exists but is not listed yet", ErrListingLags, Key(e.Seq))
			}
			s.lagged = 0
			// The object may be this replica's own, whose reply was lost: it is shipped then.
			var rest []Entry
			for _, t := range todo {
				if !s.shipped[replica][t.Hash] {
					rest = append(rest, t)
				}
			}
			todo = rest
		case err != nil:
			return todo, err
		default:
			if s.shipped[replica] == nil {
				s.shipped[replica] = map[string]bool{}
			}
			s.shipped[replica][e.Entry.Hash] = true
			s.last, s.prev, todo = e.Seq, e.Hash, todo[1:]
		}
	}
	s.lagged = 0
	return nil, nil
}

// Status is where a replica's revocation log stands, for the UI and the metrics.
type Status struct {
	Sink      bool      // whether a sink takes copies off the host
	Unshipped int       // entries the sink does not hold yet
	Oldest    time.Time // when the oldest of them was logged; zero when none
	LastOK    time.Time // when a shipping round last succeeded, or began if none has; zero unknown
	Reason    string    // why the last round failed, one of the Reason constants; empty after a success
}

// Why a shipping round failed, for the status and the log.
const (
	ReasonRefused       = "refused"               // the store answered with a client error, such as 403
	ReasonUnreachable   = "unreachable"           // a timeout, a transport failure, 5xx or a lagging listing
	ReasonNoConditional = "no_conditional_create" // the store does not refuse a second create
	ReasonBroken        = "broken"                // the sink's chain does not verify
	ReasonError         = "error"
)

// ReasonOf names why a round failed with err; empty for nil.
func ReasonOf(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrNoConditionalCreate):
		return ReasonNoConditional
	case errors.Is(err, ErrBroken):
		return ReasonBroken
	case errors.Is(err, ErrListingLags), errors.Is(err, ErrListing), objstore.Retryable(err):
		return ReasonUnreachable
	case objstore.Refused(err):
		return ReasonRefused
	}
	return ReasonError
}

// OffHostAlert is how long an entry may stay unshipped before the alert "revocation log not yet
// off-host" fires (docs/10-operations.md, "Suggested alerts").
const OffHostAlert = 5 * time.Minute

// Alerting reports whether the alert fires at now: a sink exists and an entry has waited longer
// than OffHostAlert. Without a sink, the UI shows a standing warning instead.
func (s Status) Alerting(now time.Time) bool {
	if !s.Sink {
		return false
	}
	// A round that has not finished for that long counts as well: a hung sink shows no backlog.
	return (s.Unshipped > 0 && now.Sub(s.Oldest) > OffHostAlert) ||
		(!s.LastOK.IsZero() && now.Sub(s.LastOK) > OffHostAlert)
}

// StatusOf is the status after a shipping attempt that left unshipped behind.
func StatusOf(sink bool, unshipped []Entry) Status {
	st := Status{Sink: sink, Unshipped: len(unshipped)}
	if len(unshipped) > 0 {
		st.Oldest = unshipped[0].Time
	}
	return st
}
