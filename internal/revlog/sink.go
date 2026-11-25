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
// hash; a later Ship lists only the keys after it. A broken chain stops shipping until the Sink
// is made anew, with a new prefix.
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
}

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

// reset forgets the verified prefix and what is shipped, all together.
func (s *Sink) reset() {
	s.loaded, s.last, s.prev = false, 0, ""
	s.shipped = map[string]map[string]bool{}
}

func (s *Sink) fail(err error) error {
	s.broken = err
	return err
}

// sync extends the verified prefix by the entries that others created; the caller holds s.mu.
// With checkTip it first confirms that the entry the prefix ends at is still there and unchanged,
// and every ReverifyEvery it verifies the whole sink from entry 1 again. A sink that has lost
// every object is verified as empty and shipped to again from entry 1, as a share that is not
// mounted shows an empty directory; any other loss is a break.
func (s *Sink) sync(checkTip bool) error {
	if s.broken != nil {
		return s.broken
	}
	if s.loaded && checkTip && s.now().Sub(s.verifiedAt) >= ReverifyEvery {
		s.loaded = false
	}
	full := !s.loaded
	if full {
		s.reset()
	}
	after := ""
	switch {
	case s.last > 0 && checkTip:
		after = Key(s.last - 1)
	case s.last > 0:
		after = Key(s.last)
	}
	keys, err := s.backend.List(after)
	if err != nil {
		return err
	}
	if checkTip && s.last > 0 {
		if len(keys) == 0 || keys[0] != Key(s.last) {
			all, err := s.backend.List("")
			if err != nil {
				return err
			}
			if len(all) > 0 {
				return s.fail(fmt.Errorf("%w: the sink has lost its entry %d", ErrBroken, s.last))
			}
			s.reset()
			full, keys = true, nil
		} else {
			b, err := s.backend.Get(keys[0])
			if err != nil {
				return err
			}
			var tip SinkEntry
			if err := json.Unmarshal(b, &tip); err != nil {
				return s.fail(fmt.Errorf("%w: sink entry %d: %w", ErrBroken, s.last, err))
			}
			h, err := tip.hash()
			if err != nil {
				return err
			}
			if tip.Seq != s.last || tip.Hash != s.prev || h != s.prev {
				return s.fail(fmt.Errorf("%w: sink entry %d is not the one verified", ErrBroken, s.last))
			}
			keys = keys[1:]
		}
	}
	got, err := s.scan(keys, s.last, s.prev)
	for _, e := range got {
		if s.shipped[e.Replica] == nil {
			s.shipped[e.Replica] = map[string]bool{}
		}
		s.shipped[e.Replica][e.Entry.Hash] = true
		s.last, s.prev = e.Seq, e.Hash
	}
	if err != nil {
		if errors.Is(err, ErrBroken) {
			return s.fail(err)
		}
		return err
	}
	s.loaded = true
	if full {
		s.verifiedAt = s.now()
	}
	return nil
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
	if err := s.sync(true); err != nil {
		return local, err
	}
	var todo []Entry
	for _, e := range local {
		if !s.shipped[replica][e.Hash] {
			todo = append(todo, e)
		}
	}
	for len(todo) > 0 {
		e := SinkEntry{Seq: s.last + 1, Replica: replica, Entry: todo[0], Prev: s.prev}
		if e.Hash, err = e.hash(); err != nil {
			return todo, err
		}
		b, err := json.Marshal(e)
		if err != nil {
			return todo, err
		}
		switch err := s.backend.CreateIfAbsent(Key(e.Seq), append(b, '\n')); {
		case errors.Is(err, ErrExists): // another replica took the number: read it, try the next
			before := s.last
			if err := s.sync(false); err != nil {
				return todo, err
			}
			if s.last == before {
				return todo, s.fail(fmt.Errorf("%w: the sink key %s exists but is not listed", ErrBroken, Key(e.Seq)))
			}
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
	return nil, nil
}

// Status is where a replica's revocation log stands, for the UI and the metrics.
type Status struct {
	Sink      bool      // whether a sink takes copies off the host
	Unshipped int       // entries the sink does not hold yet
	Oldest    time.Time // when the oldest of them was logged; zero when none
	LastOK    time.Time // when a shipping round last succeeded, or began if none has; zero unknown
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
