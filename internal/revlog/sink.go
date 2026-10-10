// SPDX-License-Identifier: Apache-2.0

package revlog

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"
)

// Sink is the filesystem sink of the revocation log (docs/10-operations.md, "Backup and
// restore"): a directory, usually on a share, that holds a copy of every replica's entries off
// the host. Each sink entry is the file named by its sequence number. It is published by a hard
// link, which fails when the name exists, so allocating the number and writing the entry are one
// step: the sink has no gaps, and an interrupted write leaves no empty number. Sink entries form
// their own hash chain over the entries of all replicas.
type Sink struct {
	Dir string
}

// SinkEntry is a file of the sink: a replica's local entry as that replica logged it.
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

// Read returns every entry of the sink after verifying its chain: files named 1 to n without a
// gap, each entry's hash and each link. Temporary files of writers are skipped.
func (s Sink) Read() ([]SinkEntry, error) {
	des, err := os.ReadDir(s.Dir)
	if err != nil {
		return nil, err
	}
	var seqs []uint64
	for _, de := range des {
		if n, err := strconv.ParseUint(de.Name(), 10, 64); err == nil {
			seqs = append(seqs, n)
		}
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	out := make([]SinkEntry, 0, len(seqs))
	prev := ""
	for i, n := range seqs {
		if n != uint64(i)+1 {
			return nil, fmt.Errorf("%w: the sink has no entry %d", ErrBroken, i+1)
		}
		b, err := os.ReadFile(filepath.Join(s.Dir, strconv.FormatUint(n, 10)))
		if err != nil {
			return nil, err
		}
		var e SinkEntry
		if err := json.Unmarshal(b, &e); err != nil {
			return nil, fmt.Errorf("%w: sink entry %d: %w", ErrBroken, n, err)
		}
		h, err := e.hash()
		if err != nil {
			return nil, err
		}
		if e.Seq != n || e.Prev != prev || e.Hash != h {
			return nil, fmt.Errorf("%w: sink entry %d", ErrBroken, n)
		}
		out, prev = append(out, e), h
	}
	return out, nil
}

// Ship copies the entries of the local log at path that the sink does not hold yet for replica
// into the sink, in order. What a replica has shipped is read from the sink itself, by the
// entries' hashes, so a crash between publishing an entry and anything else ships nothing twice,
// and the entries a restore appended to a restored log are shipped although their numbers were
// taken before. It returns the entries still unshipped, none when it succeeds.
func (s Sink) Ship(path, replica string) ([]Entry, error) {
	local, err := Read(path)
	if err != nil {
		return nil, err
	}
	sink, err := s.Read()
	if err != nil {
		return local, err
	}
	shipped := map[string]bool{}
	for _, e := range sink {
		if e.Replica == replica {
			shipped[e.Entry.Hash] = true
		}
	}
	var todo []Entry
	for _, e := range local {
		if !shipped[e.Hash] {
			todo = append(todo, e)
		}
	}
	for len(todo) > 0 {
		next, prev := uint64(len(sink))+1, ""
		if len(sink) > 0 {
			prev = sink[len(sink)-1].Hash
		}
		e := SinkEntry{Seq: next, Replica: replica, Entry: todo[0], Prev: prev}
		if e.Hash, err = e.hash(); err != nil {
			return todo, err
		}
		taken, err := s.publish(e)
		if err != nil {
			return todo, err
		}
		if taken { // another replica took the number: read its entry, and try the next
			if sink, err = s.Read(); err != nil {
				return todo, err
			}
			continue
		}
		sink, todo = append(sink, e), todo[1:]
	}
	return nil, nil
}

// publish writes e to a temporary file, syncs it, and links it to its number; taken reports that
// the number exists already.
func (s Sink) publish(e SinkEntry) (taken bool, err error) {
	b, err := json.Marshal(e)
	if err != nil {
		return false, err
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return false, err
	}
	tmp := filepath.Join(s.Dir, ".tmp-"+hex.EncodeToString(suffix))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640) //nolint:gosec // G304: the configured sink
	if err != nil {
		return false, err
	}
	defer func() { _ = os.Remove(tmp) }()
	_, err = f.Write(append(b, '\n'))
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return false, err
	}
	if err := os.Link(tmp, filepath.Join(s.Dir, strconv.FormatUint(e.Seq, 10))); err != nil {
		if errors.Is(err, os.ErrExist) {
			return true, nil
		}
		return false, err
	}
	if d, err := os.Open(s.Dir); err == nil { // the new name, durable
		_ = d.Sync()
		_ = d.Close()
	}
	return false, nil
}

// Status is where a replica's revocation log stands, for the UI and the metrics.
type Status struct {
	Sink      bool      // whether a sink takes copies off the host
	Unshipped int       // entries the sink does not hold yet
	Oldest    time.Time // when the oldest of them was logged; zero when none
}

// OffHostAlert is how long an entry may stay unshipped before the alert "revocation log not yet
// off-host" fires (docs/10-operations.md, "Suggested alerts").
const OffHostAlert = 5 * time.Minute

// Alerting reports whether the alert fires at now: a sink exists and an entry has waited longer
// than OffHostAlert. Without a sink, the UI shows a standing warning instead.
func (s Status) Alerting(now time.Time) bool {
	return s.Sink && s.Unshipped > 0 && now.Sub(s.Oldest) > OffHostAlert
}

// StatusOf is the status after a shipping attempt that left unshipped behind.
func StatusOf(sink bool, unshipped []Entry) Status {
	st := Status{Sink: sink, Unshipped: len(unshipped)}
	if len(unshipped) > 0 {
		st.Oldest = unshipped[0].Time
	}
	return st
}
