// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/agentproto"
	"github.com/felix-homelab/rpmgr/internal/pki"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
)

// DenyListFile holds, in the state directory, the signed deny-lists that make up the agent's
// deny-list (docs/10-operations.md, "Filesystem layout").
const DenyListFile = "denylist.signed"

// DenyList is the agent's deny-list (docs/04-security.md, "Revocation"): the union of every signed
// list it received, each entry kept until the certificate it covers expires. A list with a lower
// version or of a new database epoch never removes an entry. It is stored as the signed lists that
// still contribute an entry, and loaded before any session.
type DenyList struct {
	o DenyListOptions

	mu   sync.RWMutex
	kept []keptList // newest first
}

// DenyListOptions configure a DenyList.
type DenyListOptions struct {
	StateDir string
	Root     *x509.Certificate // the pinned root
	// Signers returns the config-signing certificates and their intermediates, as the runtime
	// keeps them.
	Signers func() []*x509.Certificate
	Now     func() time.Time
}

type keptList struct {
	signed  *agentv1.Signed
	entries []*agentv1.DenyEntry
}

// NewDenyList returns an empty deny-list; Load fills it from the state directory.
func NewDenyList(o DenyListOptions) *DenyList {
	if o.Now == nil {
		o.Now = time.Now
	}
	return &DenyList{o: o}
}

// verify checks a signed deny-list as a snapshot is checked and returns its entries.
func (d *DenyList) verify(signed *agentv1.Signed) ([]*agentv1.DenyEntry, error) {
	payload, err := snapshot.Verify(signed, d.o.Signers(), d.o.Root, d.o.Now())
	if err != nil {
		return nil, err
	}
	list := &agentv1.DenyList{}
	if err := proto.Unmarshal(payload, list); err != nil {
		return nil, fmt.Errorf("agent: deny-list: %w", err)
	}
	for _, e := range list.GetEntries() {
		if e.GetSerial() == "" && e.GetIdentity() == "" || e.GetNotAfter() == nil {
			return nil, errors.New("agent: a deny-list entry without a subject or an expiry")
		}
	}
	return list.GetEntries(), nil
}

// Apply merges a signed deny-list from the controller, whatever happens to snapshots, and stores
// the result.
func (d *DenyList) Apply(signed *agentv1.Signed) error {
	entries, err := d.verify(signed)
	if err != nil {
		return err
	}
	d.mu.Lock()
	d.kept = prune(append([]keptList{{signed: signed, entries: entries}}, d.kept...), d.o.Now())
	kept := slices.Clone(d.kept)
	d.mu.Unlock()
	return d.store(kept)
}

// prune keeps, newest first, every list that holds an unexpired entry no newer list holds.
func prune(lists []keptList, now time.Time) []keptList {
	seen := map[string]bool{}
	var out []keptList
	for _, l := range lists {
		adds := false
		for _, e := range l.entries {
			k := denyKey(e)
			if e.GetNotAfter().AsTime().After(now) && !seen[k] {
				seen[k], adds = true, true
			}
		}
		if adds {
			out = append(out, l)
		}
	}
	return out
}

func denyKey(e *agentv1.DenyEntry) string {
	if s := e.GetSerial(); s != "" {
		return "serial " + s
	}
	return "identity " + e.GetIdentity()
}

// entries returns the unexpired entries, each once, with its latest expiry.
func (d *DenyList) entries() map[string]*agentv1.DenyEntry {
	now := d.o.Now()
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := map[string]*agentv1.DenyEntry{}
	for _, l := range d.kept {
		for _, e := range l.entries {
			k := denyKey(e)
			if e.GetNotAfter().AsTime().After(now) && (out[k] == nil || e.GetNotAfter().AsTime().After(out[k].GetNotAfter().AsTime())) {
				out[k] = e
			}
		}
	}
	return out
}

// Denied reports whether cert is denied by serial or by identity; it is pki.Expect.Denied for the
// agent's own TLS peers.
func (d *DenyList) Denied(cert *x509.Certificate) bool {
	es := d.entries()
	if es["serial "+pki.SerialHex(cert.SerialNumber)] != nil {
		return true
	}
	return len(cert.URIs) == 1 && es["identity "+cert.URIs[0].String()] != nil
}

// Digest is the digest of the unexpired entries, for Hello.
func (d *DenyList) Digest() []byte {
	es := d.entries()
	list := make([]*agentv1.DenyEntry, 0, len(es))
	for _, e := range es {
		list = append(list, e)
	}
	return pki.DenyDigest(list)
}

// store writes the kept lists, each as a length-prefixed signed message, atomically.
func (d *DenyList) store(kept []keptList) error {
	var buf bytes.Buffer
	for _, l := range kept {
		b, err := proto.Marshal(l.signed)
		if err != nil {
			return err
		}
		buf.Write(binary.AppendUvarint(nil, uint64(len(b))))
		buf.Write(b)
	}
	if err := writeAtomic(filepath.Join(d.o.StateDir, DenyListFile), buf.Bytes(), 0o600); err != nil {
		return err
	}
	return syncDir(d.o.StateDir)
}

// ErrBadDenyList is returned by Load for a stored list that does not verify; the lists that do are
// kept.
var ErrBadDenyList = errors.New("agent: a stored deny-list does not verify")

// Load reads the stored lists and verifies each. It keeps every list that verifies, so a damaged
// file loses as little as possible, and returns ErrBadDenyList if one did not.
func (d *DenyList) Load() error {
	f, err := os.Open(filepath.Join(d.o.StateDir, DenyListFile)) //nolint:gosec // G304: the configured state directory
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	r := bufio.NewReader(f)
	var kept []keptList
	var bad error
	for {
		n, err := binary.ReadUvarint(r)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || n > agentproto.MaxControlMessage {
			bad = fmt.Errorf("%w: the file is damaged", ErrBadDenyList)
			break
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(r, b); err != nil {
			bad = fmt.Errorf("%w: the file is damaged", ErrBadDenyList)
			break
		}
		signed := &agentv1.Signed{}
		if err := proto.Unmarshal(b, signed); err != nil {
			bad = fmt.Errorf("%w: %w", ErrBadDenyList, err)
			continue
		}
		entries, err := d.verify(signed)
		if err != nil {
			bad = fmt.Errorf("%w: %w", ErrBadDenyList, err)
			continue
		}
		kept = append(kept, keptList{signed: signed, entries: entries})
	}
	d.mu.Lock()
	d.kept = prune(kept, d.o.Now())
	d.mu.Unlock()
	return bad
}
