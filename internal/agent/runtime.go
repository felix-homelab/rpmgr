// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/agent/v1"
	"github.com/felix-homelab/rpmgr/internal/snapshot"
)

// LastKnownGoodFile is the last applied snapshot in the state directory, as it was signed
// (docs/10-operations.md, "Filesystem layout").
const LastKnownGoodFile = "snapshot.signed"

// Changes is what a snapshot changes against the one the agent runs, by resource ID.
type Changes struct {
	Added, Changed, Removed, Unchanged []string
}

// Applier runs the resources of a role (docs/03-connections.md, "Configuration reconciliation").
type Applier interface {
	// Validate checks a whole snapshot before anything changes; any error rejects it.
	Validate(snap *agentv1.Snapshot) []*agentv1.SnapshotError
	// Apply prepares the added and changed resources next to the running ones, swaps them in and
	// lets the removed ones drain; unchanged resources stay untouched. It returns the resources
	// that are not ready.
	Apply(ctx context.Context, snap *agentv1.Snapshot, c Changes) []*agentv1.ResourceStatus
}

// RuntimeOptions configure a Runtime.
type RuntimeOptions struct {
	Identity Loaded
	StateDir string
	Applier  Applier
	// Send sends an answer to the controller, normally Client.Send; may be nil.
	Send func(*agentv1.AgentMessage) bool
	// OnEndpoints gets the controller endpoints of every applied snapshot; may be nil.
	OnEndpoints func([]string)
	Now         func() time.Time
	Logger      *slog.Logger
}

// Runtime applies the agent's snapshots: it verifies each, ignores one that is not newer, lets the
// role validate and apply the rest, keeps the last applied one on disk as the last-known-good copy
// and answers the controller. Of several snapshots that arrive while one is applied, only the
// newest is applied next.
type Runtime struct {
	o RuntimeOptions

	mu      sync.Mutex
	signers []*x509.Certificate // config-signing certificates and intermediates
	epoch   string              // the database epoch the last Welcome announced
	cur     *running            // the snapshot applied last; nil before the first
	next    *agentv1.Signed     // the newest snapshot not yet applied
	wake    chan struct{}
}

// running is the snapshot the agent runs.
type running struct {
	rev       *agentv1.Revision
	hash      []byte
	resources map[string][]byte // resource hash by ID
}

// NewRuntime returns a runtime that verifies snapshots with the identity's signing certificates.
func NewRuntime(o RuntimeOptions) *Runtime {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Send == nil {
		o.Send = func(*agentv1.AgentMessage) bool { return false }
	}
	return &Runtime{o: o, signers: slices.Clone(o.Identity.Signing), wake: make(chan struct{}, 1)}
}

// ErrBadLastKnownGood is returned by LoadLastKnownGood for a copy that does not verify.
var ErrBadLastKnownGood = errors.New("agent: the last-known-good snapshot does not verify; starting without it")

// LoadLastKnownGood applies the last-known-good copy, if there is one, after verifying it as if it
// had just arrived. A copy that does not verify is not applied, and the agent starts empty.
func (r *Runtime) LoadLastKnownGood(ctx context.Context) error {
	b, err := os.ReadFile(filepath.Join(r.o.StateDir, LastKnownGoodFile)) //nolint:gosec // G304: the configured state directory
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	signed := &agentv1.Signed{}
	if err := proto.Unmarshal(b, signed); err != nil {
		return fmt.Errorf("%w: %w", ErrBadLastKnownGood, err)
	}
	snap, err := r.verify(signed)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrBadLastKnownGood, err)
	}
	if errs := r.validate(snap); len(errs) > 0 {
		return fmt.Errorf("%w: %s", ErrBadLastKnownGood, errs[0].GetMessage())
	}
	r.apply(ctx, signed, snap)
	return nil
}

// Hello fills the last applied revision and hash into a Hello; it is ClientOptions.Hello.
func (r *Runtime) Hello(h *agentv1.Hello) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cur != nil {
		h.LastApplied, h.LastAppliedHash = proto.Clone(r.cur.rev).(*agentv1.Revision), slices.Clone(r.cur.hash)
	}
}

// Welcome takes the database epoch and the signing certificates of a Welcome; it is
// ClientOptions.OnWelcome. The certificates replace the stored ones, so that a snapshot signed by
// the next key verifies, also after a restart.
func (r *Runtime) Welcome(w *agentv1.Welcome) {
	var certs []*x509.Certificate
	for _, der := range w.GetSigningCertificates() {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			r.o.Logger.Warn("ignoring the signing certificates of a Welcome", "error", err)
			certs = nil
			break
		}
		certs = append(certs, c)
	}
	r.mu.Lock()
	r.epoch = w.GetDbEpoch()
	changed := len(certs) > 0 && !slices.EqualFunc(certs, r.signers, (*x509.Certificate).Equal)
	if changed {
		r.signers = certs
	}
	r.mu.Unlock()
	if changed && r.o.Identity.Dir != "" {
		if err := writeAtomic(filepath.Join(r.o.Identity.Dir, SigningFile), certsPEM(certs), 0o644); err != nil {
			r.o.Logger.Error("cannot store the signing certificates", "error", err)
		}
	}
}

// Signers returns the config-signing certificates and their intermediates the runtime verifies
// with.
func (r *Runtime) Signers() []*x509.Certificate {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.signers)
}

// Message takes a snapshot from the control session; it is ClientOptions.OnMessage. It never
// blocks: a snapshot replaces one that is still waiting.
func (r *Runtime) Message(m *agentv1.ControllerMessage) {
	if m.GetSnapshot() == nil {
		return
	}
	r.mu.Lock()
	r.next = m.GetSnapshot()
	r.mu.Unlock()
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// Run applies snapshots until ctx ends.
func (r *Runtime) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.wake:
		}
		r.mu.Lock()
		signed := r.next
		r.next = nil
		r.mu.Unlock()
		if signed != nil {
			r.receive(ctx, signed)
		}
	}
}

// receive verifies, checks the revision, validates and applies one snapshot, and answers.
func (r *Runtime) receive(ctx context.Context, signed *agentv1.Signed) {
	hash := snapshot.Hash(signed)
	snap, err := r.verify(signed)
	if err != nil {
		r.o.Logger.Error("rejecting a snapshot that does not verify", "error", err)
		r.reject(nil, hash, []*agentv1.SnapshotError{{Message: err.Error()}})
		return
	}
	rev := snap.GetRevision()
	r.mu.Lock()
	cur, epoch := r.cur, r.epoch
	r.mu.Unlock()
	if cur != nil && bytes.Equal(cur.hash, hash) {
		r.o.Send(applied(rev, hash, nil)) // the controller missed the answer
		return
	}
	if cur != nil && !newer(rev, cur.rev, epoch) {
		r.o.Logger.Info("ignoring a snapshot that is not newer", "seq", rev.GetSeq(), "db_epoch", rev.GetDbEpoch(),
			"running_seq", cur.rev.GetSeq())
		return
	}
	if errs := r.validate(snap); len(errs) > 0 {
		r.o.Logger.Error("rejecting an invalid snapshot; keeping the last-known-good one", "seq", rev.GetSeq(),
			"errors", len(errs), "first", errs[0].GetMessage())
		r.reject(rev, hash, errs)
		return
	}
	notReady := r.apply(ctx, signed, snap)
	if err := r.persist(signed); err != nil {
		r.o.Logger.Error("cannot store the last-known-good snapshot", "error", err)
	}
	r.o.Send(applied(rev, hash, notReady))
}

// newer reports whether rev may replace cur: a higher revision of the same database epoch, or any
// revision of a new epoch, provided the controller announced that epoch in Welcome.
func newer(rev, cur *agentv1.Revision, announced string) bool {
	if rev.GetDbEpoch() == cur.GetDbEpoch() {
		return rev.GetSeq() > cur.GetSeq()
	}
	return rev.GetDbEpoch() == announced
}

// verify checks the signature, the signer and the agent the snapshot is for.
func (r *Runtime) verify(signed *agentv1.Signed) (*agentv1.Snapshot, error) {
	r.mu.Lock()
	signers := r.signers
	r.mu.Unlock()
	return snapshot.VerifySnapshot(signed, signers, r.o.Identity.Root, r.o.Identity.SPIFFE(), r.o.Now())
}

// validate checks what every role relies on, each resource's ID and hash, and then lets the role
// check the rest.
func (r *Runtime) validate(snap *agentv1.Snapshot) []*agentv1.SnapshotError {
	var errs []*agentv1.SnapshotError
	seen := map[string]bool{}
	for _, res := range snap.GetResources() {
		h, err := snapshot.ResourceHash(res)
		switch {
		case res.GetId() == "":
			errs = append(errs, &agentv1.SnapshotError{Message: "a resource without an ID"})
		case seen[res.GetId()]:
			errs = append(errs, &agentv1.SnapshotError{ResourceId: res.GetId(), Message: "the resource ID appears twice"})
		case err != nil || !bytes.Equal(h, res.GetHash()):
			errs = append(errs, &agentv1.SnapshotError{ResourceId: res.GetId(), Message: "the resource hash does not match its content"})
		}
		seen[res.GetId()] = true
	}
	if len(errs) > 0 {
		return errs
	}
	return r.o.Applier.Validate(snap)
}

// apply hands the changes to the role and makes snap the running snapshot.
func (r *Runtime) apply(ctx context.Context, signed *agentv1.Signed, snap *agentv1.Snapshot) []*agentv1.ResourceStatus {
	next := &running{rev: snap.GetRevision(), hash: snapshot.Hash(signed), resources: map[string][]byte{}}
	for _, res := range snap.GetResources() {
		next.resources[res.GetId()] = res.GetHash()
	}
	r.mu.Lock()
	cur := r.cur
	r.mu.Unlock()
	var c Changes
	for _, res := range snap.GetResources() {
		switch old, ok := cur.resource(res.GetId()); {
		case !ok:
			c.Added = append(c.Added, res.GetId())
		case bytes.Equal(old, res.GetHash()):
			c.Unchanged = append(c.Unchanged, res.GetId())
		default:
			c.Changed = append(c.Changed, res.GetId())
		}
	}
	if cur != nil {
		for _, id := range slices.Sorted(maps.Keys(cur.resources)) {
			if _, ok := next.resources[id]; !ok {
				c.Removed = append(c.Removed, id)
			}
		}
	}
	notReady := r.o.Applier.Apply(ctx, snap, c)
	r.mu.Lock()
	r.cur = next
	r.mu.Unlock()
	if r.o.OnEndpoints != nil && len(snap.GetControllerEndpoints()) > 0 {
		r.o.OnEndpoints(snap.GetControllerEndpoints())
	}
	return notReady
}

func (cur *running) resource(id string) ([]byte, bool) {
	if cur == nil {
		return nil, false
	}
	h, ok := cur.resources[id]
	return h, ok
}

// persist stores the snapshot as it was signed, replacing the previous copy atomically.
func (r *Runtime) persist(signed *agentv1.Signed) error {
	b, err := proto.Marshal(signed)
	if err != nil {
		return err
	}
	path := filepath.Join(r.o.StateDir, LastKnownGoodFile)
	if err := writeAtomic(path, b, 0o600); err != nil {
		return err
	}
	return syncDir(r.o.StateDir)
}

func (r *Runtime) reject(rev *agentv1.Revision, hash []byte, errs []*agentv1.SnapshotError) {
	r.o.Send(&agentv1.AgentMessage{Msg: &agentv1.AgentMessage_Rejected{Rejected: &agentv1.Rejected{
		Revision: rev, Hash: hash, Errors: errs}}})
}

func applied(rev *agentv1.Revision, hash []byte, notReady []*agentv1.ResourceStatus) *agentv1.AgentMessage {
	return &agentv1.AgentMessage{Msg: &agentv1.AgentMessage_Applied{Applied: &agentv1.Applied{
		Revision: rev, Hash: hash, NotReady: notReady}}}
}

// syncDir makes a rename in dir durable.
func syncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // G304: the configured state directory
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
