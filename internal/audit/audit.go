// SPDX-License-Identifier: Apache-2.0

// Package audit appends to and verifies the hash-chained audit log (docs/04-security.md, "Audit
// log"). Every org has its own chain, and instance-level events (system scopes, local
// administration, instance settings) have the instance chain. Each entry's hash covers the hash
// before it and the entry's canonical encoding, and the chain's head row holds the last seq and
// hash, so a modified, deleted, reordered or moved entry and a deleted tail are all detected.
//
// The hashes alone do not stop an attacker with write access to the database, who can recompute
// a chain; signed checkpoints outside the database do (docs/04-security.md).
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// ActorType says who acted.
type ActorType string

// Actor types. Local administration on the controller host is a system actor named "local-cli".
const (
	ActorUser      ActorType = "user"
	ActorAgent     ActorType = "agent"
	ActorSystem    ActorType = "system"
	ActorAnonymous ActorType = "anonymous"
)

// Result is the outcome of the recorded action.
type Result string

// Results.
const (
	Success Result = "success"
	Failure Result = "failure"
	Denied  Result = "denied"
)

// InstanceChain names the chain of instance-level events, whose entries have no org.
const InstanceChain = "instance"

// Caps on fields a client controls (docs/06-data-model.md, "System"). Longer values are
// truncated, never refused: an over-long header must not keep an event out of the log.
const (
	MaxUserAgent = 512
	MaxRequestID = 128
)

// Entry is one audit entry. The caller fills in who did what; Append sets ID, Seq, PrevHash, Hash
// and Time.
type Entry struct {
	ID       string
	OrgID    string // empty: the instance chain
	Seq      int64
	PrevHash []byte
	Hash     []byte
	Time     time.Time

	ActorType    ActorType
	ActorID      string // user, agent or job; empty only for an anonymous actor
	CredentialID string // the session or token ID, never the secret
	AuthMethod   string
	IP           string
	UserAgent    string
	RequestID    string
	Action       string
	TargetType   string
	TargetID     string
	Result       Result
	Diff         string // the redacted before/after
	Reason       string
}

// Chain returns the chain the entry belongs to: its org ID, or InstanceChain.
func (e Entry) Chain() string { return chainOf(e.OrgID) }

func chainOf(orgID string) string {
	if orgID == "" {
		return InstanceChain
	}
	return orgID
}

// Head is the state of a chain: the seq and hash of its last entry. An empty chain has seq 0 and
// the chain's genesis hash.
type Head struct {
	Chain string
	Seq   int64
	Hash  []byte
}

var (
	// ErrOutsideScope is returned when an org scope appends to or verifies another org's chain.
	ErrOutsideScope = errors.New("audit: chain outside the scope's org")
	// ErrBroken is wrapped by every *ChainError.
	ErrBroken = errors.New("audit: chain is broken")
)

// ChainError reports where verification found a chain broken.
type ChainError struct {
	Chain   string
	Seq     int64
	Problem string
}

func (e *ChainError) Error() string {
	return fmt.Sprintf("audit: chain %s is broken at entry %d: %s", e.Chain, e.Seq, e.Problem)
}

// Unwrap returns ErrBroken.
func (e *ChainError) Unwrap() error { return ErrBroken }

// Append appends e to its chain inside tx, the transaction of the change it records, so the change
// and its entry commit or roll back together. It increments the chain's head with a row lock
// first, which serialises concurrent appends to one chain.
//
// An org scope may append to its own org's chain and to the instance chain, which records
// instance-level effects of an org request. Without a scope any chain is allowed: events such as a
// failed login or the grant of a system scope happen before there is one. On SQLite, Append must
// run in the transaction the caller already holds, never in a second one (one writer).
func Append(ctx context.Context, tx *ent.Tx, e Entry) (Entry, error) {
	if s, ok := authz.FromContext(ctx); ok && !s.System() && e.OrgID != "" && e.OrgID != s.OrgID() {
		return Entry{}, ErrOutsideScope
	}
	if err := e.validate(); err != nil {
		return Entry{}, err
	}
	e.clean()
	e.ID = ids.New("aud")
	e.Time = time.Now().UTC().Truncate(time.Microsecond) // the precision both dialects store
	chain := e.Chain()

	seq, prev, err := lockHead(ctx, tx, chain)
	if err != nil {
		return Entry{}, err
	}
	e.Seq, e.PrevHash = seq, prev
	e.Hash = chainHash(prev, e)
	if _, err := tx.ExecContext(ctx, "UPDATE audit_heads SET hash = $1 WHERE chain = $2", e.Hash, chain); err != nil {
		return Entry{}, fmt.Errorf("audit: head of %s: %w", chain, err)
	}
	var org any
	if e.OrgID != "" {
		org = e.OrgID
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_log (id, org_id, seq, prev_hash, hash, ts,
		actor_type, actor_id, credential_id, auth_method, ip, user_agent, request_id, action,
		target_type, target_id, result, diff, reason)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)`,
		e.ID, org, e.Seq, e.PrevHash, e.Hash, e.Time, string(e.ActorType), e.ActorID, e.CredentialID,
		e.AuthMethod, e.IP, e.UserAgent, e.RequestID, e.Action, e.TargetType, e.TargetID,
		string(e.Result), e.Diff, e.Reason)
	if err != nil {
		return Entry{}, fmt.Errorf("audit: append to %s: %w", chain, err)
	}
	return e, nil
}

// lockHead increments the chain's head and returns the new seq and the hash before it. A chain's
// first append creates the head; a concurrent first append waits for that insert, then finds it.
func lockHead(ctx context.Context, tx *ent.Tx, chain string) (int64, []byte, error) {
	for attempt := 0; attempt < 2; attempt++ {
		rows, err := tx.QueryContext(ctx,
			"UPDATE audit_heads SET seq = seq + 1 WHERE chain = $1 RETURNING seq, hash", chain)
		if err != nil {
			return 0, nil, fmt.Errorf("audit: head of %s: %w", chain, err)
		}
		var seq int64
		var hash []byte
		found, err := scanFirst(rows, &seq, &hash)
		if err != nil {
			return 0, nil, fmt.Errorf("audit: head of %s: %w", chain, err)
		}
		if found {
			return seq, hash, nil
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO audit_heads (chain, seq, hash) VALUES ($1, 0, $2) "+
			"ON CONFLICT (chain) DO NOTHING", chain, genesis(chain)); err != nil {
			return 0, nil, fmt.Errorf("audit: create the head of %s: %w", chain, err)
		}
	}
	return 0, nil, fmt.Errorf("audit: the head of %s cannot be created", chain)
}

// Record appends e in a transaction of its own, for events that change nothing else: a failed
// login, the grant of a system scope. On SQLite it must not be called while the same goroutine
// holds a write transaction; use Append with that transaction instead.
func Record(ctx context.Context, db *store.DB, e Entry) (Entry, error) {
	var out Entry
	ctx = store.WithoutTxHook(ctx) // a request's own entry belongs to the change it makes, not here
	err := store.WriteTx(ctx, db, func(tx *ent.Tx) error {
		var err error
		out, err = Append(ctx, tx, e)
		return err
	})
	return out, err
}

// SystemScopes returns the authz.AuditFunc that records every grant of a system scope in the
// instance chain, in a transaction of its own: if the record fails, authz.System refuses the scope.
// Like Record, it must not be called inside a write transaction on SQLite.
func SystemScopes(db *store.DB) authz.AuditFunc {
	return func(ctx context.Context, job, reason string) error {
		_, err := Record(ctx, db, Entry{
			ActorType: ActorSystem,
			ActorID:   job,
			Action:    "system_scope.grant",
			Result:    Success,
			Reason:    reason,
		})
		return err
	}
}

// Verify walks the chain of orgID, or the instance chain for an empty orgID, in one read snapshot
// and returns its head. A broken chain returns a *ChainError at the first entry that does not fit.
// An org scope verifies only its own org's chain; the instance chain needs the system scope.
func Verify(ctx context.Context, db *store.DB, orgID string) (Head, error) {
	s, ok := authz.FromContext(ctx)
	if !ok {
		return Head{}, errors.New("audit: verification needs a scope")
	}
	if !s.System() && (orgID == "" || orgID != s.OrgID()) {
		return Head{}, ErrOutsideScope
	}
	var head Head
	err := store.ReadTx(ctx, db, func(tx *ent.Tx, _ store.Revision) error {
		var err error
		head, err = verify(ctx, tx, orgID)
		return err
	})
	return head, err
}

func verify(ctx context.Context, tx *ent.Tx, orgID string) (Head, error) {
	chain := chainOf(orgID)
	q, args := "SELECT "+entryColumns+" FROM audit_log WHERE org_id IS NULL ORDER BY seq", []any(nil)
	if orgID != "" {
		q, args = "SELECT "+entryColumns+" FROM audit_log WHERE org_id = $1 ORDER BY seq", []any{orgID}
	}
	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return Head{}, err
	}
	defer func() { _ = rows.Close() }()
	h := Head{Chain: chain, Hash: genesis(chain)}
	for rows.Next() {
		e, err := scanEntry(rows)
		if err != nil {
			return Head{}, err
		}
		e.OrgID = orgID
		switch want := h.Seq + 1; {
		case e.Seq > want:
			return Head{}, &ChainError{chain, want, "the entry is missing"}
		case e.Seq < want:
			return Head{}, &ChainError{chain, e.Seq, "the entry is out of order"}
		case !bytes.Equal(e.PrevHash, h.Hash):
			return Head{}, &ChainError{chain, e.Seq, "prev_hash is not the hash of the entry before"}
		case !bytes.Equal(chainHash(h.Hash, e), e.Hash):
			return Head{}, &ChainError{chain, e.Seq, "the hash does not match the entry"}
		}
		h.Seq, h.Hash = e.Seq, e.Hash
	}
	if err := rows.Err(); err != nil {
		return Head{}, err
	}
	if err := rows.Close(); err != nil {
		return Head{}, err
	}
	hr, err := tx.QueryContext(ctx, "SELECT seq, hash FROM audit_heads WHERE chain = $1", chain)
	if err != nil {
		return Head{}, err
	}
	var seq int64
	var hash []byte
	found, err := scanFirst(hr, &seq, &hash)
	switch {
	case err != nil:
		return Head{}, err
	case !found && h.Seq == 0:
		return h, nil // no entry yet
	case !found:
		return Head{}, &ChainError{chain, h.Seq, "the chain has no head"}
	case seq != h.Seq || !bytes.Equal(hash, h.Hash):
		return Head{}, &ChainError{chain, seq, fmt.Sprintf("the head does not match the last entry (%d)", h.Seq)}
	}
	return h, nil
}

const entryColumns = `id, seq, prev_hash, hash, ts, actor_type, actor_id, credential_id, auth_method,
	ip, user_agent, request_id, action, target_type, target_id, result, diff, reason`

func scanEntry(rows *sql.Rows) (Entry, error) {
	var e Entry
	var actor, result string
	err := rows.Scan(&e.ID, &e.Seq, &e.PrevHash, &e.Hash, &e.Time, &actor, &e.ActorID,
		&e.CredentialID, &e.AuthMethod, &e.IP, &e.UserAgent, &e.RequestID, &e.Action, &e.TargetType,
		&e.TargetID, &result, &e.Diff, &e.Reason)
	e.ActorType, e.Result = ActorType(actor), Result(result)
	return e, err
}

// scanFirst scans the first row, if there is one, and closes rows.
func scanFirst(rows *sql.Rows, dst ...any) (bool, error) {
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		return false, rows.Err()
	}
	if err := rows.Scan(dst...); err != nil {
		return false, err
	}
	return true, rows.Close()
}

func (e *Entry) validate() error {
	switch e.ActorType {
	case ActorUser, ActorAgent, ActorSystem:
		if e.ActorID == "" {
			return fmt.Errorf("audit: a %s actor needs an ID", e.ActorType)
		}
	case ActorAnonymous:
	default:
		return fmt.Errorf("audit: unknown actor type %q", e.ActorType)
	}
	switch e.Result {
	case Success, Failure, Denied:
	default:
		return fmt.Errorf("audit: unknown result %q", e.Result)
	}
	if e.Action == "" {
		return errors.New("audit: an entry needs an action")
	}
	if e.OrgID != "" && !ids.Valid("org", e.OrgID) {
		return fmt.Errorf("audit: %q is not an org ID", e.OrgID)
	}
	return nil
}

// clean makes every text field storable on both dialects (valid UTF-8 without NUL, which
// PostgreSQL refuses) and caps the fields a client controls.
func (e *Entry) clean() {
	for _, f := range []*string{&e.ActorID, &e.CredentialID, &e.AuthMethod, &e.IP, &e.UserAgent,
		&e.RequestID, &e.Action, &e.TargetType, &e.TargetID, &e.Diff, &e.Reason} {
		*f = strings.ReplaceAll(strings.ToValidUTF8(*f, "\uFFFD"), "\x00", "\uFFFD")
	}
	e.UserAgent = truncate(e.UserAgent, MaxUserAgent)
	e.RequestID = truncate(e.RequestID, MaxRequestID)
}

// truncate cuts s to at most n bytes without splitting a character.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// genesis is the hash before a chain's first entry; it names the chain, so a chain's first entry
// does not verify as the first entry of another.
func genesis(chain string) []byte {
	h := sha256.Sum256(lengthPrefixed([]byte("rpmgr-audit-v1/genesis"), chain))
	return h[:]
}

// chainHash is SHA-256(prev ‖ canonical entry).
func chainHash(prev []byte, e Entry) []byte {
	h := sha256.New()
	h.Write(prev)
	h.Write(canonical(e))
	return h.Sum(nil)
}

// canonical is the entry's canonical encoding: a version label, seq and time (microseconds since
// the epoch) as signed varints, then every text field in a fixed order with a length prefix, so no
// two different entries encode to the same bytes.
func canonical(e Entry) []byte {
	b := []byte("rpmgr-audit-v1/entry")
	b = binary.AppendVarint(b, e.Seq)
	b = binary.AppendVarint(b, e.Time.UnixMicro())
	return lengthPrefixed(b, e.ID, e.Chain(), string(e.ActorType), e.ActorID, e.CredentialID,
		e.AuthMethod, e.IP, e.UserAgent, e.RequestID, e.Action, e.TargetType, e.TargetID,
		string(e.Result), e.Diff, e.Reason)
}

func lengthPrefixed(b []byte, fields ...string) []byte {
	for _, f := range fields {
		b = binary.AppendUvarint(b, uint64(len(f)))
		b = append(b, f...)
	}
	return b
}
