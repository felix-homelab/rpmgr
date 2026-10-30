// SPDX-License-Identifier: Apache-2.0

package auditsink

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/felix-homelab/rpmgr/internal/audit"
	"github.com/felix-homelab/rpmgr/internal/egress"
	"github.com/felix-homelab/rpmgr/internal/ids"
	"github.com/felix-homelab/rpmgr/internal/objstore"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
)

// The limits of the object-storage sink (docs/03-connections.md, "Timeouts, keepalive and
// backoff"; docs/04-security.md, "Audit log"): a whole batch is written within S3BatchTimeout and
// the check of a bucket within S3CheckTimeout. An object is locked for the sink's lock days,
// DefaultLockDays unless set, within the range.
const (
	S3BatchTimeout  = 60 * time.Second
	S3CheckTimeout  = 60 * time.Second
	DefaultLockDays = 365
	MinLockDays     = 30
	MaxLockDays     = 3650
	// s3Prefix is where the sink keeps its objects; the bucket may hold others.
	s3Prefix = "audit/"
	// probeLockDays is how long the object of the bucket check stays locked.
	probeLockDays = 1
)

// S3Settings are what an object-storage sink keeps besides its secret key (the settings of the
// row): where the bucket is, how to address it, and how long its objects are locked.
type S3Settings struct {
	Endpoint, Region, Bucket, AccessKeyID, CA string
	// LockDays is 0 for the default.
	LockDays int
}

// S3SettingsOf reads the settings of a row.
func S3SettingsOf(m map[string]string) S3Settings {
	days, _ := strconv.Atoi(m["lock_days"])
	return S3Settings{Endpoint: m["endpoint"], Region: m["region"], Bucket: m["bucket"], AccessKeyID: m["access_key_id"], CA: m["ca"], LockDays: days}
}

// Map is the settings as a row keeps them; empty values are left out.
func (s S3Settings) Map() map[string]string {
	m := map[string]string{"endpoint": s.Endpoint, "region": s.Region, "bucket": s.Bucket, "access_key_id": s.AccessKeyID}
	if s.CA != "" {
		m["ca"] = s.CA
	}
	if s.LockDays != 0 {
		m["lock_days"] = strconv.Itoa(s.LockDays)
	}
	return m
}

// Days is the lock period in days.
func (s S3Settings) Days() int {
	if s.LockDays == 0 {
		return DefaultLockDays
	}
	return s.LockDays
}

// client builds the client of the bucket, which never uses a proxy of the environment. The Instance Admin sets the endpoint, so it may reach
// private ranges and loopback; the egress guard still refuses link-local, metadata, multicast and
// broadcast addresses at dial time (D145, E5).
func (s S3Settings) client(key secret.Value, now func() time.Time) (*objstore.Client, error) {
	cfg := objstore.Config{Endpoint: s.Endpoint, Region: s.Region, Bucket: s.Bucket, Now: now,
		Credentials: objstore.Credentials{AccessKeyID: s.AccessKeyID, SecretAccessKey: key}, Control: egress.Policy{Internal: true}.Control,
		// No proxy: the guard sees only the address that is dialled, which a proxy would hide.
		Proxy: func(*http.Request) (*url.URL, error) { return nil, nil }}
	if s.CA != "" {
		roots, err := rootsOf(s.CA)
		if err != nil {
			return nil, fmt.Errorf("the object-storage sink's %w", err)
		}
		cfg.RootCAs = roots
	}
	return objstore.New(cfg)
}

// CheckS3Settings reports why settings and a secret key cannot be used by an object-storage sink,
// or nil. It does not reach the store.
func CheckS3Settings(s S3Settings, key string) error {
	if s.LockDays != 0 && (s.LockDays < MinLockDays || s.LockDays > MaxLockDays) {
		return fmt.Errorf("the lock period is from %d to %d days", MinLockDays, MaxLockDays)
	}
	c, err := s.client(secret.New(key), nil)
	if err != nil {
		return err
	}
	c.Close()
	return nil
}

// s3Sink writes each item as one object, with a conditional create into a bucket with Object Lock
// in compliance mode, so that not even this sink's credentials can change it before its lock
// ends. The store's answer to a write acknowledges the item.
type s3Sink struct {
	client   *objstore.Client
	lockDays int
	now      func() time.Time
	// batchTimeout bounds a whole batch; batchStart is when the batch in hand began, zero between
	// batches.
	batchTimeout time.Duration
	batchStart   time.Time
}

// errBatchTime is the failure of a batch that ran past its time: the items before it were
// acknowledged, the rest goes in the next pass.
var errBatchTime = errors.New("writing a batch to the object store took longer than the time allowed for a batch")

func openS3(o Options, s *ent.AuditSink) (Sink, error) {
	set := S3SettingsOf(s.Settings)
	if s.SecretEnc == nil || len(*s.SecretEnc) == 0 {
		return nil, errors.New("the object-storage sink has no secret key")
	}
	key, err := o.Sealer.Open(secret.Context{Table: "audit_sinks", Column: "secret_enc", RowID: s.ID}, *s.SecretEnc)
	if err != nil {
		return nil, errors.New("the object-storage sink's secret key cannot be opened")
	}
	c, err := set.client(key, o.Now)
	if err != nil {
		return nil, fmt.Errorf("the object-storage sink has unusable settings: %w", err)
	}
	return &s3Sink{client: c, lockDays: set.Days(), now: o.Now, batchTimeout: S3BatchTimeout}, nil
}

// s3Key is the key of a checkpoint or entry: the seq as 20 digits keeps a listing in order.
func s3Key(chain, kind string, seq int64) string {
	return fmt.Sprintf("%s%020d", s3Dir(chain, kind), seq)
}

// s3Dir is the prefix of a chain's checkpoints or entries.
func s3Dir(chain, kind string) string { return s3Prefix + chain + "/" + kind + "/" }

// Ship writes the item. A key that is taken holds the item already if it holds the same bytes.
func (k *s3Sink) Ship(ctx context.Context, it Item) error {
	var key string
	switch it.Type {
	case EventCheckpoint:
		key = s3Key(it.Chain, "checkpoints", it.Seq)
	case EventEntry:
		key = s3Key(it.Chain, "entries", it.Seq)
	default:
		return fmt.Errorf("an item of type %s has no place in an object store", it.Type)
	}
	if k.batchStart.IsZero() {
		k.batchStart = time.Now()
	}
	deadline := k.batchStart.Add(k.batchTimeout)
	if !time.Now().Before(deadline) {
		return errBatchTime
	}
	parent := ctx
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	_, err := k.client.Put(ctx, key, it.Body, objstore.PutOptions{IfNoneMatch: true, LockMode: "COMPLIANCE",
		RetainUntil: k.now().Add(time.Duration(k.lockDays) * 24 * time.Hour), ContentType: "application/json"})
	if errors.Is(err, objstore.ErrExists) {
		var held []byte
		if held, err = k.client.Get(ctx, key); err == nil {
			if bytes.Equal(held, it.Body) {
				return nil
			}
			return &PermanentError{Status: 412, Msg: "the object store holds other bytes under " + key +
				" than the item; the sink ships nothing more of that chain until that is looked into"}
		}
	}
	switch {
	case err == nil:
		return nil
	case parent.Err() == nil && errors.Is(ctx.Err(), context.DeadlineExceeded):
		return errBatchTime
	case objstore.Refused(err):
		var oe *objstore.Error
		_ = errors.As(err, &oe)
		return &PermanentError{Status: oe.Status, Err: err, Msg: "the object store refused an item (" + oe.Error() +
			"); the sink ships nothing more of that chain until the store accepts it"}
	}
	return s3Failure(err)
}

// Flush ends a batch, whose time starts again with the next.
func (k *s3Sink) Flush(context.Context) error {
	k.batchStart = time.Time{}
	return nil
}

// Close drops the client's idle connections.
func (k *s3Sink) Close() error {
	k.client.Close()
	return nil
}

// s3Failure names what failed without the store's address: the status of a sink is read by more
// than the Instance Admin.
func s3Failure(err error) error {
	var re *egress.RefusedError
	var oe *objstore.Error
	if errors.As(err, &re) || errors.As(err, &oe) {
		return err
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.New("the object store did not answer in time")
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Err != nil {
		err = op.Err
	}
	return fmt.Errorf("the object store could not be reached: %w", err)
}

// checkS3 is Test for an object-storage sink: it checks the bucket instead of writing an item that
// the lock would keep for the sink's whole lock period.
func (r *Runner) checkS3(ctx context.Context, s *ent.AuditSink) error {
	sink, err := r.open(s)
	if err != nil {
		return err
	}
	defer closeSink(sink)
	return CheckBucket(ctx, sink.(*s3Sink).client, r.o.Now())
}

// CheckSettingsAndBucket checks an object-storage sink's settings and then its bucket, as the API
// does before it saves the sink: the bucket must keep an object locked in compliance mode, answer
// a second conditional create with "exists", and refuse to delete the locked version.
func CheckSettingsAndBucket(ctx context.Context, s S3Settings, key string, now func() time.Time) error {
	if err := CheckS3Settings(s, key); err != nil {
		return err
	}
	c, err := s.client(secret.New(key), now)
	if err != nil {
		return err
	}
	defer c.Close()
	return CheckBucket(ctx, c, now())
}

// CheckBucket is the check of a bucket (docs/04-security.md, "Audit log"). A store that does not
// let the check finish is an *UnreachableError, apart from a bucket that is refused.
func CheckBucket(ctx context.Context, c *objstore.Client, now time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, S3CheckTimeout)
	defer cancel()
	key := s3Prefix + "probe/" + ids.New("prb")
	body := []byte("rpmgr audit sink check\n")
	o := objstore.PutOptions{IfNoneMatch: true, LockMode: "COMPLIANCE", RetainUntil: now.Add(probeLockDays * 24 * time.Hour), ContentType: "text/plain"}
	version, err := c.Put(ctx, key, body, o)
	if err != nil {
		return checkFailure("a write with Object Lock in compliance mode", err)
	}
	if version == "" {
		return errors.New("the bucket returned no version ID: it is not versioned, so it cannot hold locked objects")
	}
	_, err = c.Put(ctx, key, body, o)
	if err == nil {
		return errors.New("the store replaced an object under a conditional create: it does not support If-None-Match: *")
	}
	if !errors.Is(err, objstore.ErrExists) {
		return checkFailure("a second conditional write", err)
	}
	if err = c.Delete(ctx, key, version); err == nil {
		return errors.New("the store deleted a locked object: it does not enforce Object Lock")
	} else if !objstore.Refused(err) {
		return checkFailure("deleting a locked object", err)
	}
	return nil
}

func checkFailure(what string, err error) error {
	if objstore.Retryable(err) {
		return &UnreachableError{fmt.Errorf("the object store could not complete %s: %w", what, s3Failure(err))}
	}
	return fmt.Errorf("the object store refused %s: %w", what, err)
}

// UnreachableError is a check or a read-back that the store did not let finish: no connection,
// no answer in time, or an answer such as 5xx that a later try may not repeat. It is not a verdict
// on the bucket.
type UnreachableError struct{ Err error }

func (e *UnreachableError) Error() string { return e.Err.Error() }
func (e *UnreachableError) Unwrap() error { return e.Err }

// orgOfChain is the org ID of a chain's name, empty for the instance chain.
func orgOfChain(chain string) string {
	if chain == audit.InstanceChain {
		return ""
	}
	return chain
}
