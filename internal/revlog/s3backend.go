// SPDX-License-Identifier: Apache-2.0

package revlog

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/felix-homelab/rpmgr/internal/objstore"
)

// MaxListPages is how many pages of a listing the backend reads before it gives up: a store that
// answers with the same continuation token for ever must not hold a shipping round
// (docs/03-connections.md, "Timeouts and limits").
const MaxListPages = 10000

var maxListPages = MaxListPages // a variable for tests

// S3RequestTimeout bounds one request of the S3 sink (docs/03-connections.md, "Timeouts and
// limits"): a store that stalls holds a shipping round for seconds, and the next tick tries again.
const S3RequestTimeout = 10 * time.Second

// probeKey is the one object of the start-up probe, under a directory that sorts after every key
// of an entry. Every start uses it, so probes do not pile up in the listing.
const probeKey = "_probe/conditional-create"

// ErrNoConditionalCreate is the answer for a store that does not refuse a second create with
// If-None-Match: *. It would overwrite an entry another replica wrote and leave gaps, so nothing
// is ever shipped to it (docs/04-security.md, "Revocation log"; VB-24).
var ErrNoConditionalCreate = errors.New("revlog: the store does not refuse a second create with If-None-Match: *")

// ErrListing is the answer for a listing that does not end or does not run in key order.
var ErrListing = errors.New("revlog: the store's listing does not end or is out of order")

// S3Backend is the Backend of an S3-compatible store: an object is a key under a prefix of one
// bucket, written with a conditional create. Its credentials need to put, get and list, and no
// delete. The store, not this code, keeps the credentials from overwriting: use Object Lock
// (LockDays) where the credentials may overwrite.
type S3Backend struct {
	// LockDays, when above zero, locks each entry in COMPLIANCE mode for that many days; the
	// bucket must have Object Lock enabled.
	LockDays int
	// Now is the clock of the lock; nil means time.Now.
	Now func() time.Time

	ctx    context.Context
	client *objstore.Client
	prefix string // empty, or ends in a slash

	mu      sync.Mutex
	probed  bool
	refused error // the answer of a store that failed the probe, which is final
}

// NewS3Backend returns the backend over a client of the sink's bucket. prefix is the key prefix;
// a slash is added when it lacks one. Requests end with ctx, as well as with their own timeout.
func NewS3Backend(ctx context.Context, c *objstore.Client, prefix string) *S3Backend {
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return &S3Backend{ctx: ctx, client: c, prefix: prefix}
}

// refusesHeader reports whether the store answered a conditional create in a way that says it does
// not know the header.
func refusesHeader(err error) bool {
	var oe *objstore.Error
	return errors.As(err, &oe) && (oe.Status == http.StatusNotImplemented || oe.Status == http.StatusBadRequest)
}

// Probe checks that the store refuses a second create of a key with If-None-Match: *: it creates
// the object _probe/conditional-create, which stays because a delete may be forbidden, and creates
// it again. A 412 on the first create already proves it, since an earlier start made the object.
// It returns ErrNoConditionalCreate for a store that does not refuse: it overwrites, or answers 400
// or 501 to the header. Any other error says the store could not be asked, and the probe is
// repeated before the first create of an entry. A store that passed is not asked again.
func (b *S3Backend) Probe(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.probed {
		return nil
	}
	if b.refused != nil {
		return b.refused
	}
	key := b.prefix + probeKey
	put := objstore.PutOptions{IfNoneMatch: true}
	for attempt := 0; attempt < 2; attempt++ {
		_, err := b.client.Put(ctx, key, []byte("probe\n"), put)
		switch {
		case errors.Is(err, objstore.ErrExists):
			b.probed = true
			return nil
		case err == nil:
			continue // created; the second create must be refused
		case refusesHeader(err):
			var oe *objstore.Error
			_ = errors.As(err, &oe)
			b.refused = fmt.Errorf("%w: the store answered %d", ErrNoConditionalCreate, oe.Status)
			return b.refused
		}
		return fmt.Errorf("probe of the store: %w", err)
	}
	b.refused = ErrNoConditionalCreate
	return b.refused
}

// List returns the keys after the given key in ascending order, those of entries only. It fails
// on a listing that repeats a continuation token, runs out of order or has more than MaxListPages.
func (b *S3Backend) List(after string) ([]string, error) {
	start := ""
	if after != "" {
		start = b.prefix + after
	}
	var keys []string
	last := start
	seen := map[string]bool{}
	for token, pages := "", 0; ; pages++ {
		if pages >= maxListPages {
			return nil, fmt.Errorf("%w: more than %d pages", ErrListing, MaxListPages)
		}
		page, err := b.client.ListAfter(b.ctx, b.prefix, start, token, 0)
		if err != nil {
			return nil, err
		}
		for _, o := range page.Objects {
			if o.Key <= last {
				return nil, fmt.Errorf("%w: key %q follows %q", ErrListing, o.Key, last)
			}
			last = o.Key
			k := strings.TrimPrefix(o.Key, b.prefix)
			if !strings.HasPrefix(k, "_probe/") {
				keys = append(keys, k)
			}
		}
		if page.Next == "" {
			return keys, nil
		}
		if seen[page.Next] {
			return nil, fmt.Errorf("%w: the token repeats", ErrListing)
		}
		seen[page.Next] = true
		token = page.Next
	}
}

// Get returns the object at key.
func (b *S3Backend) Get(key string) ([]byte, error) {
	return b.client.Get(b.ctx, b.prefix+key)
}

// CreateIfAbsent writes data at key with If-None-Match: *, and returns ErrExists, without writing,
// when the key is taken (412). It writes nothing to a store that failed the probe.
func (b *S3Backend) CreateIfAbsent(key string, data []byte) error {
	if err := b.Probe(b.ctx); err != nil {
		return err
	}
	o := objstore.PutOptions{IfNoneMatch: true}
	if b.LockDays > 0 {
		now := time.Now
		if b.Now != nil {
			now = b.Now
		}
		o.LockMode, o.RetainUntil = "COMPLIANCE", now().Add(time.Duration(b.LockDays)*24*time.Hour)
	}
	_, err := b.client.Put(b.ctx, b.prefix+key, data, o)
	if errors.Is(err, objstore.ErrExists) {
		return ErrExists
	}
	return err
}
