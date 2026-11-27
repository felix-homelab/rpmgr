// SPDX-License-Identifier: Apache-2.0

package revlog

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/felix-homelab/rpmgr/internal/objstore"
)

// S3RequestTimeout bounds one request of the S3 sink (docs/03-connections.md, "Timeouts and
// limits"): a store that stalls holds a shipping round for seconds, and the next tick tries again.
const S3RequestTimeout = 10 * time.Second

// probeDir holds the objects of the start-up probe. It sorts after every key of an entry, and
// the backend never lists it as part of the sink.
const probeDir = "_probe/"

// ErrNoConditionalCreate is the answer for a store that does not refuse a second create with
// If-None-Match: *. It would overwrite an entry another replica wrote and leave gaps, so nothing
// is ever shipped to it (docs/04-security.md, "Revocation log"; VB-24).
var ErrNoConditionalCreate = errors.New("revlog: the store does not refuse a second create with If-None-Match: *")

// S3Backend is the Backend of an S3-compatible store: an object is a key under a prefix of one
// bucket, written with a conditional create. Its credentials need to put, get and list, and no
// delete or overwrite.
type S3Backend struct {
	client *objstore.Client
	prefix string // empty, or ends in a slash

	mu      sync.Mutex
	probed  bool
	refused error // the answer of a store that failed the probe, which is final
}

// NewS3Backend returns the backend over a client of the sink's bucket. prefix is the key prefix,
// empty for the bucket's root; a slash is added when it lacks one.
func NewS3Backend(c *objstore.Client, prefix string) *S3Backend {
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return &S3Backend{client: c, prefix: prefix}
}

// Probe checks that the store refuses a second create of a key with If-None-Match: *, by creating
// an object under _probe/ twice. Its objects stay, because a delete may be forbidden. It returns
// ErrNoConditionalCreate for a store that does not refuse: it overwrites, or does not know the
// header. Any other error says the store could not be asked, and the probe is repeated before
// the first create of an entry. A store that passed is not asked again.
func (b *S3Backend) Probe(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.probed {
		return nil
	}
	if b.refused != nil {
		return b.refused
	}
	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		return err
	}
	key := b.prefix + probeDir + hex.EncodeToString(id[:])
	put := objstore.PutOptions{IfNoneMatch: true}
	if _, err := b.client.Put(ctx, key, []byte("probe\n"), put); err != nil {
		return fmt.Errorf("probe of the store: %w", err)
	}
	_, err := b.client.Put(ctx, key, []byte("probe\n"), put)
	var oe *objstore.Error
	switch {
	case err == nil:
		b.refused = ErrNoConditionalCreate
		return b.refused
	case errors.Is(err, objstore.ErrExists):
		b.probed = true
		return nil
	case errors.As(err, &oe) && (oe.Status == http.StatusNotImplemented || oe.Status == http.StatusBadRequest):
		b.refused = fmt.Errorf("%w: the store answered %d", ErrNoConditionalCreate, oe.Status)
		return b.refused
	}
	return fmt.Errorf("probe of the store: %w", err)
}

// List returns the keys after the given key in ascending order, those of entries only.
func (b *S3Backend) List(after string) ([]string, error) {
	ctx := context.Background()
	start := ""
	if after != "" {
		start = b.prefix + after
	}
	var keys []string
	for token := ""; ; {
		page, err := b.client.ListAfter(ctx, b.prefix, start, token, 0)
		if err != nil {
			return nil, err
		}
		for _, o := range page.Objects {
			k := strings.TrimPrefix(o.Key, b.prefix)
			if !strings.HasPrefix(k, probeDir) {
				keys = append(keys, k)
			}
		}
		if page.Next == "" {
			return keys, nil
		}
		token = page.Next
	}
}

// Get returns the object at key.
func (b *S3Backend) Get(key string) ([]byte, error) {
	return b.client.Get(context.Background(), b.prefix+key)
}

// CreateIfAbsent writes data at key with If-None-Match: *, and returns ErrExists, without writing,
// when the key is taken (412). It writes nothing to a store that failed the probe.
func (b *S3Backend) CreateIfAbsent(key string, data []byte) error {
	ctx := context.Background()
	if err := b.Probe(ctx); err != nil {
		return err
	}
	_, err := b.client.Put(ctx, b.prefix+key, data, objstore.PutOptions{IfNoneMatch: true})
	if errors.Is(err, objstore.ErrExists) {
		return ErrExists
	}
	return err
}
