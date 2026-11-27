// SPDX-License-Identifier: Apache-2.0

//go:build objstoreit

package objstore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func startStore(t *testing.T) string { return StartSilo(t) }

func makeBucket(t *testing.T, endpoint, name string, lock bool) { MakeBucket(t, endpoint, name, lock) }

func itCreds() Credentials { return SiloCredentials() }

func TestStore(t *testing.T) {
	endpoint := startStore(t)
	makeBucket(t, endpoint, "plain", false)
	makeBucket(t, endpoint, "locked", true)
	open := func(bucket string) *Client {
		c, err := New(Config{Endpoint: endpoint, Region: "us-east-1", Bucket: bucket, Credentials: itCreds()})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	ctx := context.Background()

	t.Run("conditional create race", func(t *testing.T) {
		c := open("plain")
		for round := 0; round < 20; round++ {
			key := fmt.Sprintf("race/%04d", round)
			var wg sync.WaitGroup
			errs := make([]error, 2)
			for i := range errs {
				wg.Add(1)
				go func() {
					defer wg.Done()
					errs[i] = put(ctx, c, key, []byte{byte('a' + i)}, PutOptions{IfNoneMatch: true})
				}()
			}
			wg.Wait()
			wins := 0
			for _, e := range errs {
				switch {
				case e == nil:
					wins++
				case errors.Is(e, ErrExists), Retryable(e): // 412, or 409 while the other write is in flight
				default:
					t.Fatalf("round %d: %v", round, e)
				}
			}
			if wins != 1 {
				t.Fatalf("round %d: %d winners, want 1 (%v)", round, wins, errs)
			}
		}
		if err := put(ctx, c, "race/0000", []byte("again"), PutOptions{IfNoneMatch: true}); !errors.Is(err, ErrExists) {
			t.Errorf("create of a taken key: %v", err)
		}
	})

	t.Run("get and list", func(t *testing.T) {
		c := open("plain")
		for i := 0; i < 5; i++ {
			if err := put(ctx, c, fmt.Sprintf("list/%02d", i), []byte("v"), PutOptions{}); err != nil {
				t.Fatal(err)
			}
		}
		var keys []string
		for tok := ""; ; {
			p, err := c.List(ctx, "list/", tok, 2)
			if err != nil {
				t.Fatal(err)
			}
			for _, o := range p.Objects {
				keys = append(keys, o.Key)
			}
			if tok = p.Next; tok == "" {
				break
			}
		}
		if len(keys) != 5 || keys[0] != "list/00" || keys[4] != "list/04" {
			t.Errorf("keys %v", keys)
		}
		if b, err := c.Get(ctx, "list/03"); err != nil || string(b) != "v" {
			t.Errorf("get: %q, %v", b, err)
		}
		if _, err := c.Get(ctx, "list/none"); !errors.Is(err, ErrNotFound) {
			t.Errorf("missing: %v", err)
		}
	})

	t.Run("object lock", func(t *testing.T) {
		c := open("locked")
		until := time.Now().Add(time.Hour)
		version, err := c.Put(ctx, "chain/0001", []byte("cp"), PutOptions{IfNoneMatch: true, LockMode: "COMPLIANCE", RetainUntil: until})
		if err != nil || version == "" {
			t.Fatalf("locked put: version %q, %v", version, err)
		}
		// A bucket without Object Lock refuses a PUT that asks for it, with a 4xx.
		err = put(ctx, open("plain"), "chain/0001", []byte("cp"), PutOptions{LockMode: "COMPLIANCE", RetainUntil: until})
		if !Refused(err) {
			t.Errorf("lock in a bucket without Object Lock: %v", err)
		}
		// Deleting the locked object is refused too: any 4xx (AWS 403, SILO 400).
		if err := c.Delete(ctx, "chain/0001", version); !Refused(err) {
			t.Errorf("delete of a locked version: %v", err)
		}
		if b, err := c.Get(ctx, "chain/0001"); err != nil || string(b) != "cp" {
			t.Errorf("locked object after the delete: %q, %v", b, err)
		}
	})

	t.Run("wrong secret", func(t *testing.T) {
		c, _ := New(Config{Endpoint: endpoint, Region: "us-east-1", Bucket: "plain", Credentials: creds("itadmin", "wrong-password-1")})
		err := put(ctx, c, "k", nil, PutOptions{})
		if !Refused(err) || strings.Contains(err.Error(), "wrong-password") {
			t.Errorf("wrong secret: %v", err)
		}
	})

	t.Run("store down", func(t *testing.T) {
		c, _ := New(Config{Endpoint: "http://127.0.0.1:1", Region: "us-east-1", Bucket: "plain", Credentials: itCreds()})
		if err := put(ctx, c, "k", nil, PutOptions{}); !Retryable(err) {
			t.Errorf("down: %v", err)
		}
	})
}
