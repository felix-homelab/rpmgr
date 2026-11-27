// SPDX-License-Identifier: Apache-2.0

//go:build objstoreit

package objstore

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// startStore builds test/objstore, runs the store on a loopback port and returns its endpoint.
func startStore(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs("../../test/objstore")
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("docker", "build", "-q", dir).CombinedOutput()
	if err != nil {
		t.Fatalf("docker build: %v\n%s", err, out)
	}
	image := strings.TrimSpace(string(out))
	out, err = exec.Command("docker", "run", "-d", "--rm", "-p", "127.0.0.1::9000",
		"-e", "MINIO_ROOT_USER=itadmin", "-e", "MINIO_ROOT_PASSWORD=it-password-1234",
		image, "server", "/data").CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	id := strings.TrimSpace(string(out))
	t.Cleanup(func() { _ = exec.Command("docker", "stop", "-t", "1", id).Run() })
	out, err = exec.Command("docker", "port", id, "9000/tcp").Output()
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "http://" + strings.Fields(string(out))[0]
	for i := 0; i < 60; i++ {
		if resp, err := http.Get(endpoint + "/minio/health/live"); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				return endpoint
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("the store did not become ready")
	return ""
}

// makeBucket creates a bucket, with Object Lock when lock is set, through the client's signer.
func makeBucket(t *testing.T, endpoint, name string, lock bool) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPut, endpoint+"/"+name, nil)
	if lock {
		req.Header.Set("X-Amz-Bucket-Object-Lock-Enabled", "true")
	}
	sign(req, emptyHash, itCreds(), "us-east-1", time.Now())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("create bucket %s: %s", name, resp.Status)
	}
}

func itCreds() Credentials { return creds("itadmin", "it-password-1234") }

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
