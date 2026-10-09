// SPDX-License-Identifier: Apache-2.0

package password_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/password"
)

// cheap are test parameters that hash fast.
var cheap = password.Params{Time: 1, MemoryKiB: 8, Threads: 1}

// TestCheckLength: 12 to 256 characters, counted as characters, not bytes; no composition rules.
func TestCheckLength(t *testing.T) {
	for pw, ok := range map[string]bool{
		strings.Repeat("a", 11): false, strings.Repeat("a", 12): true, strings.Repeat("a", 256): true,
		strings.Repeat("a", 257): false, strings.Repeat("ä", 12): true, strings.Repeat("ä", 11): false,
		strings.Repeat("ä", 256): true, "": false, "\xff" + strings.Repeat("a", 12): false,
	} {
		if err := password.CheckLength(pw); (err == nil) != ok {
			t.Errorf("%d bytes, %q…: %v", len(pw), pw[:min(len(pw), 4)], err)
		}
	}
	if _, err := password.Hash(context.Background(), "short", cheap); !errors.Is(err, password.ErrLength) {
		t.Errorf("a short password was hashed: %v", err)
	}
}

// TestHashVerify: a hash verifies its password only, in PHC format with a fresh salt; it asks
// for a rehash when the wanted parameters differ, and only with the right password.
func TestHashVerify(t *testing.T) {
	ctx := context.Background()
	pw := "correct horse battery"
	h, err := password.Hash(ctx, pw, cheap)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=8,t=1,p=1$") {
		t.Fatalf("format: %s", h)
	}
	if again, _ := password.Hash(ctx, pw, cheap); again == h {
		t.Fatal("the same salt twice")
	}
	if ok, rehash, err := password.Verify(ctx, pw, h, cheap); !ok || rehash || err != nil {
		t.Fatalf("the right password: %v %v %v", ok, rehash, err)
	}
	if ok, rehash, err := password.Verify(ctx, pw+"x", h, cheap); ok || rehash || err != nil {
		t.Fatalf("a wrong password: %v %v %v", ok, rehash, err)
	}
	stronger := password.Params{Time: 2, MemoryKiB: 8, Threads: 1}
	if ok, rehash, _ := password.Verify(ctx, pw, h, stronger); !ok || !rehash {
		t.Fatal("no rehash for other parameters")
	}
	if ok, rehash, _ := password.Verify(ctx, "wrong password!", h, stronger); ok || rehash {
		t.Fatal("a rehash for a wrong password")
	}
	if password.ParamsOf(rpmgrv1.PasswordHashProfile_PASSWORD_HASH_PROFILE_LOW_MEMORY) != password.LowMemory ||
		password.ParamsOf(rpmgrv1.PasswordHashProfile_PASSWORD_HASH_PROFILE_DEFAULT) != password.Default ||
		password.ParamsOf(rpmgrv1.PasswordHashProfile_PASSWORD_HASH_PROFILE_UNSPECIFIED) != password.Default {
		t.Fatal("profiles")
	}
	if password.Default != (password.Params{Time: 3, MemoryKiB: 65536, Threads: 4}) ||
		password.LowMemory != (password.Params{Time: 2, MemoryKiB: 19456, Threads: 1}) {
		t.Fatal("the profiles of docs/04")
	}
}

// TestVerify_UnknownUser: a user without a hash costs one hash with the wanted parameters and
// never matches.
func TestVerify_UnknownUser(t *testing.T) {
	var calls atomic.Int64
	var got password.Params
	password.SetIDKey(t, func(pw, salt []byte, time, memory uint32, threads uint8, n uint32) []byte {
		calls.Add(1)
		got = password.Params{Time: time, MemoryKiB: memory, Threads: threads}
		return argon2.IDKey(pw, salt, 1, 8, 1, n)
	})
	if ok, rehash, err := password.Verify(context.Background(), "any password at all", "", password.Default); ok || rehash || err != nil {
		t.Fatalf("%v %v %v", ok, rehash, err)
	}
	if calls.Load() != 1 || got != password.Default {
		t.Fatalf("%d hashes with %+v", calls.Load(), got)
	}
}

// TestConcurrency: at most four hashes run at once; a caller whose context ends while it waits
// gets the context's error.
func TestConcurrency(t *testing.T) {
	var running, peak atomic.Int64
	release := make(chan struct{})
	password.SetIDKey(t, func(pw, salt []byte, time, memory uint32, threads uint8, n uint32) []byte {
		if r := running.Add(1); r > peak.Load() {
			peak.Store(r)
		}
		<-release
		running.Add(-1)
		return make([]byte, n)
	})
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() { _, _, _ = password.Verify(context.Background(), "a long enough password", "", cheap) })
	}
	time.Sleep(200 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, _, err := password.Verify(ctx, "a long enough password", "", cheap)
	close(release)
	wg.Wait()
	if peak.Load() != password.Concurrency || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("peak %d, waiting caller: %v", peak.Load(), err)
	}
}

// TestVerify_Refusals: stored hashes of another algorithm or version, outside the parameter
// limits or malformed are errors, never a match.
func TestVerify_Refusals(t *testing.T) {
	salt, tag := "c2FsdHNhbHRzYWx0", "dGFndGFndGFndGFndGFndGFndGFndGFn"
	for name, h := range map[string]string{
		"argon2i":         "$argon2i$v=19$m=8,t=1,p=1$" + salt + "$" + tag,
		"version 16":      "$argon2id$v=16$m=8,t=1,p=1$" + salt + "$" + tag,
		"memory too high": "$argon2id$v=19$m=262145,t=1,p=1$" + salt + "$" + tag,
		"memory too low":  "$argon2id$v=19$m=7,t=1,p=1$" + salt + "$" + tag,
		"no passes":       "$argon2id$v=19$m=8,t=0,p=1$" + salt + "$" + tag,
		"many passes":     "$argon2id$v=19$m=8,t=11,p=1$" + salt + "$" + tag,
		"many threads":    "$argon2id$v=19$m=8,t=1,p=17$" + salt + "$" + tag,
		"no threads":      "$argon2id$v=19$m=8,t=1,p=0$" + salt + "$" + tag,
		"twice":           "$argon2id$v=19$m=8,t=1,t=1$" + salt + "$" + tag,
		"missing":         "$argon2id$v=19$m=8,t=1$" + salt + "$" + tag,
		"unknown":         "$argon2id$v=19$m=8,t=1,p=1,x=1$" + salt + "$" + tag,
		"short salt":      "$argon2id$v=19$m=8,t=1,p=1$c2FsdA$" + tag,
		"short tag":       "$argon2id$v=19$m=8,t=1,p=1$" + salt + "$dGFn",
		"long tag":        "$argon2id$v=19$m=8,t=1,p=1$" + salt + "$" + strings.Repeat("dGFn", 30),
		"bad base64":      "$argon2id$v=19$m=8,t=1,p=1$" + salt + "$***",
		"parts":           "$argon2id$v=19$m=8,t=1,p=1$" + salt,
		"plain":           "hunter2",
	} {
		if ok, _, err := password.Verify(context.Background(), "a long enough password", h, cheap); ok || err == nil {
			t.Errorf("%s: %v %v", name, ok, err)
		}
	}
}

// FuzzVerify: no stored hash makes Verify panic or match a password it was not made from.
func FuzzVerify(f *testing.F) {
	f.Add("$argon2id$v=19$m=8,t=1,p=1$c2FsdHNhbHRzYWx0$dGFndGFndGFndGFndGFndGFndGFndGFn")
	f.Add("")
	f.Add("$$$$$")
	f.Fuzz(func(t *testing.T, h string) {
		if strings.Contains(h, "m=") && !strings.Contains(h, "m=8,") {
			return // keep each run cheap
		}
		if ok, _, _ := password.Verify(context.Background(), "a long enough password", h, cheap); ok {
			t.Fatalf("matched %q", h)
		}
	})
}
