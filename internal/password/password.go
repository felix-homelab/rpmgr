// SPDX-License-Identifier: Apache-2.0

// Package password hashes and verifies passwords with argon2id in PHC string format
// (docs/04-security.md, "Human authentication and sessions"). At most four hashes run at once,
// to bound memory; a verification of an unknown user costs one hash like any other, so timing
// tells nothing about which accounts exist.
package password

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
)

// Length limits of a password, in characters; there are no composition rules.
const (
	MinLength = 12
	MaxLength = 256
)

// Concurrency is how many hashes run at once.
const Concurrency = 4

const (
	saltLen = 16
	tagLen  = 32
	// Limits on the parameters of a stored hash, so a tampered row cannot make a verification
	// cost more than the costliest profile allows.
	maxMemoryKiB = 256 * 1024
	maxTime      = 10
	maxThreads   = 16
)

// Params are argon2id's cost parameters.
type Params struct {
	Time      uint32
	MemoryKiB uint32
	Threads   uint8
}

// The profiles: RFC 9106's second recommended option, and one for hosts with less than 1 GiB of
// memory.
var (
	Default   = Params{Time: 3, MemoryKiB: 64 * 1024, Threads: 4}
	LowMemory = Params{Time: 2, MemoryKiB: 19 * 1024, Threads: 1}
)

// ParamsOf returns the parameters of a profile setting; unset is Default.
func ParamsOf(p rpmgrv1.PasswordHashProfile) Params {
	if p == rpmgrv1.PasswordHashProfile_PASSWORD_HASH_PROFILE_LOW_MEMORY {
		return LowMemory
	}
	return Default
}

// ErrLength is returned for a password shorter than MinLength or longer than MaxLength.
var ErrLength = fmt.Errorf("password: a password has %d to %d characters", MinLength, MaxLength)

// slots bounds concurrent hashes.
var slots = make(chan struct{}, Concurrency)

// idKey is argon2.IDKey; a variable for tests.
var idKey = argon2.IDKey

// CheckLength reports ErrLength for a password outside the length limits, counted in characters.
func CheckLength(pw string) error {
	if n := utf8.RuneCountInString(pw); n < MinLength || n > MaxLength || !utf8.ValidString(pw) {
		return ErrLength
	}
	return nil
}

// Hash returns the PHC string of a password under p.
func Hash(ctx context.Context, pw string, p Params) (string, error) {
	if err := CheckLength(pw); err != nil {
		return "", err
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	tag, err := derive(ctx, pw, salt, p, tagLen)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.MemoryKiB, p.Time, p.Threads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(tag)), nil
}

// Verify reports whether pw matches the PHC string, and whether the hash should be replaced
// because its parameters are not want. An empty phc, the case of an unknown user or one without a
// password, costs one hash under want and never matches.
func Verify(ctx context.Context, pw, phc string, want Params) (ok, rehash bool, err error) {
	if phc == "" {
		_, err := derive(ctx, pw, make([]byte, saltLen), want, tagLen)
		return false, false, err
	}
	h, err := parse(phc)
	if err != nil {
		return false, false, err
	}
	tag, err := derive(ctx, pw, h.salt, h.params, uint32(len(h.tag))) //nolint:gosec // G115: 16 to 64 bytes, checked in parse
	if err != nil {
		return false, false, err
	}
	ok = subtle.ConstantTimeCompare(tag, h.tag) == 1
	return ok, ok && (h.params != want || len(h.salt) != saltLen || len(h.tag) != tagLen), nil
}

// derive runs argon2id once a slot is free.
func derive(ctx context.Context, pw string, salt []byte, p Params, n uint32) ([]byte, error) {
	select {
	case slots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-slots }()
	return idKey([]byte(pw), salt, p.Time, p.MemoryKiB, p.Threads, n), nil
}

type phc struct {
	params    Params
	salt, tag []byte
}

// parse reads an argon2id PHC string of version 19 within the parameter limits.
func parse(s string) (phc, error) {
	bad := errors.New("password: not an argon2id hash of version 19 in PHC format within the limits")
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return phc{}, bad
	}
	var h phc
	seen := map[string]bool{}
	for _, kv := range strings.Split(parts[3], ",") {
		k, v, _ := strings.Cut(kv, "=")
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil || seen[k] {
			return phc{}, bad
		}
		seen[k] = true
		switch {
		case k == "m" && n >= 8 && n <= maxMemoryKiB:
			h.params.MemoryKiB = uint32(n)
		case k == "t" && n >= 1 && n <= maxTime:
			h.params.Time = uint32(n)
		case k == "p" && n >= 1 && n <= maxThreads:
			h.params.Threads = uint8(n)
		default:
			return phc{}, bad
		}
	}
	if len(seen) != 3 {
		return phc{}, bad
	}
	var err error
	if h.salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil || len(h.salt) < 8 {
		return phc{}, bad
	}
	if h.tag, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil || len(h.tag) < 16 || len(h.tag) > 64 {
		return phc{}, bad
	}
	return h, nil
}
