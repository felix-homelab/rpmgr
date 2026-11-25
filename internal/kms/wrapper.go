// SPDX-License-Identifier: Apache-2.0

package kms

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/felix-homelab/rpmgr/internal/secret"
)

// contextLabel starts the Transit context, then the secret's AAD ("Envelope format v2" in
// docs/04-security.md).
const contextLabel = "rpmgr-envelope-v2/transit"

// keyType is the only Transit key type rpmgr uses.
const keyType = "aes256-gcm96"

var ciphertextRe = regexp.MustCompile(`^vault:v([1-9][0-9]{0,9}):[A-Za-z0-9+/]+={0,2}$`)

var _ secret.Wrapper = (*Client)(nil)

// ErrKeyVersion means Transit refuses the key version of a ciphertext: the minimum decryption
// version was raised past it, or the key was restored from an older state and does not know it yet.
// Both are states the operator can change; it is neither a value that does not open nor an outage.
var ErrKeyVersion = errors.New("kms: transit does not accept the key version of the ciphertext")

// Kind implements secret.Wrapper.
func (c *Client) Kind() byte { return secret.KindTransit }

// ID implements secret.Wrapper: "<mount>/<key>".
func (c *Client) ID() []byte { return []byte(c.mount + "/" + c.key) }

// transitContext is the base64 context that binds a wrap to the secret's AAD.
func transitContext(aad []byte) string {
	return base64.StdEncoding.EncodeToString(append([]byte(contextLabel), aad...))
}

// Wrap implements secret.Wrapper: Transit encrypts the data key under the key's latest version
// and the result is the ciphertext as ASCII, "vault:v<n>:<base64>".
func (c *Client) Wrap(ctx context.Context, dataKey, aad []byte) ([]byte, error) {
	pt := base64.StdEncoding.EncodeToString(dataKey)
	ct, err := c.transit(ctx, "encrypt", map[string]string{
		"plaintext": pt,
		"context":   transitContext(aad),
	}, secret.FromBytes(dataKey), secret.New(pt))
	if err != nil {
		return nil, err
	}
	return []byte(ct), nil
}

// Unwrap implements secret.Wrapper. A ciphertext that is malformed or that Transit says does not
// open, as with a changed context, is secret.ErrOpen; every other failure is returned as it is.
func (c *Client) Unwrap(ctx context.Context, wrapped, aad []byte) ([]byte, error) {
	if !ciphertextRe.Match(wrapped) {
		return nil, secret.ErrOpen
	}
	var out struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	body, err := json.Marshal(map[string]string{"ciphertext": string(wrapped), "context": transitContext(aad)})
	if err != nil {
		return nil, err
	}
	err = c.do(ctx, http.MethodPost, c.path("decrypt"), body, &out)
	if err != nil {
		return nil, mapOpenError(err)
	}
	key, err := base64.StdEncoding.DecodeString(out.Data.Plaintext)
	if err != nil || len(key) == 0 {
		// A 2xx answer without a key, as with wrap_info or an empty object, is not a value that does
		// not open: Transit did not answer the question.
		return nil, fmt.Errorf("%w: the answer to decrypt holds no usable plaintext", ErrUnavailable)
	}
	return key, nil
}

// Rewrap moves a ciphertext to the key's latest version without the data key leaving Transit. It
// is for `rpmgr kek rotate`; the result is a new wrapped data key for the same row.
func (c *Client) Rewrap(ctx context.Context, wrapped, aad []byte) ([]byte, error) {
	if !ciphertextRe.Match(wrapped) {
		return nil, secret.ErrOpen
	}
	ct, err := c.transit(ctx, "rewrap", map[string]string{
		"ciphertext": string(wrapped),
		"context":    transitContext(aad),
	})
	if err != nil {
		return nil, mapOpenError(err)
	}
	return []byte(ct), nil
}

// Check reads the key and refuses one that is missing, of another type or not derived. It also
// returns the key's latest version. The controller calls it at start.
func (c *Client) Check(ctx context.Context) (latest int, err error) {
	var out struct {
		Data struct {
			Type          string `json:"type"`
			Derived       bool   `json:"derived"`
			LatestVersion int    `json:"latest_version"`
		} `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, "/"+c.mount+"/keys/"+c.key, nil, &out); err != nil {
		var te *Error
		if errors.As(err, &te) && te.Status == http.StatusNotFound {
			return 0, fmt.Errorf("kms: key %s/%s or mount %s not found: %w", c.mount, c.key, c.mount, err)
		}
		return 0, err
	}
	if out.Data.Type != keyType {
		return 0, fmt.Errorf("kms: key %s/%s is of type %q, not %s", c.mount, c.key, clean(out.Data.Type, nil), keyType)
	}
	if !out.Data.Derived {
		return 0, fmt.Errorf("kms: key %s/%s is not derived; create it with derived=true", c.mount, c.key)
	}
	if out.Data.LatestVersion < 1 {
		return 0, fmt.Errorf("kms: key %s/%s reports no latest version", c.mount, c.key)
	}
	c.noteVersion(out.Data.LatestVersion)
	return out.Data.LatestVersion, nil
}

func (c *Client) path(op string) string { return "/" + c.mount + "/" + op + "/" + c.key }

// transit runs encrypt or rewrap and returns the ciphertext of the answer.
func (c *Client) transit(ctx context.Context, op string, req map[string]string, redact ...secret.Value) (string, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	var out struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	if err := c.do(ctx, http.MethodPost, c.path(op), body, &out, redact...); err != nil {
		return "", err
	}
	if !ciphertextRe.MatchString(out.Data.Ciphertext) {
		return "", fmt.Errorf("%w: the answer to %s holds no ciphertext in the vault:v<n>: form", ErrUnavailable, op)
	}
	// Transit wraps under the latest version; an older one than Check or an earlier answer saw means
	// the key service went back to an older state, which must not seal new values.
	v := versionOf(out.Data.Ciphertext)
	if latest := int(c.latest.Load()); v < latest {
		return "", fmt.Errorf("%w: the answer to %s is of version %d, the key's latest seen is %d", ErrKeyVersion, op, v, latest)
	}
	c.noteVersion(v)
	return out.Data.Ciphertext, nil
}

// noteVersion remembers the highest key version seen.
func (c *Client) noteVersion(v int) {
	for {
		cur := c.latest.Load()
		if int64(v) <= cur || c.latest.CompareAndSwap(cur, int64(v)) {
			return
		}
	}
}

// versionOf is the n of "vault:v<n>:…", which ciphertextRe has checked.
func versionOf(ct string) int {
	m := ciphertextRe.FindStringSubmatch(ct)
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

// mapOpenError turns the 400 of Transit for a ciphertext it cannot use into the error that says
// what is wrong with it. Transit gives no code, so the message is matched [V VB-31]. A key version
// that is too old (the minimum decryption version was raised) or too new (Transit was restored from
// an older backup) is ErrKeyVersion, checked first because those messages also name the
// ciphertext. A failed authentication, as with a changed context, and an invalid ciphertext do not
// open: secret.ErrOpen. A 400 of another kind, such as a key that does not exist, is a
// configuration error and is returned as it is, as is every other failure.
func mapOpenError(err error) error {
	var te *Error
	if !errors.As(err, &te) || te.Status != http.StatusBadRequest {
		return err
	}
	m := strings.ToLower(te.Message)
	switch {
	case strings.Contains(m, "too old") || strings.Contains(m, "too new") || strings.Contains(m, "disallowed by policy"):
		return fmt.Errorf("%w: %w", ErrKeyVersion, err)
	case strings.Contains(m, "message authentication failed") || strings.Contains(m, "invalid ciphertext"):
		return secret.ErrOpen
	}
	return err
}
