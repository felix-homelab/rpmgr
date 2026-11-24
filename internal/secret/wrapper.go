// SPDX-License-Identifier: Apache-2.0

package secret

import "context"

// Wrapper kinds, the second byte of a version 2 value.
const (
	// KindLocal is a KEK the controller holds: a file or a systemd credential.
	KindLocal byte = 1
	// KindTransit is a key in Vault or OpenBao Transit; its Wrapper is not part of this package yet.
	KindTransit byte = 2
)

// A Wrapper wraps and unwraps data keys under a key-encryption key that it holds or reaches. It is
// the one place a KEK source differs ("KEK sources" in docs/04-security.md).
//
// aad is the secret's associated data, the table, column and row; a Wrapper binds the wrapped key
// to it in the way its kind defines, so that a value moved to another row does not unwrap.
// Unwrap returns ErrOpen for a wrapped key that does not open. Any other error means the Wrapper
// could not be asked, as when a key service is down, and is passed to the caller as it is so that
// it can be retried.
type Wrapper interface {
	// Kind is KindLocal or KindTransit.
	Kind() byte
	// ID is the KEK identifier written into the envelope, one to 256 bytes.
	ID() []byte
	Wrap(ctx context.Context, dataKey, aad []byte) ([]byte, error)
	Unwrap(ctx context.Context, wrapped, aad []byte) ([]byte, error)
}

// LocalWrapper wraps data keys with AES-256-GCM under a KEK the controller holds.
type LocalWrapper struct{ kek KEK }

// NewLocalWrapper returns the Wrapper for a local KEK.
func NewLocalWrapper(k KEK) *LocalWrapper { return &LocalWrapper{kek: k} }

// Kind implements Wrapper.
func (w *LocalWrapper) Kind() byte { return KindLocal }

// ID implements Wrapper: the 8-byte KEK version.
func (w *LocalWrapper) ID() []byte { return append([]byte(nil), w.kek.id[:]...) }

// Wrap implements Wrapper: a 12-byte nonce, the key and a 16-byte tag, 60 bytes. The associated
// data is the label rpmgr-envelope-v2/wrap, aad and the KEK identifier.
func (w *LocalWrapper) Wrap(_ context.Context, dataKey, aad []byte) ([]byte, error) {
	return sealGCM(nil, []byte(w.kek.key.Reveal()), dataKey, w.wrapAD(aad))
}

// Unwrap implements Wrapper.
func (w *LocalWrapper) Unwrap(_ context.Context, wrapped, aad []byte) ([]byte, error) {
	if len(wrapped) != nonceLen+keyLen+tagLen {
		return nil, ErrOpen
	}
	key, err := openGCM([]byte(w.kek.key.Reveal()), wrapped, w.wrapAD(aad))
	if err != nil {
		return nil, ErrOpen
	}
	return key, nil
}

func (w *LocalWrapper) wrapAD(aad []byte) []byte {
	ad := append([]byte("rpmgr-envelope-v2/wrap"), aad...)
	return append(ad, w.kek.id[:]...)
}
