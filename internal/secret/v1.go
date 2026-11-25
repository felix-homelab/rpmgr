// SPDX-License-Identifier: Apache-2.0

package secret

// Sealed format, version 1, the layout of Phase 1. It is read for ever and never written:
//
//	1 byte   format version (1)
//	8 bytes  KEK version
//	12 bytes nonce of the wrapped data key
//	48 bytes wrapped data key (32-byte key + 16-byte tag)
//	12 bytes nonce of the secret
//	n+16     encrypted secret and tag

const (
	v1WrappedLen = keyLen + tagLen
	v1HeaderLen  = 1 + kekIDLen + nonceLen + v1WrappedLen + nonceLen
)

func (s *Sealer) unwrapV1(ctx Context, sealed []byte) (parsed, error) {
	if len(sealed) < v1HeaderLen+tagLen || len(sealed) > v1HeaderLen+maxSealSize+tagLen {
		return parsed{}, ErrOpen
	}
	var id [kekIDLen]byte
	copy(id[:], sealed[1:1+kekIDLen])
	w, ok := s.byID[wrapperID{KindLocal, string(id[:])}]
	local, isLocal := w.(*LocalWrapper)
	if !ok || !isLocal {
		return parsed{}, ErrOpen
	}
	wrapped := sealed[1+kekIDLen : 1+kekIDLen+nonceLen+v1WrappedLen]
	dataKey, err := openGCM([]byte(local.kek.key.Reveal()), wrapped, wrapADV1(ctx, id))
	if err != nil {
		return parsed{}, ErrOpen
	}
	return parsed{format: formatV1, wrapper: w, dataKey: dataKey, rest: sealed[1+kekIDLen+nonceLen+v1WrappedLen:]}, nil
}

// wrapADV1 is the wrapped data key's associated data: the context and the KEK version.
func wrapADV1(ctx Context, kekID [kekIDLen]byte) []byte {
	return append(append([]byte("rpmgr-envelope-v1/wrap"), dataAD(formatV1, ctx)...), kekID[:]...)
}
