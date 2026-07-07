// Package tls12 is a stand-in for crypto/internal/fips140/tls12 used by the
// vendored crypto/tls fork. It implements the TLS 1.2 PRF (RFC 5246 §5) and the
// extended master secret derivation (RFC 7627), without the FIPS service
// indicator bookkeeping of the original.
package tls12

import (
	"crypto/hmac"
	"hash"
)

// hmacNew adapts a generic hash constructor to crypto/hmac.New.
func hmacNew[H hash.Hash](h func() H, key []byte) hash.Hash {
	return hmac.New(func() hash.Hash { return h() }, key)
}

// PRF implements the TLS 1.2 pseudo-random function, as defined in RFC 5246,
// Section 5.
func PRF[H hash.Hash](hash func() H, secret []byte, label string, seed []byte, keyLen int) []byte {
	labelAndSeed := make([]byte, len(label)+len(seed))
	copy(labelAndSeed, label)
	copy(labelAndSeed[len(label):], seed)

	result := make([]byte, keyLen)
	pHash(hash, result, secret, labelAndSeed)
	return result
}

// pHash implements the P_hash function, as defined in RFC 5246, Section 5.
func pHash[H hash.Hash](hash func() H, result, secret, seed []byte) {
	h := hmacNew(hash, secret)
	h.Write(seed)
	a := h.Sum(nil)

	for len(result) > 0 {
		h.Reset()
		h.Write(a)
		h.Write(seed)
		b := h.Sum(nil)
		n := copy(result, b)
		result = result[n:]

		h.Reset()
		h.Write(a)
		a = h.Sum(nil)
	}
}

const masterSecretLength = 48
const extendedMasterSecretLabel = "extended master secret"

// MasterSecret implements the TLS 1.2 extended master secret derivation, as
// defined in RFC 7627.
func MasterSecret[H hash.Hash](hash func() H, preMasterSecret, transcript []byte) []byte {
	return PRF(hash, preMasterSecret, extendedMasterSecretLabel, transcript, masterSecretLength)
}
