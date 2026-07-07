// Package hkdf is a stand-in for crypto/internal/fips140/hkdf used by the
// vendored tls13 key-schedule shim. It wraps the public crypto/hkdf and keeps
// the internal package's panic-on-error signatures so tls13.go stays verbatim.
package hkdf

import (
	stdhkdf "crypto/hkdf"
	"hash"
)

// Extract derives a pseudorandom key from secret and salt.
func Extract[H hash.Hash](h func() H, secret, salt []byte) []byte {
	out, err := stdhkdf.Extract(h, secret, salt)
	if err != nil {
		// Inputs are fixed-size hashes/secrets produced internally; an error
		// here means a programming mistake, not attacker input.
		panic("tls/fipsshim/hkdf: Extract: " + err.Error())
	}
	return out
}

// Expand expands a pseudorandom key into keyLen bytes bound to info.
func Expand[H hash.Hash](h func() H, prk []byte, info string, keyLen int) []byte {
	out, err := stdhkdf.Expand(h, prk, info, keyLen)
	if err != nil {
		panic("tls/fipsshim/hkdf: Expand: " + err.Error())
	}
	return out
}
