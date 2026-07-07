// Package fips140tls is a stand-in for crypto/tls/internal/fips140tls used by
// the vendored crypto/tls fork. This fork is never built in FIPS-only mode, so
// enforcement is always off.
package fips140tls

// Required reports whether FIPS 140-3 mode restrictions must be enforced.
// Always false in this fork.
func Required() bool { return false }
