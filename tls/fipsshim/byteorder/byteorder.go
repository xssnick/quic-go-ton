// Package byteorder is a minimal stand-in for the standard library's
// internal/byteorder and crypto/internal/fips140deps/byteorder, exposing only
// the helpers used by the vendored crypto/tls fork.
package byteorder

import "encoding/binary"

// LEUint32 decodes a little-endian uint32 from b.
func LEUint32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }

// BEAppendUint16 appends a big-endian uint16 to b.
func BEAppendUint16(b []byte, v uint16) []byte { return binary.BigEndian.AppendUint16(b, v) }
