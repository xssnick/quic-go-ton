# quic-go-ton — TON fork of quic-go

This is a fork of [quic-go](https://github.com/quic-go/quic-go) adapted for the
TON network's QUIC transport. It is wire-compatible with the reference C++ node,
which uses ngtcp2 + OpenSSL 3.5 with **RFC 7250 Raw Public Keys** (Ed25519 ADNL
identities) instead of X.509 certificates.

The whole stack stays **pure Go** — no cgo, no OpenSSL.

## What differs from upstream quic-go

1. **Module path** renamed `github.com/quic-go/quic-go` → `github.com/xssnick/quic-go-ton`.
2. **Bundled TLS fork** at [`./tls`](./tls) — a copy of the Go 1.26 standard
   `crypto/tls`, de-internalized so it builds as a normal module, plus an
   RFC 7250 Raw Public Key implementation ([`tls/rpk.go`](./tls/rpk.go)).
   The core QUIC packages import this fork instead of stdlib `crypto/tls`, so
   RPK config flows through `quic.Config.TLSConfig` unchanged.
3. **Removed** `http3`, `interop`, `example`, `integrationtests` — they bridge to
   `net/http`'s standard-library `*tls.Config` and cannot use the forked TLS
   type. They are not needed for a raw QUIC transport.
4. Requires **Go 1.26** (the vendored `crypto/tls` uses 1.26 stdlib APIs such as
   `crypto/hkdf`, `crypto/hpke`, `errors.AsType`).
5. Handshake configuration in `internal/handshake/tls_config.go` always targets
   the bundled TLS API, regardless of the Go toolchain version. Do not restore
   upstream toolchain-version build tags for these helpers.

## Using raw public keys

Build the TLS config from the `tls` subpackage and pass it to `quic` as usual:

```go
import (
    quic "github.com/xssnick/quic-go-ton"
    "github.com/xssnick/quic-go-ton/tls"
)

tlsConf := &tls.Config{
    MinVersion: tls.VersionTLS13,
    NextProtos: []string{"ton"},
    RawPublicKeys: &tls.RawPublicKeyConfig{
        PrivateKey: myEd25519Priv,          // local identity
        GetPrivateKey: selectBySNI,          // server: choose identity by SNI (optional)
        Verify: func(peer ed25519.PublicKey) error { // required
            // check peer identity, return error to abort
            return nil
        },
    },
}
ln, _ := quic.Listen(pconn, tlsConf, quicConf)     // server
conn, _ := quic.DialAddr(ctx, addr, tlsConf, quicConf) // client
// after handshake: conn.ConnectionState().TLS.PeerRawPublicKey
```

The RPK profile is deliberately narrow to match the C++ node
(`setup_rpk_context` in `quic-pimpl.cpp`), which pins `min == max == TLS 1.3`,
`SSL_VERIFY_PEER`, and `server_certificate_type == client_certificate_type ==
{RawPublicKey}`. Enforced guarantees when `RawPublicKeys` is set — **only the
TON authorization method is accepted, no fallback in either direction**:

| Guarantee | Enforcement |
|-----------|-------------|
| TLS 1.3 only | client refuses to offer RPK unless `MinVersion == VersionTLS13` (`handshake_client.go`); quic-go pins 1.3 for QUIC |
| Server presents only a raw Ed25519 key | `pickRawPublicKeyCertificate` requires the client to have offered `server_certificate_type=RawPublicKey`, else `handshake_failure` |
| Client accepts only a raw Ed25519 server key | `negotiateRawPublicKeyClient` requires the server to echo `server_certificate_type=RawPublicKey`, else abort; a peer key that isn't Ed25519 is rejected (`processRawPublicKey`) |
| Mutual auth is raw-key only | server requesting client auth requires `client_certificate_type=RawPublicKey` (`setupRawPublicKeyEncryptedExtensions`); client refuses a non-RPK client-auth request (`sendClientCertificate`) |
| No anonymous / empty client cert | caller uses `ClientAuth: RequireAnyClientCert`; empty cert rejected |
| No session resumption | server issues no tickets, client offers no PSK — every connection re-runs `Verify` |
| Signature is Ed25519 | `signatureSchemesForPublicKey(ed25519) == [Ed25519]`; CertificateVerify validated against the peer's raw key |

A single SubjectPublicKeyInfo is carried in the Certificate message; the
`client_certificate_type`(19) / `server_certificate_type`(20) extensions carry
only `RawPublicKey`(2). See `tls/rpk_test.go` for the rejection tests.

**Interop-verified** against the reference C++ node (ngtcp2 + OpenSSL 3.5), both
directions of the QUIC + RPK handshake and the `quic.query`/`quic.answer`
framing. One interop requirement was discovered live: in RPK mode the ClientHello
`signature_algorithms` and the server's CertificateRequest must advertise **only
Ed25519** and must **not** send `signature_algorithms_cert`. A raw public key has
no X.509 certificate, and sending `signature_algorithms_cert` makes OpenSSL's RPK
peer dereference a non-existent certificate in `tls_choose_sigalg` and crash
(`X509_get_signature_info(NULL)`). This is enforced in `handshake_client.go`
(ClientHello) and `handshake_server_tls13.go` (CertificateRequest).

The TON application layer (SNI = ADNL id, ALPN `ton`, `quic.query`/`quic.answer`
TL framing) lives in `github.com/xssnick/tonutils-go/quic`, which imports this
module and derives each peer's ADNL id from `PeerRawPublicKey` after the
handshake — exactly like the C++ node's `parse_peer_id`.

## Maintaining the fork

### Re-basing the crypto/tls fork onto a newer Go

The `tls` package is a mechanical copy of `$(go env GOROOT)/src/crypto/tls`
with internal dependencies replaced by local shims under `tls/fipsshim/`:

| stdlib internal package            | replacement                     |
|------------------------------------|---------------------------------|
| `internal/godebug`                 | `tls/fipsshim/godebug` (no-op)  |
| `internal/byteorder`               | `tls/fipsshim/byteorder`        |
| `crypto/tls/internal/fips140tls`   | `tls/fipsshim/fips140tls` (off) |
| `crypto/internal/fips140/tls13`    | `tls/fipsshim/tls13` (+ hkdf)   |
| `crypto/internal/fips140/tls12`    | `tls/fipsshim/tls12`            |
| `crypto/internal/boring`, fips aes | rewritten in `cipher_suites.go` to stdlib `crypto/aes`+`crypto/cipher` |

`crypto/hpke`, `crypto/hkdf`, `crypto/fips140` are used as-is (public since Go 1.24/1.26).

To re-base: copy the new `crypto/tls` sources over `tls/*.go` (keeping
`rpk.go`), re-apply the import rewrites above, re-apply the small `// RPK`
hooks in `handshake_client_tls13.go`, `handshake_server_tls13.go`,
`handshake_messages.go`, `conn.go`, `common.go`, and re-run `go test ./tls/`.

### Re-basing onto a newer quic-go

1. Rename imports `github.com/quic-go/quic-go` → `github.com/xssnick/quic-go-ton`.
2. Rewrite `"crypto/tls"` → `"github.com/xssnick/quic-go-ton/tls"` in every
   non-`tls/` `.go` file.
3. Retarget the linkname pulls (they reference unexported stdlib symbols that
   the fork re-exports via `//go:linkname` push directives):
   - `internal/qtls/cipher_suite.go`: `cipherSuitesTLS13`, `defaultCipherSuitesTLS13`, `defaultCipherSuitesTLS13NoAES`
   - `internal/handshake/cipher_suite_fips140.go`: `aeadAESGCMTLS13`
4. Ensure `tls.Config.Clone()` copies `RawPublicKeys` (quic-go clones the config
   before every handshake — a dropped field silently disables RPK).
5. Remove `http3`, `interop`, `example`, `integrationtests`.
