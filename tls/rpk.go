// Copyright 2026. RFC 7250 raw public key support for the vendored crypto/tls.
//
// This file is the only substantial addition to the forked crypto/tls sources.
// Everything RFC 7250-specific lives here; the copied handshake files carry
// only small, clearly marked `// RPK` hook calls into the functions below.
//
// Profile implemented (deliberately narrow, to match the TON C++ node):
//   - TLS 1.3 only, mutual raw public keys, no X.509 fallback.
//   - Keys are Ed25519, carried as a single SubjectPublicKeyInfo in the
//     Certificate message (RFC 7250 §3, RFC 8446 §4.4.2).
//   - client_certificate_type(19) and server_certificate_type(20) extensions
//     carry only RawPublicKey(2).

package tls

import (
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
)

// Certificate types from the IANA "TLS Certificate Types" registry (RFC 7250).
const (
	certTypeX509         uint8 = 0
	certTypeRawPublicKey uint8 = 2
)

// Extension code points for RFC 7250 (IANA "TLS ExtensionType Values").
const (
	extensionClientCertType uint16 = 19 // client_certificate_type
	extensionServerCertType uint16 = 20 // server_certificate_type
)

// RawPublicKeyConfig, when assigned to Config.RawPublicKeys, switches a
// connection to RFC 7250 raw public key mode. In this mode X.509 certificates
// are replaced by bare Ed25519 public keys in both directions. It requires
// TLS 1.3. Session resumption is disabled internally (the server issues no
// tickets and the client offers no PSK), so every connection performs a full
// handshake and the Verify callback always runs. When a server both enables
// raw public keys and requests client authentication, the client must also
// present a raw public key — there is no X.509 fallback in either direction.
type RawPublicKeyConfig struct {
	// PrivateKey is the local Ed25519 key presented as this endpoint's raw
	// public key. On a server it is the default identity (used when no SNI
	// matches); on a client it is the key presented if the server requests
	// client authentication. May be nil on a client that never authenticates.
	PrivateKey ed25519.PrivateKey

	// GetPrivateKey, if set on a server, selects the local Ed25519 key by the
	// client's SNI. Returning (nil, nil) falls back to PrivateKey. This is how
	// a server hosts multiple ADNL identities on one socket.
	GetPrivateKey func(sni string) (ed25519.PrivateKey, error)

	// Verify is invoked with the peer's Ed25519 public key immediately after it
	// is received and before the handshake completes. Returning an error aborts
	// the handshake. Required whenever a peer key is expected.
	Verify func(peer ed25519.PublicKey) error
}

func (c *Config) rpk() *RawPublicKeyConfig {
	if c == nil {
		return nil
	}
	return c.RawPublicKeys
}

func (r *RawPublicKeyConfig) selectKey(sni string) (ed25519.PrivateKey, error) {
	if r.GetPrivateKey != nil {
		k, err := r.GetPrivateKey(sni)
		if err != nil {
			return nil, err
		}
		if k != nil {
			return k, nil
		}
	}
	if len(r.PrivateKey) == 0 {
		return nil, errors.New("tls: no raw public key private key configured")
	}
	return r.PrivateKey, nil
}

// rawPublicKeyCertificate builds a Certificate whose single entry is the DER
// SubjectPublicKeyInfo of the Ed25519 key, so the normal certificate-message
// marshaling writes the raw public key on the wire.
func rawPublicKeyCertificate(priv ed25519.PrivateKey) (*Certificate, error) {
	spki, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		return nil, fmt.Errorf("tls: marshaling raw public key: %w", err)
	}
	return &Certificate{Certificate: [][]byte{spki}, PrivateKey: priv}, nil
}

// processRawPublicKey parses the peer's SubjectPublicKeyInfo, runs the Verify
// callback, and installs a synthetic leaf so the existing CertificateVerify
// path (which reads peerCertificates[0].PublicKey) works unchanged.
func (c *Conn) processRawPublicKey(certificate Certificate) error {
	if len(certificate.Certificate) != 1 {
		c.sendAlert(alertDecodeError)
		return errors.New("tls: raw public key peer must send exactly one SubjectPublicKeyInfo")
	}
	pub, err := x509.ParsePKIXPublicKey(certificate.Certificate[0])
	if err != nil {
		c.sendAlert(alertBadCertificate)
		return fmt.Errorf("tls: failed to parse peer raw public key: %w", err)
	}
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		c.sendAlert(alertUnsupportedCertificate)
		return fmt.Errorf("tls: peer raw public key is %T, want Ed25519", pub)
	}
	if r := c.config.rpk(); r != nil && r.Verify != nil {
		if err := r.Verify(edPub); err != nil {
			c.sendAlert(alertBadCertificate)
			return fmt.Errorf("tls: raw public key rejected: %w", err)
		}
	}
	c.peerRawPublicKey = edPub
	c.peerCertificates = []*x509.Certificate{{PublicKey: edPub}}
	return nil
}

// enableRawPublicKeys advertises RawPublicKey for both directions in the
// ClientHello. Called from makeClientHello when RPK is configured.
func (m *clientHelloMsg) enableRawPublicKeys() {
	m.clientCertificateTypes = []uint8{certTypeRawPublicKey}
	m.serverCertificateTypes = []uint8{certTypeRawPublicKey}
}

// negotiateRawPublicKeyClient validates the server's EncryptedExtensions echo
// and records which directions use raw public keys. With RPK configured the
// server MUST select RawPublicKey for its own certificate; there is no X.509
// fallback (matching the reference C++ node).
func (c *Conn) negotiateRawPublicKeyClient(ee *encryptedExtensionsMsg) error {
	if c.config.rpk() == nil {
		// We didn't offer RPK. A server must not select it unsolicited.
		if ee.serverCertificateType != nil || ee.clientCertificateType != nil {
			c.sendAlert(alertUnsupportedExtension)
			return errors.New("tls: server sent unsolicited certificate_type extension")
		}
		return nil
	}

	if ee.serverCertificateType == nil {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: server did not select raw public key certificate type")
	}
	if *ee.serverCertificateType != certTypeRawPublicKey {
		c.sendAlert(alertUnsupportedCertificate)
		return fmt.Errorf("tls: server selected unsupported server certificate type %d", *ee.serverCertificateType)
	}
	c.rpkForServerCert = true

	if ee.clientCertificateType != nil {
		if *ee.clientCertificateType != certTypeRawPublicKey {
			c.sendAlert(alertUnsupportedCertificate)
			return fmt.Errorf("tls: server selected unsupported client certificate type %d", *ee.clientCertificateType)
		}
		c.rpkForClientCert = true
	}
	return nil
}

// pickRawPublicKeyCertificate is the RPK replacement for pickCertificate on the
// server: it requires the client to have offered RawPublicKey, selects the
// local Ed25519 identity by SNI, and pins Ed25519 as the signature scheme.
func (hs *serverHandshakeStateTLS13) pickRawPublicKeyCertificate() error {
	c := hs.c

	if !slices.Contains(hs.clientHello.serverCertificateTypes, certTypeRawPublicKey) {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: client does not support raw public keys (required by server)")
	}
	if !slices.Contains(hs.clientHello.supportedSignatureAlgorithms, Ed25519) {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: client does not support Ed25519 signatures required for raw public keys")
	}

	priv, err := c.config.rpk().selectKey(hs.clientHello.serverName)
	if err != nil {
		c.sendAlert(alertUnrecognizedName)
		return err
	}
	cert, err := rawPublicKeyCertificate(priv)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	hs.cert = cert
	hs.sigAlg = Ed25519
	c.rpkForServerCert = true
	return nil
}

// setupRawPublicKeyEncryptedExtensions echoes the selected certificate types in
// the server's EncryptedExtensions and records whether client authentication
// will use a raw public key. When the server requests client authentication it
// requires the client to use a raw public key too: there is no X.509 fallback
// for the client-auth direction, mirroring the server-cert direction in
// pickRawPublicKeyCertificate.
func (hs *serverHandshakeStateTLS13) setupRawPublicKeyEncryptedExtensions(ee *encryptedExtensionsMsg) error {
	c := hs.c
	if c.config.rpk() == nil {
		return nil
	}
	rpkType := certTypeRawPublicKey
	ee.serverCertificateType = &rpkType

	if hs.requestClientCert() {
		if !slices.Contains(hs.clientHello.clientCertificateTypes, certTypeRawPublicKey) {
			c.sendAlert(alertHandshakeFailure)
			return errors.New("tls: client does not support raw public keys for client authentication (required by server)")
		}
		t := certTypeRawPublicKey
		ee.clientCertificateType = &t
		c.rpkForClientCert = true
	}
	return nil
}

// sendRawPublicKeyClientCertificate is the RPK replacement for the client's
// certificate flight when the server requested client authentication with a
// raw public key.
func (hs *clientHandshakeStateTLS13) sendRawPublicKeyClientCertificate() error {
	c := hs.c

	r := c.config.rpk()
	if r == nil || len(r.PrivateKey) == 0 {
		// No client identity available: send an empty certificate. The server
		// decides whether that is acceptable per its ClientAuth policy.
		if _, err := hs.c.writeHandshakeRecord(&certificateMsgTLS13{}, hs.transcript); err != nil {
			return err
		}
		return nil
	}

	cert, err := rawPublicKeyCertificate(r.PrivateKey)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	certMsg := &certificateMsgTLS13{certificate: *cert}
	if _, err := hs.c.writeHandshakeRecord(certMsg, hs.transcript); err != nil {
		return err
	}

	certVerifyMsg := &certificateVerifyMsg{
		hasSignatureAlgorithm: true,
		signatureAlgorithm:    Ed25519,
	}
	signed := signedMessage(clientSignatureContext, hs.transcript)
	sig, err := crypto.SignMessage(cert.PrivateKey.(crypto.Signer), c.config.rand(), signed, crypto.SignerOpts(directSigning))
	if err != nil {
		c.sendAlert(alertInternalError)
		return errors.New("tls: failed to sign handshake: " + err.Error())
	}
	certVerifyMsg.signature = sig

	if _, err := hs.c.writeHandshakeRecord(certVerifyMsg, hs.transcript); err != nil {
		return err
	}
	return nil
}
