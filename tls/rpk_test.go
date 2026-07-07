package tls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
)

// rpkPair runs a mutual raw-public-key handshake over net.Pipe and returns the
// two ConnectionStates plus any error, so tests can assert on the negotiated
// peer keys.
func rpkHandshake(t *testing.T, serverCfg, clientCfg *Config) (srvState, cliState ConnectionState, srvErr, cliErr error) {
	t.Helper()
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv := Server(s, serverCfg)
		if err := srv.Handshake(); err != nil {
			srvErr = err
			return
		}
		srvState = srv.ConnectionState()
		// exchange one round-trip
		buf := make([]byte, 4)
		if _, err := io.ReadFull(srv, buf); err != nil {
			srvErr = err
			return
		}
		if _, err := srv.Write([]byte("pong")); err != nil {
			srvErr = err
		}
	}()

	cli := Client(c, clientCfg)
	if err := cli.Handshake(); err != nil {
		cliErr = err
		wg.Wait()
		return
	}
	cliState = cli.ConnectionState()
	if _, err := cli.Write([]byte("ping")); err != nil {
		cliErr = err
		wg.Wait()
		return
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(cli, buf); err != nil {
		cliErr = err
	} else if string(buf) != "pong" {
		cliErr = errors.New("bad reply: " + string(buf))
	}
	wg.Wait()
	return
}

func genKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestRPKServerOnly(t *testing.T) {
	srvPub, srvPriv := genKey(t)

	var gotServerKey ed25519.PublicKey
	serverCfg := &Config{
		MinVersion: VersionTLS13,
		RawPublicKeys: &RawPublicKeyConfig{
			PrivateKey: srvPriv,
			Verify:     func(ed25519.PublicKey) error { return nil }, // no client auth requested
		},
	}
	clientCfg := &Config{
		MinVersion:         VersionTLS13,
		InsecureSkipVerify: true, // bypasses X.509 path; RPK Verify is what matters
		RawPublicKeys: &RawPublicKeyConfig{
			Verify: func(peer ed25519.PublicKey) error {
				gotServerKey = peer
				return nil
			},
		},
	}

	srvState, cliState, srvErr, cliErr := rpkHandshake(t, serverCfg, clientCfg)
	if srvErr != nil {
		t.Fatalf("server: %v", srvErr)
	}
	if cliErr != nil {
		t.Fatalf("client: %v", cliErr)
	}
	if !bytes.Equal(gotServerKey, srvPub) {
		t.Fatalf("client saw wrong server key")
	}
	if !bytes.Equal(cliState.PeerRawPublicKey, srvPub) {
		t.Fatalf("ConnectionState.PeerRawPublicKey mismatch on client")
	}
	if cliState.Version != VersionTLS13 {
		t.Fatalf("expected TLS 1.3")
	}
	// Server didn't request client auth, so it has no peer key.
	if srvState.PeerRawPublicKey != nil {
		t.Fatalf("server unexpectedly got a client key")
	}
}

func TestRPKMutualAuth(t *testing.T) {
	srvPub, srvPriv := genKey(t)
	cliPub, cliPriv := genKey(t)

	var serverSawClient ed25519.PublicKey
	serverCfg := &Config{
		MinVersion: VersionTLS13,
		ClientAuth: RequireAnyClientCert,
		RawPublicKeys: &RawPublicKeyConfig{
			PrivateKey: srvPriv,
			Verify: func(peer ed25519.PublicKey) error {
				serverSawClient = peer
				return nil
			},
		},
	}
	var clientSawServer ed25519.PublicKey
	clientCfg := &Config{
		MinVersion:         VersionTLS13,
		InsecureSkipVerify: true,
		RawPublicKeys: &RawPublicKeyConfig{
			PrivateKey: cliPriv,
			Verify: func(peer ed25519.PublicKey) error {
				clientSawServer = peer
				return nil
			},
		},
	}

	srvState, cliState, srvErr, cliErr := rpkHandshake(t, serverCfg, clientCfg)
	if srvErr != nil {
		t.Fatalf("server: %v", srvErr)
	}
	if cliErr != nil {
		t.Fatalf("client: %v", cliErr)
	}
	if !bytes.Equal(clientSawServer, srvPub) {
		t.Fatalf("client saw wrong server key")
	}
	if !bytes.Equal(serverSawClient, cliPub) {
		t.Fatalf("server saw wrong client key")
	}
	if !bytes.Equal(cliState.PeerRawPublicKey, srvPub) {
		t.Fatalf("client ConnectionState peer key mismatch")
	}
	if !bytes.Equal(srvState.PeerRawPublicKey, cliPub) {
		t.Fatalf("server ConnectionState peer key mismatch")
	}
}

// TestRPKVerifyRejection ensures a rejecting Verify callback aborts the handshake.
func TestRPKVerifyRejection(t *testing.T) {
	_, srvPriv := genKey(t)

	serverCfg := &Config{
		MinVersion:    VersionTLS13,
		RawPublicKeys: &RawPublicKeyConfig{PrivateKey: srvPriv, Verify: func(ed25519.PublicKey) error { return nil }},
	}
	clientCfg := &Config{
		MinVersion:         VersionTLS13,
		InsecureSkipVerify: true,
		RawPublicKeys: &RawPublicKeyConfig{
			Verify: func(ed25519.PublicKey) error { return errors.New("nope, unknown identity") },
		},
	}

	_, _, _, cliErr := rpkHandshake(t, serverCfg, clientCfg)
	if cliErr == nil {
		t.Fatalf("expected client handshake to fail on rejected server key")
	}
}

// TestRPKServerRequiresClientRPKForClientAuth covers the mutual-auth downgrade
// gap: a client that offers RawPublicKey for the *server* direction but not the
// *client* direction, against a server requesting client auth, must be refused
// rather than silently falling back to an X.509 client certificate.
func TestRPKServerRequiresClientRPKForClientAuth(t *testing.T) {
	_, srvPriv := genKey(t)
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	go func() { _, _ = io.Copy(io.Discard, c) }() // drain any alert the server writes

	conn := Server(s, &Config{
		MinVersion: VersionTLS13,
		ClientAuth: RequireAnyClientCert,
		RawPublicKeys: &RawPublicKeyConfig{
			PrivateKey: srvPriv,
			Verify:     func(ed25519.PublicKey) error { return nil },
		},
	})

	// Client offered server RPK but omitted client_certificate_type.
	hs := &serverHandshakeStateTLS13{
		c: conn,
		clientHello: &clientHelloMsg{
			serverCertificateTypes:       []uint8{certTypeRawPublicKey},
			supportedSignatureAlgorithms: []SignatureScheme{Ed25519},
		},
	}
	ee := &encryptedExtensionsMsg{}
	if err := hs.setupRawPublicKeyEncryptedExtensions(ee); err == nil {
		t.Fatal("server accepted client-auth without a client RPK offer (X.509 downgrade)")
	}
	if conn.rpkForClientCert {
		t.Fatal("rpkForClientCert must not be set when the client did not offer RPK")
	}

	// Sanity: when the client does offer client RPK, negotiation succeeds.
	hs.clientHello.clientCertificateTypes = []uint8{certTypeRawPublicKey}
	if err := hs.setupRawPublicKeyEncryptedExtensions(&encryptedExtensionsMsg{}); err != nil {
		t.Fatalf("negotiation failed with a valid client RPK offer: %v", err)
	}
	if !conn.rpkForClientCert {
		t.Fatal("rpkForClientCert should be set after a valid client RPK offer")
	}
}

// TestRPKRejectsNonEd25519Key ensures a peer presenting a non-Ed25519 raw
// public key (e.g. an ECDSA P-256 SPKI) is rejected — only Ed25519 is accepted,
// as in the C++ node.
func TestRPKRejectsNonEd25519Key(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	go func() { _, _ = io.Copy(io.Discard, s) }()

	conn := Client(c, &Config{
		MinVersion:    VersionTLS13,
		RawPublicKeys: &RawPublicKeyConfig{Verify: func(ed25519.PublicKey) error { return nil }},
	})

	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.processRawPublicKey(Certificate{Certificate: [][]byte{spki}}); err == nil {
		t.Fatal("accepted a non-Ed25519 raw public key")
	}
	if conn.peerRawPublicKey != nil {
		t.Fatal("peerRawPublicKey must stay unset on rejection")
	}
}

// TestRPKClientRequiresTLS13 ensures a client configured for raw public keys
// refuses to offer them alongside TLS 1.2 (the C++ node pins min==max==1.3).
func TestRPKClientRequiresTLS13(t *testing.T) {
	_, priv := genKey(t)
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	go func() { _, _ = io.Copy(io.Discard, s) }()

	conn := Client(c, &Config{
		MinVersion:    VersionTLS12, // too low for RPK
		MaxVersion:    VersionTLS13,
		RawPublicKeys: &RawPublicKeyConfig{PrivateKey: priv, Verify: func(ed25519.PublicKey) error { return nil }},
	})
	if err := conn.Handshake(); err == nil {
		t.Fatal("expected handshake to fail: raw public keys require TLS 1.3 only")
	}
}

// TestRPKClientRefusesNonRPKClientAuth ensures a client refuses a server that
// requests client authentication without negotiating a raw public key for it —
// no X.509 client-cert fallback.
func TestRPKClientRefusesNonRPKClientAuth(t *testing.T) {
	_, priv := genKey(t)
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	go func() { _, _ = io.Copy(io.Discard, s) }()

	conn := Client(c, &Config{
		MinVersion:    VersionTLS13,
		RawPublicKeys: &RawPublicKeyConfig{PrivateKey: priv, Verify: func(ed25519.PublicKey) error { return nil }},
	})
	// Server sent a CertificateRequest but never negotiated RawPublicKey for the
	// client direction (conn.rpkForClientCert stays false).
	hs := &clientHandshakeStateTLS13{c: conn, certReq: &certificateRequestMsgTLS13{}}
	if err := hs.sendClientCertificate(); err == nil {
		t.Fatal("client accepted non-RPK client authentication request")
	}
}

// TestConfigCloneKeepsRawPublicKeys guards against Config.Clone dropping the
// RawPublicKeys field — quic-go clones the config before every handshake, so a
// dropped field silently disables RPK and the server falls back to X.509.
func TestConfigCloneKeepsRawPublicKeys(t *testing.T) {
	_, priv := genKey(t)
	rpk := &RawPublicKeyConfig{PrivateKey: priv, Verify: func(ed25519.PublicKey) error { return nil }}
	cfg := &Config{RawPublicKeys: rpk}
	if cfg.Clone().RawPublicKeys != rpk {
		t.Fatal("Config.Clone dropped RawPublicKeys")
	}
}

// TestRPKServerRequiresClientOffer ensures a server in RPK mode refuses a client
// that does not offer raw public keys (no silent X.509 fallback).
func TestRPKServerRequiresClientOffer(t *testing.T) {
	_, srvPriv := genKey(t)

	serverCfg := &Config{
		MinVersion:    VersionTLS13,
		RawPublicKeys: &RawPublicKeyConfig{PrivateKey: srvPriv, Verify: func(ed25519.PublicKey) error { return nil }},
	}
	// Plain client, no RPK config.
	clientCfg := &Config{MinVersion: VersionTLS13, InsecureSkipVerify: true}

	_, _, srvErr, cliErr := rpkHandshake(t, serverCfg, clientCfg)
	if srvErr == nil && cliErr == nil {
		t.Fatalf("expected handshake failure when client does not offer raw public keys")
	}
}
