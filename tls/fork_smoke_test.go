package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

// TestForkX509Handshake is a smoke test proving the de-internalized crypto/tls
// fork still completes a normal TLS 1.3 handshake and moves application data.
func TestForkX509Handshake(t *testing.T) {
	cert := selfSignedCert(t)

	serverCfg := &Config{
		Certificates: []Certificate{cert},
		MinVersion:   VersionTLS13,
	}
	clientCfg := &Config{
		InsecureSkipVerify: true,
		MinVersion:         VersionTLS13,
	}

	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	var serverErr error
	go func() {
		defer wg.Done()
		srv := Server(s, serverCfg)
		if err := srv.Handshake(); err != nil {
			serverErr = err
			return
		}
		buf := make([]byte, 5)
		if _, err := io.ReadFull(srv, buf); err != nil {
			serverErr = err
			return
		}
		if string(buf) != "hello" {
			serverErr = errors.New("server got wrong payload: " + string(buf))
			return
		}
		if _, err := srv.Write([]byte("world")); err != nil {
			serverErr = err
		}
	}()

	cli := Client(c, clientCfg)
	if err := cli.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if cs := cli.ConnectionState(); cs.Version != VersionTLS13 {
		t.Fatalf("expected TLS 1.3, got version 0x%04x", cs.Version)
	}
	if _, err := cli.Write([]byte("hello")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(cli, buf); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(buf) != "world" {
		t.Fatalf("client got wrong payload: %q", buf)
	}

	wg.Wait()
	if serverErr != nil {
		t.Fatalf("server side: %v", serverErr)
	}
}

func selfSignedCert(t *testing.T) Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fork-smoke"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"fork-smoke"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}
