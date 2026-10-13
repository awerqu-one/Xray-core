package raywire

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
)

// startTLSDecoy serves each connection with a crypto/tls server, which is how a TLS
// site meets a probe that is not TLS. It reports on arrived when the first byte of a
// connection is read, so a test can see when the bytes reached the decoy.
func startTLSDecoy(t *testing.T, arrived chan<- time.Time) xnet.Destination {
	t.Helper()
	cfg := &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}}
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.AcceptTCP()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				// The handshake fails on a probe, as it would at a real site.
				_ = tls.Server(&firstByteConn{Conn: c, arrived: arrived}, cfg).Handshake()
			}()
		}
	}()
	return xnet.DestinationFromAddr(ln.Addr())
}

// firstByteConn reports the time of the first read that returns bytes.
type firstByteConn struct {
	net.Conn
	once    sync.Once
	arrived chan<- time.Time
}

func (c *firstByteConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.once.Do(func() {
			select {
			case c.arrived <- time.Now():
			default:
			}
		})
	}
	return n, err
}

// selfSignedCert returns a certificate for a test decoy.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "decoy.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
