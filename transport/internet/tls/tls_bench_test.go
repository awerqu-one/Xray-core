package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	gotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

var (
	testCertOnce sync.Once
	testCert     gotls.Certificate
	testCertErr  error
)

// benchServerConfig returns a server config with a self-signed ECDSA P-256 certificate for
// localhost. The certificate is made once per test binary.
func benchServerConfig(tb testing.TB) *gotls.Config {
	tb.Helper()
	testCertOnce.Do(func() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			testCertErr = err
			return
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "localhost"},
			DNSNames:     []string{"localhost"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			testCertErr = err
			return
		}
		testCert = gotls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	})
	if testCertErr != nil {
		tb.Fatal(testCertErr)
	}
	return &gotls.Config{Certificates: []gotls.Certificate{testCert}}
}

// benchClientConfig is the client side of the test handshakes. The server certificate is
// self-signed, so verification is off; the tests check the server's behaviour, not the PKI.
func benchClientConfig() *gotls.Config {
	return &gotls.Config{ServerName: "localhost", InsecureSkipVerify: true} // #nosec G402 test only
}

// BenchmarkTLSServerHandshake measures one server handshake per op over an in-memory pipe.
// "bare" is crypto/tls alone. "wrapper" is Server of this package. "wrapper-no-recorder" is the
// same wrapper without the recorder (the code before the recorder was added), so the cost of the
// recorder is "wrapper" minus "wrapper-no-recorder", measured in the same process and window.
func BenchmarkTLSServerHandshake(b *testing.B) {
	cfg := benchServerConfig(b)
	for _, mode := range []string{"bare", "wrapper", "wrapper-no-recorder"} {
		b.Run(mode, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				cs, ss := net.Pipe()
				errc := make(chan error, 1)
				go func() {
					c := gotls.Client(cs, benchClientConfig())
					errc <- c.Handshake()
				}()
				var srv net.Conn
				switch mode {
				case "bare":
					srv = gotls.Server(ss, cfg)
				case "wrapper":
					srv = Server(ss, cfg)
				default:
					srv = &Conn{Conn: gotls.Server(ss, cfg), socket: ss}
				}
				err := srv.(interface{ Handshake() error }).Handshake()
				cerr := <-errc
				// Close the pipe, not srv: a TLS Close waits for a close_notify that the
				// idle peer never reads (5 s in crypto/tls, 250 ms in this package).
				cs.Close()
				ss.Close()
				if err != nil || cerr != nil {
					b.Fatalf("handshake: server %v, client %v", err, cerr)
				}
			}
		})
	}
}
