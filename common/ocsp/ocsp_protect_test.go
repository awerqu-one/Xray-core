package ocsp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet"
)

func TestOCSPDialProtectsBeforeRequest(t *testing.T) {
	if http.DefaultClient.Transport != nil || ocspHTTP == http.DefaultClient || ocspHTTP.Transport == nil || ocspHTTP.Transport == http.DefaultTransport {
		t.Fatal("OCSP client uses the default HTTP client")
	}
	if ocspHTTP.Timeout != 0 {
		t.Fatalf("OCSP client timeout = %s, want none", ocspHTTP.Timeout)
	}
	tr, ok := ocspHTTP.Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig != nil || !tr.ForceAttemptHTTP2 || tr.TLSHandshakeTimeout != 10*time.Second {
		t.Fatal("OCSP transport does not keep default TLS behavior")
	}

	gotReq := make(chan struct{}, 1)
	var hitMu sync.Mutex
	var hits []string
	record := func(name string) {
		hitMu.Lock()
		hits = append(hits, name)
		hitMu.Unlock()
		select {
		case gotReq <- struct{}{}:
		default:
		}
	}

	// The handler reads issuerDER when the request arrives. The variable is
	// assigned before GetOCSPForCert dials.
	var issuerDER []byte
	issuerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record("issuer")
		_, _ = w.Write(issuerDER)
	}))
	t.Cleanup(issuerSrv.Close)
	ocspSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record("ocsp")
		_, _ = w.Write([]byte("ocsp-staple"))
	}))
	t.Cleanup(ocspSrv.Close)

	leafDER, gotIssuer := newOCSPTestCerts(t, issuerSrv.URL, ocspSrv.URL)
	issuerDER = gotIssuer

	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()

	var dialMu sync.Mutex
	var dials []string
	remove, err := internet.AddDialerController(func(network, address string, c syscall.RawConn) error {
		if err := c.Control(func(fd uintptr) {
			if fd == 0 {
				t.Errorf("protect saw fd 0 for %s %s", network, address)
			}
		}); err != nil {
			return err
		}
		if network != "tcp4" && network != "tcp6" {
			t.Errorf("protect network = %s, want tcp4 or tcp6", network)
		}
		dialMu.Lock()
		dials = append(dials, address)
		dialMu.Unlock()
		once.Do(func() { close(entered) })
		<-release
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer remove()

	type result struct {
		body []byte
		err  error
	}
	errCh := make(chan result, 1)
	go func() {
		body, err := GetOCSPForCert([][]byte{leafDER})
		errCh <- result{body, err}
	}()

	select {
	case <-entered:
	case res := <-errCh:
		t.Fatalf("OCSP finished before protect: %v", res.err)
	case <-time.After(2 * time.Second):
		t.Fatal("protect controller was not called")
	}
	select {
	case <-gotReq:
		t.Fatal("HTTP request sent before protect controller returned")
	case <-time.After(50 * time.Millisecond):
	}
	unblock()

	var res result
	select {
	case res = <-errCh:
		if res.err != nil {
			t.Fatal(res.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OCSP fetch did not return after protect")
	}
	if !bytes.Equal(res.body, []byte("ocsp-staple")) {
		t.Fatalf("OCSP body = %q", res.body)
	}
	hitMu.Lock()
	gotHits := slices.Clone(hits)
	hitMu.Unlock()
	if !slices.Contains(gotHits, "issuer") || !slices.Contains(gotHits, "ocsp") {
		t.Fatalf("requests = %v, want issuer and ocsp", gotHits)
	}

	dialMu.Lock()
	defer dialMu.Unlock()
	if !slices.Contains(dials, hostport(t, issuerSrv.URL)) || !slices.Contains(dials, hostport(t, ocspSrv.URL)) {
		t.Fatalf("protected dials = %v, want %s and %s", dials, issuerSrv.URL, ocspSrv.URL)
	}
	if http.DefaultClient.Transport != nil {
		t.Fatal("http.DefaultClient.Transport was mutated")
	}
}

func TestOCSPDialProtectErrorFailsRequest(t *testing.T) {
	gotReq := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case gotReq <- struct{}{}:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	leafDER, _ := newOCSPTestCerts(t, srv.URL, srv.URL)
	remove, err := internet.AddDialerController(func(string, string, syscall.RawConn) error {
		return errors.New("protect Android VPN socket failed")
	})
	if err != nil {
		t.Fatal(err)
	}
	defer remove()

	start := time.Now()
	_, err = GetOCSPForCert([][]byte{leafDER})
	if err == nil {
		t.Fatal("OCSP fetch succeeded although protect failed")
	}
	if time.Since(start) > time.Second {
		t.Fatalf("protect failure waited on a dial: %s", time.Since(start))
	}
	if !strings.Contains(err.Error(), "failed to apply external controller") || !strings.Contains(err.Error(), "protect Android VPN socket failed") {
		t.Fatalf("protect error = %v", err)
	}
	select {
	case <-gotReq:
		t.Fatal("HTTP request sent after protect failed")
	case <-time.After(50 * time.Millisecond):
	}
	if http.DefaultClient.Transport != nil {
		t.Fatal("http.DefaultClient.Transport was mutated")
	}
}

func hostport(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

func newOCSPTestCerts(t *testing.T, issuerURL, ocspURL string) (leafDER, issuerDER []byte) {
	t.Helper()
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ocsp-test-issuer"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	issuerDER, err = x509.CreateCertificate(rand.Reader, issuerTmpl, issuerTmpl, issuerKey.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "ocsp-test-leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		OCSPServer:            []string{ocspURL},
		IssuingCertificateURL: []string{issuerURL},
	}
	leafDER, err = x509.CreateCertificate(rand.Reader, leafTmpl, issuer, leafKey.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	return leafDER, issuerDER
}
