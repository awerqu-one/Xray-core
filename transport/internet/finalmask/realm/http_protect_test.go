package realm

import (
	"context"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func TestRealmHTTPDialProtectsBeforeRequest(t *testing.T) {
	for _, scheme := range []string{"http", "https"} {
		t.Run(scheme, func(t *testing.T) {
			gotReq := make(chan struct{}, 1)
			srv := newRealmTestServer(t, scheme, func(w http.ResponseWriter, r *http.Request) {
				select {
				case gotReq <- struct{}{}:
				default:
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"addresses":["127.0.0.1:1"],"nonce":"n","obfs":"o"}`))
			})

			entered := make(chan struct{})
			release := make(chan struct{})
			var once sync.Once
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			defer unblock()

			var mu sync.Mutex
			var networks []string
			remove, err := internet.AddDialerController(func(network, address string, c syscall.RawConn) error {
				if err := c.Control(func(fd uintptr) {
					if fd == 0 {
						t.Errorf("protect saw fd 0 for %s %s", network, address)
					}
				}); err != nil {
					return err
				}
				host, _, splitErr := net.SplitHostPort(address)
				if splitErr != nil || host != srv.host {
					t.Errorf("protect address = %s, want host %s", address, srv.host)
				}
				mu.Lock()
				networks = append(networks, network)
				mu.Unlock()
				once.Do(func() { close(entered) })
				<-release
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			defer remove()

			client := NewClient(srv.scheme, srv.host, srv.port, "token", srv.tls)
			errCh := make(chan error, 1)
			go func() {
				_, err := client.Connect(context.Background(), "realm", ConnectRequest{})
				errCh <- err
			}()

			select {
			case <-entered:
			case err := <-errCh:
				t.Fatalf("request finished before protect: %v", err)
			case <-time.After(2 * time.Second):
				t.Fatal("protect controller was not called")
			}
			select {
			case <-gotReq:
				t.Fatal("HTTP request sent before protect controller returned")
			case <-time.After(50 * time.Millisecond):
			}
			unblock()

			select {
			case err := <-errCh:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("request did not return after protect")
			}
			select {
			case <-gotReq:
			default:
				t.Fatal("server did not see the HTTP request")
			}
			mu.Lock()
			defer mu.Unlock()
			if len(networks) == 0 || (networks[0] != "tcp4" && networks[0] != "tcp6") {
				t.Fatalf("controller networks = %v, want tcp4 or tcp6", networks)
			}
		})
	}
}

func TestRealmHTTPDialProtectErrorFailsRequest(t *testing.T) {
	for _, scheme := range []string{"http", "https"} {
		t.Run(scheme, func(t *testing.T) {
			gotReq := make(chan struct{}, 1)
			srv := newRealmTestServer(t, scheme, func(w http.ResponseWriter, r *http.Request) {
				select {
				case gotReq <- struct{}{}:
				default:
				}
				w.WriteHeader(http.StatusOK)
			})
			remove, err := internet.AddDialerController(func(string, string, syscall.RawConn) error {
				return errors.New("protect Android VPN socket failed")
			})
			if err != nil {
				t.Fatal(err)
			}
			defer remove()

			client := NewClient(srv.scheme, srv.host, srv.port, "token", srv.tls)
			start := time.Now()
			_, err = client.Connect(context.Background(), "realm", ConnectRequest{})
			if err == nil {
				t.Fatal("request succeeded although protect failed")
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
		})
	}
}

type realmTestServer struct {
	scheme string
	host   string
	port   string
	tls    *tls.Config
}

func newRealmTestServer(t *testing.T, scheme string, handler http.HandlerFunc) *realmTestServer {
	t.Helper()
	var srv *httptest.Server
	if scheme == "https" {
		srv = httptest.NewTLSServer(handler)
	} else {
		srv = httptest.NewServer(handler)
	}
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	out := &realmTestServer{scheme: u.Scheme, host: host, port: port}
	if scheme == "https" {
		cert := srv.Certificate()
		if cert == nil {
			t.Fatal("tls test server has no certificate")
		}
		out.tls = &tls.Config{
			ServerName: "example.com",
			Certificate: []*tls.Certificate{{
				Usage:       tls.Certificate_AUTHORITY_VERIFY,
				Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
			}},
		}
	}
	return out
}
