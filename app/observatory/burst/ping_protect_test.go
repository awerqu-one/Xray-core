package burst

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet"
)

func TestDirectPingDialProtectsBeforeRequest(t *testing.T) {
	if http.DefaultClient.Transport != nil {
		t.Fatal("http.DefaultClient.Transport was mutated")
	}
	gotReq := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case gotReq <- struct{}{}:
		default:
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	client := newDirectPingClient(srv.URL, 5*time.Second)
	if client.httpClient.Transport == nil || client.httpClient.Transport == http.DefaultTransport {
		t.Fatal("direct ping client uses the default transport")
	}
	if client.httpClient.Timeout != 5*time.Second {
		t.Fatalf("client timeout = %s", client.httpClient.Timeout)
	}
	tr, ok := client.httpClient.Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig != nil || !tr.ForceAttemptHTTP2 || tr.TLSHandshakeTimeout != 10*time.Second {
		t.Fatal("direct ping transport does not keep default TLS behavior")
	}

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
		if splitErr != nil || host != "127.0.0.1" {
			t.Errorf("protect address = %s, want 127.0.0.1", address)
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

	errCh := make(chan error, 1)
	go func() {
		_, err := client.MeasureDelay(http.MethodGet)
		errCh <- err
	}()

	select {
	case <-entered:
	case err := <-errCh:
		t.Fatalf("ping finished before protect: %v", err)
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
		t.Fatal("ping did not return after protect")
	}
	select {
	case <-gotReq:
	default:
		t.Fatal("server did not see the ping request")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(networks) == 0 || (networks[0] != "tcp4" && networks[0] != "tcp6") {
		t.Fatalf("controller networks = %v, want tcp4 or tcp6", networks)
	}
	if http.DefaultClient.Transport != nil {
		t.Fatal("http.DefaultClient.Transport was mutated")
	}
}

func TestDirectPingDialProtectErrorFailsRequest(t *testing.T) {
	gotReq := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case gotReq <- struct{}{}:
		default:
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	remove, err := internet.AddDialerController(func(string, string, syscall.RawConn) error {
		return errors.New("protect Android VPN socket failed")
	})
	if err != nil {
		t.Fatal(err)
	}
	defer remove()

	client := newDirectPingClient(srv.URL, 5*time.Second)
	start := time.Now()
	_, err = client.MeasureDelay(http.MethodGet)
	if err == nil {
		t.Fatal("ping succeeded although protect failed")
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
}
