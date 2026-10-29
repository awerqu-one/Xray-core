package xicmp_test

import (
	"errors"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask/xicmp"
)

func TestXICMPListenProtectsBeforeUse(t *testing.T) {
	for _, dgram := range []bool{false, true} {
		dgram := dgram
		t.Run(map[bool]string{false: "raw", true: "dgram"}[dgram], func(t *testing.T) {
			if dgram {
				allowICMPEcho(t)
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

			dest := xnet.UDPDestination(xnet.ParseAddress("203.0.113.1"), 1)
			errCh := make(chan error, 1)
			go func() {
				conn, err := xicmp.NewConnClient(&xicmp.Config{DGRAM: dgram}, &dest)
				if conn != nil {
					conn.Close()
				}
				errCh <- err
			}()

			select {
			case <-entered:
			case err := <-errCh:
				if dgram && isPermission(err) {
					t.Skip(err)
				}
				t.Fatalf("listen finished before protect: %v", err)
			case <-time.After(2 * time.Second):
				t.Fatal("protect controller was not called")
			}

			select {
			case err := <-errCh:
				t.Fatalf("listen returned before protect finished: %v", err)
			default:
			}
			unblock()

			select {
			case err := <-errCh:
				if err != nil {
					if dgram && isPermission(err) {
						t.Skip(err)
					}
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("listen did not return after protect")
			}

			mu.Lock()
			defer mu.Unlock()
			want := []string{"ip4", "ip6"}
			if dgram {
				want = []string{"udp4", "udp6"}
			}
			if len(networks) != 2 || networks[0] != want[0] || networks[1] != want[1] {
				t.Fatalf("controller networks = %v, want %v", networks, want)
			}
		})
	}
}

func TestXICMPListenProtectErrorFailsDial(t *testing.T) {
	for _, failOn := range []int32{1, 2} {
		failOn := failOn
		t.Run(map[int32]string{1: "first", 2: "second"}[failOn], func(t *testing.T) {
			var calls int32
			var mu sync.Mutex
			remove, err := internet.AddDialerController(func(string, string, syscall.RawConn) error {
				mu.Lock()
				calls++
				n := calls
				mu.Unlock()
				if n == failOn {
					return errors.New("protect Android VPN socket failed")
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			defer remove()

			before := countFDs(t)
			dest := xnet.UDPDestination(xnet.ParseAddress("203.0.113.1"), 1)
			conn, err := xicmp.NewConnClient(&xicmp.Config{}, &dest)
			if conn != nil {
				conn.Close()
				t.Fatal("dial returned a socket after protect failed")
			}
			if err == nil {
				t.Fatal("dial succeeded although protect failed")
			}
			if !strings.Contains(err.Error(), "failed to apply external controller") || !strings.Contains(err.Error(), "protect Android VPN socket failed") {
				t.Fatalf("protect error = %v", err)
			}
			if got := countFDs(t); got > before {
				t.Fatalf("leaked fds after protect failure: before %d after %d", before, got)
			}
		})
	}
}

func allowICMPEcho(t *testing.T) {
	const path = "/proc/sys/net/ipv4/ping_group_range"
	old, err := os.ReadFile(path)
	if err != nil {
		return
	}
	if err := os.WriteFile(path, []byte("0 2147483647\n"), 0o644); err != nil {
		return
	}
	t.Cleanup(func() {
		_ = os.WriteFile(path, old, 0o644)
	})
}

func isPermission(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "permission denied") || strings.Contains(msg, "operation not permitted")
}

func countFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}
