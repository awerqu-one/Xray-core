package dns

import (
	"context"
	"errors"
	stdnet "net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

func TestQUICLocalDialProtectsBeforeUse(t *testing.T) {
	ln, err := stdnet.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan struct{}, 1)
	go func() {
		buf := make([]byte, 2048)
		for {
			_ = ln.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, _, err := ln.ReadFrom(buf)
			if err != nil {
				return
			}
			select {
			case got <- struct{}{}:
			default:
			}
		}
	}()

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

	udp := ln.LocalAddr().(*stdnet.UDPAddr)
	dest := net.UDPDestination(net.ParseAddress(udp.IP.String()), net.Port(udp.Port))
	s := &QUICNameServer{destination: &dest}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := s.openQUIC(ctx)
		done <- err
	}()

	select {
	case <-entered:
	case err := <-done:
		t.Fatalf("dial finished before protect: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("protect controller was not called")
	}
	select {
	case <-got:
		t.Fatal("UDP packet sent before protect controller returned")
	case <-time.After(50 * time.Millisecond):
	}
	unblock()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("dial did not return")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(networks) != 1 || networks[0] != "udp4" {
		t.Fatalf("controller networks = %v, want [udp4]", networks)
	}
}

func TestQUICLocalDialProtectError(t *testing.T) {
	remove, err := internet.AddDialerController(func(string, string, syscall.RawConn) error {
		return errors.New("protect Android VPN socket failed")
	})
	if err != nil {
		t.Fatal(err)
	}
	defer remove()

	dest := net.UDPDestination(net.ParseAddress("127.0.0.1"), 9)
	s := &QUICNameServer{destination: &dest}
	start := time.Now()
	_, err = s.openQUIC(context.Background())
	if err == nil {
		t.Fatal("dial succeeded although protect failed")
	}
	if time.Since(start) > time.Second {
		t.Fatalf("protect failure waited on a dial: %s", time.Since(start))
	}
	if !strings.Contains(err.Error(), "failed to apply external controller") || !strings.Contains(err.Error(), "protect Android VPN socket failed") {
		t.Fatalf("protect error = %v", err)
	}
}
