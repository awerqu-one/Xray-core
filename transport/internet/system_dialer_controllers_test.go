package internet_test

import (
	"context"
	"errors"
	"net"
	"sync"
	"syscall"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

func listenLoopback(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	t.Cleanup(func() { l.Close() })
	return l
}

func dialLoopback(l net.Listener) error {
	port := xnet.Port(l.Addr().(*net.TCPAddr).Port)
	conn, err := (&internet.DefaultSystemDialer{}).Dial(context.Background(), nil, xnet.TCPDestination(xnet.LocalHostIP, port), nil)
	if err == nil {
		conn.Close()
	}
	return err
}

func TestDialerControllerErrorAbortsDial(t *testing.T) {
	l := listenLoopback(t)
	if err := dialLoopback(l); err != nil {
		t.Fatalf("dial without controller: %v", err)
	}
	remove, err := internet.AddDialerController(func(string, string, syscall.RawConn) error {
		return errors.New("bind failed")
	})
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	if err := dialLoopback(l); err == nil {
		t.Fatal("dial succeeded although the controller failed")
	}
	remove()
	if err := dialLoopback(l); err != nil {
		t.Fatalf("dial after removing the controller: %v", err)
	}
}

func TestDialerControllerRemoveIsExactAndRepeatable(t *testing.T) {
	base := len(internet.DialerControllers())
	var calls [3]int
	var removes [3]func()
	for i := range removes {
		i := i
		r, err := internet.AddDialerController(func(string, string, syscall.RawConn) error { calls[i]++; return nil })
		if err != nil {
			t.Fatal(err)
		}
		removes[i] = r
	}
	if got := len(internet.DialerControllers()); got != base+3 {
		t.Fatalf("controllers = %d, want %d", got, base+3)
	}
	removes[1]()
	removes[1]()
	if got := len(internet.DialerControllers()); got != base+2 {
		t.Fatalf("after removing the middle one: %d, want %d", got, base+2)
	}
	l := listenLoopback(t)
	if err := dialLoopback(l); err != nil {
		t.Fatal(err)
	}
	if calls[0] != 1 || calls[1] != 0 || calls[2] != 1 {
		t.Fatalf("calls = %v, want [1 0 1]", calls)
	}
	removes[0]()
	removes[2]()
	if got := len(internet.DialerControllers()); got != base {
		t.Fatalf("controllers left behind: %d, want %d", got, base)
	}
}

func TestDialerControllersConcurrent(t *testing.T) {
	l := listenLoopback(t)
	base := len(internet.DialerControllers())
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				r, err := internet.AddDialerController(func(string, string, syscall.RawConn) error { return nil })
				if err != nil {
					t.Error(err)
					return
				}
				if err := dialLoopback(l); err != nil {
					t.Error(err)
				}
				r()
			}
		}()
	}
	wg.Wait()
	if got := len(internet.DialerControllers()); got != base {
		t.Fatalf("controllers left behind: %d, want %d", got, base)
	}
}
