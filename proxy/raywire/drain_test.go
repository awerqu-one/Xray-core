//go:build unix

package raywire

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
)

// requireFIN checks that a connection that the server closed ended with a FIN and not
// a reset. The prober waits, so that any reset has arrived, and then a write must
// succeed. After a reset, the write fails with ECONNRESET or EPIPE.
func requireFIN(t *testing.T, prober *net.TCPConn) {
	t.Helper()
	time.Sleep(100 * time.Millisecond)
	if _, err := prober.Write([]byte{0}); err != nil {
		t.Fatalf("write after the server closed = %v, want none: the close sent a reset", err)
	}
}

// TestDrainFIN checks that every close without a relay drains the queued bytes first.
// The probes are sent before the server closes, so a close that does not drain resets
// the connection. The drain is specified for Unix systems (R13), so the test is built
// only there; on other platforms the close is a plain Close. The four refusals are a full admission, a full relay pool, no decoy
// and a decoy that cannot be dialed.
func TestDrainFIN(t *testing.T) {
	setPreAuthTimeout(t, 200*time.Millisecond)
	decoy := xnet.DestinationFromAddr(startBannerDecoy(t))
	scenarios := []struct {
		name  string
		setup func(t *testing.T) *Server
	}{
		{"admission full", func(t *testing.T) *Server {
			srv := newProbeServer(t, decoy)
			fillAdmission(t, srv.adm, "127.0.0.1", maxPendingPerIP)
			return srv
		}},
		{"relay pool full", func(t *testing.T) *Server {
			oldAdm := relayAdm
			relayAdm = newAdmission(1, maxRelaysPerIP)
			t.Cleanup(func() { relayAdm = oldAdm })
			if _, ok := relayAdm.TryAcquire("127.0.0.1"); !ok {
				t.Fatal("new relay pool has no free slot")
			}
			return newProbeServer(t, decoy)
		}},
		{"no decoy", func(t *testing.T) *Server {
			return newProbeServer(t, xnet.Destination{})
		}},
		{"decoy dial fails", func(t *testing.T) *Server {
			countDials(t, errors.New("connection refused"))
			return newProbeServer(t, decoy)
		}},
	}
	for _, sc := range scenarios {
		for _, n := range []int{1, 34, 49, 50, 51, 100} {
			t.Run(fmt.Sprintf("%s, %d bytes", sc.name, n), func(t *testing.T) {
				srv := sc.setup(t)
				server, prober := tcpPair(t)
				if _, err := prober.Write(randomHead(t, n)); err != nil {
					t.Fatal(err)
				}
				// The bytes are queued at the server before it decides.
				time.Sleep(20 * time.Millisecond)

				done := make(chan error, 1)
				go func() {
					_, err := srv.handlePreAuth(context.Background(), server, srv.pad)
					done <- err
				}()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("pre-auth stage did not return")
				}
				requireFIN(t, prober)
			})
		}
	}
}

// TestDrainIgnoresDeadline checks that a read deadline in the past does not stop the
// drain. Go returns at once from a read with a past deadline, and the drain must
// still discard the queued bytes so that the close sends a FIN.
func TestDrainIgnoresDeadline(t *testing.T) {
	server, prober := tcpPair(t)
	if _, err := prober.Write([]byte("queued bytes")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if err := server.SetDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	closeAfterDrain(server)
	requireFIN(t, prober)
}
