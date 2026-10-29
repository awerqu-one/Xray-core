//go:build unix

package raywire

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
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
			srv := newProbeServer(t, decoy)
			srv.relay = newAdmission(1, maxRelaysPerIP)
			if _, ok := srv.relay.TryAcquire("127.0.0.1"); !ok {
				t.Fatal("new relay pool has no free slot")
			}
			return srv
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

// TestCloseAfterRelayDrainFINBehindChainPastLimit checks that the relay's close
// still drains a wrapper chain longer than maxUnwrap. The walk to the socket
// gives up at the limit, so the only way to empty the queue is to read through
// the chain, which is what the relay has done all along. Without that read the
// queued bytes remain and the close sends a reset.
func TestCloseAfterRelayDrainFINBehindChainPastLimit(t *testing.T) {
	server, prober := tcpPair(t)
	var wrapped net.Conn = server
	for range maxUnwrap + 1 {
		wrapped = tlsdrainNetConnStub{Conn: wrapped}
	}
	if _, ok := rawSocket(wrapped); ok {
		t.Fatal("rawSocket found the socket of a chain past the depth limit")
	}
	if _, err := prober.Write([]byte("queued bytes")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	closeAfterRelayDrain(wrapped)
	requireFIN(t, prober)
}

// relayDrainBlockedWrite blocks every write of the relay to the decoy until the
// connection is closed, so the bytes the relay has not read yet stay queued in
// the prober's socket when the relay closes it.
type relayDrainBlockedWrite struct {
	net.Conn
	started chan<- struct{}
	closed  chan struct{}
	once    sync.Once
}

func (c *relayDrainBlockedWrite) Write([]byte) (int, error) {
	select {
	case c.started <- struct{}{}:
	default:
	}
	<-c.closed
	return 0, net.ErrClosed
}

func (c *relayDrainBlockedWrite) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// TestRelayCloseDrainsChainPastLimit checks that relayToDecoy uses the
// read-through drain when the prober has no CloseWrite and its wrapper chain is
// longer than maxUnwrap. The prober's late bytes are still queued when the
// decoy's output ends, so a close that does not read them would reset the
// connection instead of sending FIN.
func TestRelayCloseDrainsChainPastLimit(t *testing.T) {
	setRelayTimers(t, 200*time.Millisecond, time.Minute)

	halfClose := make(chan struct{})
	dest := startDecoy(t, func(c net.Conn) {
		if _, err := c.Write([]byte("bye")); err != nil {
			return
		}
		select {
		case <-halfClose:
		case <-time.After(5 * time.Second):
			return
		}
		c.(*net.TCPConn).CloseWrite()
		io.ReadAll(c)
	})

	writing := make(chan struct{}, 1)
	oldDial := dialDecoy
	dialDecoy = func(ctx context.Context, d xnet.Destination, sc *internet.SocketConfig) (net.Conn, error) {
		c, err := internet.DialSystem(ctx, d, sc)
		if err != nil {
			return nil, err
		}
		return &relayDrainBlockedWrite{Conn: c, started: writing, closed: make(chan struct{})}, nil
	}
	t.Cleanup(func() { dialDecoy = oldDial })

	tcp, external := tcpPair(t)
	var prober net.Conn = tcp
	for range maxUnwrap + 1 {
		prober = tlsdrainNetConnStub{Conn: prober}
	}
	if _, ok := rawSocket(prober); ok {
		t.Fatal("rawSocket found the socket of a chain past the depth limit")
	}
	// The relay reads one buffer and then blocks on the decoy, so the rest of
	// these bytes is queued when the prober is closed.
	if _, err := external.Write(make([]byte, 2*buf.Size)); err != nil {
		t.Fatal(err)
	}
	done := startRelay(prober, nil, dest)

	select {
	case <-writing:
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not read from the prober")
	}
	close(halfClose)

	if err := external.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	banner := make([]byte, len("bye"))
	if _, err := io.ReadFull(external, banner); err != nil {
		t.Fatalf("prober read: %v", err)
	}
	if string(banner) != "bye" {
		t.Fatalf("prober received %q, want %q", banner, "bye")
	}
	requireFIN(t, external)
	waitRelay(t, done, 2*time.Second)
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

// oneReaderConn fails the test if two goroutines read it at the same time.
// Wrapper transports such as WebSocket allow a single reader, so the relay's
// uplink copy and its read-through drain must never overlap.
type oneReaderConn struct {
	net.Conn
	reading atomic.Int32
	overlap atomic.Bool
}

func (c *oneReaderConn) Read(b []byte) (int, error) {
	if c.reading.Add(1) > 1 {
		c.overlap.Store(true)
	}
	defer c.reading.Add(-1)
	return c.Conn.Read(b)
}

// TestRelayDrainDoesNotReadConcurrently checks that the drain waits for the
// uplink copy. The prober keeps sending, so the copy is inside Read when the
// decoy's output ends.
func TestRelayDrainDoesNotReadConcurrently(t *testing.T) {
	setRelayTimers(t, 300*time.Millisecond, time.Minute)

	dest := startDecoy(t, func(c net.Conn) {
		if _, err := c.Write([]byte("bye")); err != nil {
			return
		}
		c.(*net.TCPConn).CloseWrite()
		io.ReadAll(c)
	})

	tcp, external := tcpPair(t)
	one := &oneReaderConn{Conn: tcp}
	var prober net.Conn = one
	for range maxUnwrap + 1 {
		prober = tlsdrainNetConnStub{Conn: prober}
	}
	if _, ok := rawSocket(prober); ok {
		t.Fatal("rawSocket found the socket of a chain past the depth limit")
	}

	// Keep the prober talking so the uplink copy stays in Read.
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := external.Write([]byte("probe")); err != nil {
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()
	done := startRelay(prober, nil, dest)
	waitRelay(t, done, 3*time.Second)
	close(stop)

	if one.overlap.Load() {
		t.Fatal("the drain read the prober while the uplink copy was reading it")
	}
}

// deadlineConn is a net.Conn that honors read deadlines the way a socket does:
// a read with an expired deadline returns os.ErrDeadlineExceeded without
// taking any buffered byte.
type deadlineConn struct {
	net.Conn
	mu      sync.Mutex
	pending []byte
	readBy  time.Time
}

func (c *deadlineConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readBy = t
	c.mu.Unlock()
	return nil
}

func (c *deadlineConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.readBy.IsZero() && !time.Now().Before(c.readBy) {
		return 0, os.ErrDeadlineExceeded
	}
	if len(c.pending) == 0 {
		return 0, io.EOF
	}
	n := copy(b, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *deadlineConn) remaining() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.pending)
}

// TestDrainRearmsDeadlineAfterGate checks that the drain still reads after it
// waited for the uplink copy. While the copy sits in Read it holds the gate,
// and the deadline that wakes it expires at the same moment, so a drain that
// armed its deadline once would read with an already-expired deadline, discard
// nothing, and leave the queued probe bytes to turn the close into a reset.
func TestDrainRearmsDeadlineAfterGate(t *testing.T) {
	setRelayTimers(t, 300*time.Millisecond, time.Minute)

	conn := &deadlineConn{pending: []byte("probe that must be discarded")}
	gate := &proberReads{}

	// Hold the gate for longer than one drain budget, as the uplink copy does
	// while it is blocked in Read.
	gate.mu.Lock()
	go func() {
		time.Sleep(3 * relayDrainWait)
		gate.mu.Unlock()
	}()

	drainThroughGated(conn, gate)

	if left := conn.remaining(); left != 0 {
		t.Fatalf("%d queued bytes left after the drain: the close would reset the prober", left)
	}
}
