//go:build unix

package raywire

import (
	"context"
	ctls "crypto/tls"
	"fmt"
	"net"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	xreality "github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
)

// tlsdrainNetConnStub stands in for a TLS or REALITY connection: it wraps a connection
// and exposes it through NetConn, which is the accessor both real types have.
type tlsdrainNetConnStub struct{ net.Conn }

func (s tlsdrainNetConnStub) NetConn() net.Conn { return s.Conn }

// tlsdrainLoop returns itself from NetConn, so a walk through it never reaches a socket.
type tlsdrainLoop struct{ net.Conn }

func (l *tlsdrainLoop) NetConn() net.Conn { return l }

// tlsdrainJunk is the queued data that a probe leaves before the server decides.
func tlsdrainJunk() []byte {
	return []byte(strings.Repeat("x", 50))
}

// TestDrainFINBehindTLSWrapper checks that a close under security:tls drains the
// socket before it closes. The probe's bytes are queued and the TLS layer has not
// read them, so a close without a drain resets the connection.
func TestDrainFINBehindTLSWrapper(t *testing.T) {
	cfg := &ctls.Config{Certificates: []ctls.Certificate{selfSignedCert(t)}}
	for _, n := range []int{1, 50, 100} {
		t.Run(fmt.Sprintf("%d bytes", n), func(t *testing.T) {
			server, prober := tcpPair(t)
			if _, err := prober.Write(randomHead(t, n)); err != nil {
				t.Fatal(err)
			}
			time.Sleep(20 * time.Millisecond)
			closeAfterDrain(xtls.Server(server, cfg))
			requireFIN(t, prober)
		})
	}
}

// TestDrainFINBehindTLSAfterHandshake checks the same close when the TLS handshake
// has completed. The junk is written after the handshake, so the TLS layer has not
// buffered it, and the close sends close_notify before the FIN.
func TestDrainFINBehindTLSAfterHandshake(t *testing.T) {
	server, prober := tcpPair(t)
	serverCfg := &ctls.Config{Certificates: []ctls.Certificate{selfSignedCert(t)}}
	hsDone := make(chan struct{})
	clientHS := make(chan error, 1)
	clientWrite := make(chan error, 1)
	go func() {
		c := ctls.Client(prober, &ctls.Config{InsecureSkipVerify: true})
		err := c.Handshake()
		clientHS <- err
		if err != nil {
			return
		}
		<-hsDone
		_, err = prober.Write(tlsdrainJunk())
		clientWrite <- err
	}()

	wrapped := xtls.Server(server, serverCfg)
	if err := wrapped.(xtls.Interface).HandshakeContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-clientHS; err != nil {
		t.Fatal(err)
	}
	close(hsDone)
	if err := <-clientWrite; err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	closeAfterDrain(wrapped)
	requireFIN(t, prober)
}

// TestDrainFINBehindNetConnAccessor checks a connection whose NetConn accessor leads
// to the socket, as REALITY's does. The drain must follow the accessor.
func TestDrainFINBehindNetConnAccessor(t *testing.T) {
	server, prober := tcpPair(t)
	if _, err := prober.Write(tlsdrainJunk()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	closeAfterDrain(tlsdrainNetConnStub{Conn: server})
	requireFIN(t, prober)
}

// TestRealREALITYConnHasNetConn checks that the REALITY connection type of the
// transport layer has the NetConn accessor that rawSocket follows.
func TestRealREALITYConnHasNetConn(t *testing.T) {
	var c net.Conn = &xreality.Conn{}
	if _, ok := c.(netConner); !ok {
		t.Fatal("transport REALITY conn has no NetConn accessor")
	}
	var u net.Conn = &xtls.Conn{}
	if _, ok := u.(netConner); !ok {
		t.Fatal("transport TLS conn has no NetConn accessor")
	}
}

// TestRawSocketWalk checks where rawSocket stops: at a socket, at a pipe, at the
// depth limit and on a loop.
func TestRawSocketWalk(t *testing.T) {
	server, _ := tcpPair(t)

	var c net.Conn = server
	for range 3 {
		c = tlsdrainNetConnStub{Conn: c}
	}
	sc, ok := rawSocket(c)
	if !ok || sc != syscall.Conn(server) {
		t.Fatalf("three accessors: ok=%v, want the socket", ok)
	}

	var counted net.Conn = &stat.CounterConnection{Connection: tlsdrainNetConnStub{Conn: server}}
	if _, ok := rawSocket(counted); !ok {
		t.Fatal("stats wrapper over an accessor: no socket found")
	}

	var deep net.Conn = server
	for range maxUnwrap - 1 {
		deep = tlsdrainNetConnStub{Conn: deep}
	}
	if _, ok := rawSocket(deep); !ok {
		t.Fatalf("%d accessors (the limit minus one): no socket found", maxUnwrap-1)
	}
	var tooDeep net.Conn = server
	for range maxUnwrap + 1 {
		tooDeep = tlsdrainNetConnStub{Conn: tooDeep}
	}
	if _, ok := rawSocket(tooDeep); ok {
		t.Fatal("a chain past the depth limit reached a socket")
	}

	loop := &tlsdrainLoop{}
	if _, ok := rawSocket(loop); ok {
		t.Fatal("a loop reached a socket")
	}

	p1, p2 := net.Pipe()
	defer p1.Close()
	defer p2.Close()
	if _, ok := rawSocket(p1); ok {
		t.Fatal("a pipe reached a socket")
	}
}

// tlsdrainSetWindow shortens the summary window for one test.
func tlsdrainSetWindow(t *testing.T, d time.Duration) {
	t.Helper()
	old := headFailWindow
	headFailWindow = d
	t.Cleanup(func() { headFailWindow = old })
}

// tlsdrainFail sends one probe that fails the head check with reason tag.
func tlsdrainFail(t *testing.T, srv *Server) {
	t.Helper()
	o := probeViaServer(t, srv, randomHead(t, hsHeadLen))
	if reason := reasonOf(o.serverErr); reason != "tag" {
		t.Fatalf("decision = %v, want reason tag", o.serverErr)
	}
}

// tlsdrainSummaries returns the summary lines that have been logged.
func tlsdrainSummaries(logs *logCapture) []string {
	var out []string
	for _, line := range logs.lines() {
		if strings.Contains(line, "first messages failed the head check") {
			out = append(out, line)
		}
	}
	return out
}

// tlsdrainWaitFor polls cond until it holds or the timeout ends.
func tlsdrainWaitFor(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestSummaryLogsBurstWithoutLaterFailure checks that a burst is logged by the
// window's own timer, with no later failure, and that an idle window logs nothing.
func TestSummaryLogsBurstWithoutLaterFailure(t *testing.T) {
	tlsdrainSetWindow(t, 400*time.Millisecond)
	logs := captureLogs(t)
	srv := newProbeServer(t, xnet.Destination{})

	for range 5 {
		tlsdrainFail(t, srv)
	}
	if n := len(tlsdrainSummaries(logs)); n != 0 {
		t.Fatalf("%d summary lines before the window ends, want none", n)
	}
	if !tlsdrainWaitFor(3*time.Second, func() bool { return len(tlsdrainSummaries(logs)) == 1 }) {
		t.Fatalf("no summary line after the burst stopped; lines %q", tlsdrainSummaries(logs))
	}
	if line := tlsdrainSummaries(logs)[0]; !strings.Contains(line, "raywire: 5 first messages") {
		t.Fatalf("summary %q, want the count 5", line)
	}

	// An idle window logs nothing.
	time.Sleep(3 * headFailWindow)
	if n := len(tlsdrainSummaries(logs)); n != 1 {
		t.Fatalf("%d summary lines after an idle window, want 1", n)
	}

	// The next burst gets its own line with its own count.
	for range 2 {
		tlsdrainFail(t, srv)
	}
	if !tlsdrainWaitFor(3*time.Second, func() bool { return len(tlsdrainSummaries(logs)) == 2 }) {
		t.Fatalf("no second summary line; lines %q", tlsdrainSummaries(logs))
	}
	if line := tlsdrainSummaries(logs)[1]; !strings.Contains(line, "raywire: 2 first messages") {
		t.Fatalf("second summary %q, want the count 2", line)
	}
}

// TestSummaryStopsOnClose checks that Close stops the pending timer, drops the
// count, and leaves a failure after Close uncounted.
func TestSummaryStopsOnClose(t *testing.T) {
	tlsdrainSetWindow(t, 200*time.Millisecond)
	logs := captureLogs(t)
	srv := newProbeServer(t, xnet.Destination{})

	for range 3 {
		tlsdrainFail(t, srv)
	}
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(4 * headFailWindow)
	if n := len(tlsdrainSummaries(logs)); n != 0 {
		t.Fatalf("%d summary lines after Close, want none", n)
	}
	tlsdrainFail(t, srv)
	time.Sleep(4 * headFailWindow)
	if n := len(tlsdrainSummaries(logs)); n != 0 {
		t.Fatalf("%d summary lines for a failure after Close, want none", n)
	}
	srv.headFails.mu.Lock()
	timer, count := srv.headFails.timer, srv.headFails.count
	srv.headFails.mu.Unlock()
	if timer != nil || count != 0 {
		t.Fatalf("after Close the log holds timer=%v count=%d, want none", timer != nil, count)
	}
}

// TestSummaryHoldsNoGoroutine checks that the summary holds no goroutine while a
// window is open, and that the goroutine that runs at the window's end exits.
func TestSummaryHoldsNoGoroutine(t *testing.T) {
	tlsdrainSetWindow(t, 100*time.Millisecond)
	captureLogs(t)
	srv := newProbeServer(t, xnet.Destination{})

	// Let earlier goroutines of the test binary finish, so the baseline is steady.
	time.Sleep(50 * time.Millisecond)
	base := runtime.NumGoroutine()

	for range 3 {
		tlsdrainFail(t, srv)
	}
	if !tlsdrainWaitFor(2*time.Second, func() bool { return runtime.NumGoroutine() <= base }) {
		t.Fatalf("%d goroutines with a window open, want at most the baseline %d", runtime.NumGoroutine(), base)
	}
	// The window ends after 100 ms. Its goroutine must be gone afterwards.
	time.Sleep(300 * time.Millisecond)
	if !tlsdrainWaitFor(2*time.Second, func() bool { return runtime.NumGoroutine() <= base }) {
		t.Fatalf("%d goroutines after the window ended, want at most the baseline %d", runtime.NumGoroutine(), base)
	}
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestPayloadAtMinimumRemainderIsAccepted checks the boundary that the removed
// payload check used to cover. A remainder of hsMinN1 bytes carries a payload of
// exactly timestampSize, so it passes the length rule and reaches the replay rule.
func TestPayloadAtMinimumRemainderIsAccepted(t *testing.T) {
	serverKey, clientKey := newKey(t), newKey(t)
	msg := craftMsg1(t, clientKey, serverKey.Public, prologue, testPSK, make([]byte, timestampSize))
	if len(msg) != hsHeadLen+hsMinN1 {
		t.Fatalf("msg1 is %d bytes, want %d", len(msg), hsHeadLen+hsMinN1)
	}
	allowAll := func([]byte) bool { return true }
	he, sc := decide(t, serverKey, allowAll, NewReplayFilter(), sendThenSentinel(msg))
	if he.Reason != "replay" {
		t.Fatalf("reason %q, want replay: a payload of %d bytes must pass the length rule", he.Reason, timestampSize)
	}
	expectSentinel(t, sc)
}

type tlsdrainRawStub struct{ net.Conn }

func (s tlsdrainRawStub) Raw() net.Conn { return s.Conn }

// The proxy protocol wrapper exposes the connection under it through Raw.
func TestRawSocketFollowsRaw(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, ok := rawSocket(tlsdrainRawStub{c}); !ok {
		t.Fatal("rawSocket did not follow Raw to the socket")
	}
	if _, ok := rawSocket(tlsdrainRawStub{tlsdrainRawStub{nil}}); ok {
		t.Fatal("rawSocket found a socket in a chain that ends in nil")
	}
}
