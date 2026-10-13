package raywire

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// tcpPair returns both ends of a loopback TCP connection. The first end is the
// prober as the relay sees it. The test drives the second.
func tcpPair(t *testing.T) (relaySide, external *net.TCPConn) {
	t.Helper()
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type accepted struct {
		conn *net.TCPConn
		err  error
	}
	acc := make(chan accepted, 1)
	go func() {
		c, err := ln.AcceptTCP()
		acc <- accepted{c, err}
	}()

	external, err = net.DialTCP("tcp", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	a := <-acc
	if a.err != nil {
		external.Close()
		t.Fatal(a.err)
	}
	t.Cleanup(func() {
		external.Close()
		a.conn.Close()
	})
	return a.conn, external
}

// startDecoy serves one loopback connection with handle. The returned
// destination is what the relay dials.
func startDecoy(t *testing.T, handle func(c net.Conn)) xnet.Destination {
	t.Helper()
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.AcceptTCP()
		if err != nil {
			return
		}
		defer c.Close()
		handle(c)
	}()
	return xnet.DestinationFromAddr(ln.Addr())
}

// echo writes back every byte it reads until the connection fails.
func echo(c net.Conn) {
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			if _, werr := c.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// startRelay runs relayToDecoy in its own goroutine. The channel closes when
// the relay returns.
func startRelay(prober net.Conn, consumed []byte, dest xnet.Destination) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		relayToDecoy(context.Background(), prober, consumed, time.Now(), dest)
	}()
	return done
}

// waitRelay fails the test if the relay has not returned within limit.
func waitRelay(t *testing.T, done <-chan struct{}, limit time.Duration) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(limit):
		t.Fatal("relay did not return")
	}
}

// readAllWithin reads c to its end and fails the test after limit.
func readAllWithin(t *testing.T, c net.Conn, limit time.Duration) []byte {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(limit)); err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return b
}

// setRelayTimers shortens the relay limits for one test.
func setRelayTimers(t *testing.T, inactivity, life time.Duration) {
	t.Helper()
	oldInactivity, oldLife := relayInactivity, relayMaxLife
	relayInactivity, relayMaxLife = inactivity, life
	t.Cleanup(func() { relayInactivity, relayMaxLife = oldInactivity, oldLife })
}

// writeLog wraps the relay's connection to the decoy and records each write.
type writeLog struct {
	net.Conn
	mu     sync.Mutex
	writes [][]byte
}

func (w *writeLog) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.writes = append(w.writes, append([]byte(nil), p...))
	w.mu.Unlock()
	return w.Conn.Write(p)
}

func (w *writeLog) CloseWrite() error {
	return w.Conn.(closeWriter).CloseWrite()
}

// recordDecoyWrites makes the relay's decoy connection record its writes. The
// returned function reports them, and must be called after the relay returns.
func recordDecoyWrites(t *testing.T) func() [][]byte {
	t.Helper()
	old := dialDecoy
	var last atomic.Pointer[writeLog]
	dialDecoy = func(ctx context.Context, dest xnet.Destination, sc *internet.SocketConfig) (net.Conn, error) {
		c, err := internet.DialSystem(ctx, dest, sc)
		if err != nil {
			return nil, err
		}
		w := &writeLog{Conn: c}
		last.Store(w)
		return w, nil
	}
	t.Cleanup(func() { dialDecoy = old })
	return func() [][]byte {
		w := last.Load()
		w.mu.Lock()
		defer w.mu.Unlock()
		return w.writes
	}
}

// countDials replaces dialDecoy with one that fails and counts the attempts.
func countDials(t *testing.T, fail error) *atomic.Int32 {
	t.Helper()
	var n atomic.Int32
	old := dialDecoy
	dialDecoy = func(context.Context, xnet.Destination, *internet.SocketConfig) (net.Conn, error) {
		n.Add(1)
		return nil, fail
	}
	t.Cleanup(func() { dialDecoy = old })
	return &n
}

// plainProber hides CloseWrite, as the stat counters do, and counts Close.
type plainProber struct {
	net.Conn
	closes atomic.Int32
}

func (p *plainProber) Close() error {
	p.closes.Add(1)
	return p.Conn.Close()
}

// logCapture keeps every log message while it is registered.
type logCapture struct {
	mu   sync.Mutex
	msgs []string
}

func (c *logCapture) Handle(msg log.Message) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.msgs = append(c.msgs, msg.String())
}

func (c *logCapture) lines() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.msgs...)
}

type discardLog struct{}

func (discardLog) Handle(log.Message) {}

// captureLogs records log messages until the test ends.
func captureLogs(t *testing.T) *logCapture {
	t.Helper()
	// The decoy log limit is per process. Each test starts with a fresh one.
	decoyDownLog.mu.Lock()
	decoyDownLog.last = time.Time{}
	decoyDownLog.mu.Unlock()
	c := &logCapture{}
	log.RegisterHandler(c)
	t.Cleanup(func() { log.RegisterHandler(discardLog{}) })
	return c
}

func TestRelayDeliversConsumedThenStream(t *testing.T) {
	setRelayTimers(t, time.Second, time.Minute)
	writes := recordDecoyWrites(t)

	type decoyInput struct {
		in  []byte
		err error
	}
	seen := make(chan decoyInput, 1)
	dest := startDecoy(t, func(c net.Conn) {
		c.Write([]byte("banner;"))
		in, err := io.ReadAll(c)
		seen <- decoyInput{in, err}
		c.Write([]byte("tail"))
	})

	prober, external := tcpPair(t)
	done := startRelay(prober, []byte("consumed-"), dest)

	if _, err := external.Write([]byte("rest")); err != nil {
		t.Fatal(err)
	}
	if err := external.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got := readAllWithin(t, external, 2*time.Second)
	waitRelay(t, done, 2*time.Second)

	var in decoyInput
	select {
	case in = <-seen:
	case <-time.After(time.Second):
		t.Fatal("decoy did not finish")
	}
	// The end-of-stream must come from the prober's CloseWrite, not from the
	// relay closing the decoy, so the decoy reads a clean EOF.
	if in.err != nil {
		t.Fatalf("decoy read ended with %v, want a clean end of stream", in.err)
	}
	if string(in.in) != "consumed-rest" {
		t.Fatalf("decoy received %q, want %q", in.in, "consumed-rest")
	}
	if string(got) != "banner;tail" {
		t.Fatalf("prober received %q, want the decoy's output %q", got, "banner;tail")
	}
	if ws := writes(); len(ws) == 0 || string(ws[0]) != "consumed-" {
		t.Fatalf("first decoy write is %q, want the consumed bytes in one write", ws)
	}
	if n := relayAdm.pendingCount(); n != 0 {
		t.Fatalf("%d relay slots still held after the relay returned", n)
	}
}

func TestRelayEmptyConsumedSendsNoWrite(t *testing.T) {
	setRelayTimers(t, time.Second, time.Minute)
	writes := recordDecoyWrites(t)

	seen := make(chan []byte, 1)
	dest := startDecoy(t, func(c net.Conn) {
		in, _ := io.ReadAll(c)
		seen <- in
	})

	prober, external := tcpPair(t)
	done := startRelay(prober, nil, dest)
	if _, err := external.Write([]byte("rest")); err != nil {
		t.Fatal(err)
	}
	if err := external.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	readAllWithin(t, external, 2*time.Second)
	waitRelay(t, done, 2*time.Second)

	var in []byte
	select {
	case in = <-seen:
	case <-time.After(time.Second):
		t.Fatal("decoy did not finish")
	}
	if string(in) != "rest" {
		t.Fatalf("decoy received %q, want %q", in, "rest")
	}
	for i, w := range writes() {
		if len(w) == 0 {
			t.Fatalf("decoy write %d is empty; no write is wanted for empty consumed bytes", i)
		}
	}
}

func TestRelayHalfCloseWithoutCloseWriteClosesProber(t *testing.T) {
	setRelayTimers(t, time.Second, time.Minute)

	dest := startDecoy(t, func(c net.Conn) {
		c.Write([]byte("bye"))
		c.(*net.TCPConn).CloseWrite()
		io.ReadAll(c)
	})

	tcp, external := tcpPair(t)
	prober := &plainProber{Conn: tcp}
	done := startRelay(prober, nil, dest)

	// The decoy's output must reach the prober, and then the prober must see
	// the end, although the prober cannot half-close.
	got := readAllWithin(t, external, 2*time.Second)
	waitRelay(t, done, 2*time.Second)

	if string(got) != "bye" {
		t.Fatalf("prober received %q, want %q", got, "bye")
	}
	if prober.closes.Load() == 0 {
		t.Fatal("prober without CloseWrite was not closed after the decoy's output ended")
	}
}

// TestRelayHalfCloseThroughStatsWrapper checks that a prober wrapped by the stats
// counter gets the same half-close as a raw connection. The decoy answers, sends
// its FIN and keeps reading, as a lingering close does. A prober that writes
// after that FIN must not be reset, so the relay must not close it.
func TestRelayHalfCloseThroughStatsWrapper(t *testing.T) {
	for _, tc := range []struct {
		name string
		wrap bool
	}{
		{"raw", false},
		{"stats wrapped", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setRelayTimers(t, 5*time.Second, time.Minute)

			got := make(chan []byte, 1)
			dest := startDecoy(t, func(c net.Conn) {
				c.Write([]byte("bye"))
				c.(*net.TCPConn).CloseWrite()
				data, _ := io.ReadAll(c)
				got <- data
			})

			tcp, external := tcpPair(t)
			var prober net.Conn = tcp
			if tc.wrap {
				prober = &stat.CounterConnection{Connection: tcp}
			}
			done := startRelay(prober, nil, dest)

			if out := readAllWithin(t, external, 2*time.Second); string(out) != "bye" {
				t.Fatalf("prober received %q, want %q", out, "bye")
			}
			// Two writes after the decoy's FIN. A reset from the first one would
			// fail the second.
			for i := range 2 {
				if _, err := external.Write([]byte("late")); err != nil {
					t.Fatalf("write %d after the decoy's FIN: %v", i, err)
				}
				time.Sleep(100 * time.Millisecond)
			}
			if err := external.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			select {
			case data := <-got:
				if string(data) != "latelate" {
					t.Fatalf("decoy received %q after the FIN, want %q", data, "latelate")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("decoy did not see the end of the prober's stream")
			}
			waitRelay(t, done, 2*time.Second)
		})
	}
}

func TestRelayInactivityClosesBothSides(t *testing.T) {
	setRelayTimers(t, 200*time.Millisecond, time.Minute)

	decoyEnded := make(chan struct{})
	dest := startDecoy(t, func(c net.Conn) {
		io.ReadAll(c)
		close(decoyEnded)
	})

	prober, external := tcpPair(t)
	start := time.Now()
	done := startRelay(prober, []byte("x"), dest)
	waitRelay(t, done, 2*time.Second)

	// No byte moved, so the inactivity limit must be what ended the relay.
	if el := time.Since(start); el < 150*time.Millisecond {
		t.Fatalf("relay ended after %v, before the inactivity limit", el)
	}
	if err := external.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(external); isTimeout(err) {
		t.Fatal("prober was not closed by the relay")
	}
	select {
	case <-decoyEnded:
	case <-time.After(time.Second):
		t.Fatal("decoy was not closed by the relay")
	}
}

func TestRelayMaxLifeEndsBusyRelay(t *testing.T) {
	setRelayTimers(t, 5*time.Second, 300*time.Millisecond)

	dest := startDecoy(t, echo)
	prober, external := tcpPair(t)
	if err := external.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	go io.Copy(io.Discard, external)

	start := time.Now()
	done := startRelay(prober, nil, dest)

	// Traffic in both directions keeps the inactivity limit from firing, so
	// only the life limit can end the relay.
	chunk := make([]byte, 512)
	var writeErr error
	for writeErr == nil && time.Since(start) < 2*time.Second {
		_, writeErr = external.Write(chunk)
		time.Sleep(5 * time.Millisecond)
	}
	waitRelay(t, done, time.Second)

	if writeErr == nil {
		t.Fatal("prober still accepted writes after the relay's life limit")
	}
}

func TestRelayFullPoolClosesWithoutDial(t *testing.T) {
	oldAdm := relayAdm
	relayAdm = newAdmission(1, maxRelaysPerIP)
	t.Cleanup(func() { relayAdm = oldAdm })
	if _, ok := relayAdm.TryAcquire("198.51.100.99"); !ok {
		t.Fatal("new pool has no free slot")
	}

	dials := countDials(t, errors.New("unexpected dial"))
	dest := xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), 9)
	prober, external := tcpPair(t)
	done := startRelay(prober, []byte("x"), dest)

	waitRelay(t, done, time.Second)
	if n := dials.Load(); n != 0 {
		t.Fatalf("relay dialed the decoy %d times with a full pool", n)
	}
	if got := readAllWithin(t, external, time.Second); len(got) != 0 {
		t.Fatalf("prober received %q from a refused relay", got)
	}
}

func TestRelayDialFailureClosesProberAndLogsError(t *testing.T) {
	logs := captureLogs(t)
	dials := countDials(t, errors.New("connection refused"))
	dest := xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), 9)

	prober, external := tcpPair(t)
	done := startRelay(prober, []byte("hello"), dest)
	waitRelay(t, done, time.Second)

	if n := dials.Load(); n != 1 {
		t.Fatalf("relay dialed %d times, want 1", n)
	}
	if got := readAllWithin(t, external, time.Second); len(got) != 0 {
		t.Fatalf("prober received %q after a failed dial", got)
	}
	for _, m := range logs.lines() {
		if strings.Contains(m, "[Error]") && strings.Contains(m, "decoy unreachable") {
			return
		}
	}
	t.Fatalf("no error-level log for the failed dial in %q", logs.lines())
}

// TestRelayInactivityCountsBytesFromEitherSide checks that the relay ends exactly
// relayInactivity after the last byte, whichever side moved it. The decoy speaks
// early in the first limit, so the relay must count that byte and end a full limit
// after it, not a limit after its start. A timer that checks at fixed steps ends
// about two steps after the byte here, which the upper bound catches.
func TestRelayInactivityCountsBytesFromEitherSide(t *testing.T) {
	const limit = 300 * time.Millisecond
	setRelayTimers(t, limit, time.Minute)

	spoke := make(chan time.Time, 1)
	dest := startDecoy(t, func(c net.Conn) {
		time.Sleep(limit / 6)
		now := time.Now()
		c.Write([]byte("late"))
		spoke <- now
		io.ReadAll(c)
	})

	prober, external := tcpPair(t)
	done := startRelay(prober, nil, dest)
	waitRelay(t, done, 2*time.Second)
	ended := time.Now()

	var spokeAt time.Time
	select {
	case spokeAt = <-spoke:
	case <-time.After(time.Second):
		t.Fatal("decoy did not speak")
	}
	gap := ended.Sub(spokeAt)
	if gap < limit {
		t.Fatalf("relay ended %v after the last byte, before the inactivity limit %v", gap, limit)
	}
	if gap > limit+150*time.Millisecond {
		t.Fatalf("relay ended %v after the last byte, past the inactivity limit %v", gap, limit)
	}
	if got := readAllWithin(t, external, time.Second); string(got) != "late" {
		t.Fatalf("prober received %q, want %q", got, "late")
	}
}

// readStats records how a relay reads one connection: the largest Read it asks
// for, and the reads it makes through the raw connection. buf.NewReader reads a
// TCP connection through the raw connection with readv, which takes several
// buffers at once.
type readStats struct {
	maxRead  atomic.Int64
	rawReads atomic.Int64
}

// readSizer is a TCP connection that reports its reads to a readStats.
type readSizer struct {
	*net.TCPConn
	st *readStats
}

func (r *readSizer) Read(p []byte) (int, error) {
	if n := int64(len(p)); n > r.st.maxRead.Load() {
		r.st.maxRead.Store(n)
	}
	return r.TCPConn.Read(p)
}

func (r *readSizer) SyscallConn() (syscall.RawConn, error) {
	rc, err := r.TCPConn.SyscallConn()
	if err != nil {
		return nil, err
	}
	return countedRaw{RawConn: rc, st: r.st}, nil
}

// countedRaw counts the reads made through a raw connection.
type countedRaw struct {
	syscall.RawConn
	st *readStats
}

func (c countedRaw) Read(f func(uintptr) bool) error {
	c.st.rawReads.Add(1)
	return c.RawConn.Read(f)
}

// TestRelayMovesBytesThroughFixedBuffers checks that a relay reads each side into
// one buf.Size buffer: no Read asks for more, and no read goes through readv,
// which can take several buffers at once. A large stream must still arrive whole.
func TestRelayMovesBytesThroughFixedBuffers(t *testing.T) {
	setRelayTimers(t, time.Second, time.Minute)

	decoyStats, proberStats := &readStats{}, &readStats{}
	oldDial := dialDecoy
	dialDecoy = func(ctx context.Context, dest xnet.Destination, sc *internet.SocketConfig) (net.Conn, error) {
		c, err := internet.DialSystem(ctx, dest, sc)
		if err != nil {
			return nil, err
		}
		tc, ok := c.(*net.TCPConn)
		if !ok {
			c.Close()
			return nil, errors.New("decoy connection is not TCP")
		}
		return &readSizer{TCPConn: tc, st: decoyStats}, nil
	}
	t.Cleanup(func() { dialDecoy = oldDial })
	dest := startDecoy(t, echo)

	tcp, external := tcpPair(t)
	done := startRelay(&readSizer{TCPConn: tcp, st: proberStats}, nil, dest)

	payload := make([]byte, 1<<20)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	go func() {
		external.Write(payload)
		external.CloseWrite()
	}()
	got := readAllWithin(t, external, 5*time.Second)
	waitRelay(t, done, 5*time.Second)

	if !bytes.Equal(got, payload) {
		t.Fatalf("prober received %d bytes back, want the %d it sent", len(got), len(payload))
	}
	for name, st := range map[string]*readStats{"prober": proberStats, "decoy": decoyStats} {
		if n := st.maxRead.Load(); n == 0 || n > buf.Size {
			t.Fatalf("relay read %d bytes from the %s at once, want 1 to %d", n, name, buf.Size)
		}
		if n := st.rawReads.Load(); n != 0 {
			t.Fatalf("relay made %d readv reads from the %s, which can exceed one buffer", n, name)
		}
	}
}

// TestRelayPerSourceCapRefusesWithoutDial checks that one source address cannot
// take the whole relay pool. Its relays beyond the per-source cap are closed
// without a dial, while another source still gets a relay.
func TestRelayPerSourceCapRefusesWithoutDial(t *testing.T) {
	oldAdm := relayAdm
	relayAdm = newAdmission(maxRelays, 2)
	t.Cleanup(func() { relayAdm = oldAdm })

	const busy, other = "203.0.113.20", "198.51.100.7"
	for i := 0; i < 2; i++ {
		if _, ok := relayAdm.TryAcquire(busy); !ok {
			t.Fatalf("relay %d from %s refused below the per-source cap", i, busy)
		}
	}
	dials := countDials(t, errors.New("connection refused"))
	dest := xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), 9)

	tcp, external := tcpPair(t)
	refused := addrConn{Conn: tcp, addr: fixedAddr(busy + ":4000")}
	waitRelay(t, startRelay(refused, []byte("x"), dest), time.Second)
	if n := dials.Load(); n != 0 {
		t.Fatalf("relay dialed %d times for a source at its cap", n)
	}
	if got := readAllWithin(t, external, time.Second); len(got) != 0 {
		t.Fatalf("prober received %q from a refused relay", got)
	}

	tcp2, _ := tcpPair(t)
	allowed := addrConn{Conn: tcp2, addr: fixedAddr(other + ":4000")}
	waitRelay(t, startRelay(allowed, []byte("x"), dest), time.Second)
	if n := dials.Load(); n != 1 {
		t.Fatalf("relay from another source dialed %d times, want 1", n)
	}
	if n := relayAdm.pendingCount(); n != 2 {
		t.Fatalf("%d relay slots held after the relays ended, want the 2 taken for %s", n, busy)
	}
}

// isTimeout reports whether err is a network timeout.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
