package tls

import (
	"bytes"
	"crypto/rand"
	gotls "crypto/tls"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
)

// recSilentDeadline ends a handshake that the peer leaves open.
const recSilentDeadline = 300 * time.Millisecond

// recPair returns the two ends of a loopback TCP connection. srv is the accepted end.
func recPair(t testing.TB) (srv, cli net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			close(ch)
			return
		}
		ch <- c
	}()
	cli, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	srv, ok := <-ch
	if !ok {
		cli.Close()
		t.Fatal("accept failed")
	}
	t.Cleanup(func() {
		srv.Close()
		cli.Close()
	})
	return srv, cli
}

// recServer returns the wrapper of sock as a *Conn.
func recServer(t testing.TB, sock net.Conn, cfg *gotls.Config) *Conn {
	t.Helper()
	c, ok := Server(sock, cfg).(*Conn)
	if !ok {
		t.Fatal("Server does not return *Conn")
	}
	return c
}

// recClientConn returns a crypto/tls client on cli with the given maximum version (0 is the default).
func recClientConn(cli net.Conn, maxVersion uint16) *gotls.Conn {
	cfg := benchClientConfig()
	cfg.MaxVersion = maxVersion
	return gotls.Client(cli, cfg)
}

// recHandshake runs the handshake of cc in its own goroutine and returns the result channel.
func recHandshake(cc *gotls.Conn) <-chan error {
	ch := make(chan error, 1)
	go func() { ch <- cc.Handshake() }()
	return ch
}

// recCaptureHello returns the bytes that a crypto/tls client writes for its first flight. The
// client gets no reply: its first read fails.
func recCaptureHello(t testing.TB, maxVersion uint16) []byte {
	t.Helper()
	cw := &recCaptureConn{}
	if err := recClientConn(cw, maxVersion).Handshake(); err == nil {
		t.Fatal("client handshake with no reply succeeded")
	}
	if len(cw.written) == 0 {
		t.Fatal("client wrote no ClientHello")
	}
	return cw.written
}

// recCaptureConn is a net.Conn that records what is written and reads nothing. The client
// handshake calls only Read, Write and Close on it.
type recCaptureConn struct {
	net.Conn
	written []byte
}

func (c *recCaptureConn) Read([]byte) (int, error) { return 0, io.EOF }
func (c *recCaptureConn) Write(p []byte) (int, error) {
	c.written = append(c.written, p...)
	return len(p), nil
}
func (c *recCaptureConn) Close() error                     { return nil }
func (c *recCaptureConn) LocalAddr() net.Addr              { return nil }
func (c *recCaptureConn) RemoteAddr() net.Addr             { return nil }
func (c *recCaptureConn) SetDeadline(time.Time) error      { return nil }
func (c *recCaptureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recCaptureConn) SetWriteDeadline(time.Time) error { return nil }

// recReadN reads from c until n bytes arrive or a read fails. It returns what it read.
func recReadN(c net.Conn, n int) []byte {
	out := make([]byte, 0, n)
	tmp := make([]byte, 4096)
	for len(out) < n {
		k, err := c.Read(tmp)
		out = append(out, tmp[:k]...)
		if err != nil {
			break
		}
	}
	return out
}

// TestTLSRecordCapExactAndDrop checks the cap at its edge, with the recorder alone: 16384 bytes
// are kept, one more byte drops the recording, and nothing is kept after the drop.
func TestTLSRecordCapExactAndDrop(t *testing.T) {
	if preHandshakeRecordCap != 16*1024 {
		t.Fatalf("preHandshakeRecordCap is %d, the spec fixes 16384", preHandshakeRecordCap)
	}
	r := &recordConn{started: time.Now()}
	r.active.Store(true)
	r.record(bytes.Repeat([]byte{'a'}, preHandshakeRecordCap))
	if r.overflow || len(r.buf) != preHandshakeRecordCap {
		t.Fatalf("at the cap: overflow %v, buffered %d", r.overflow, len(r.buf))
	}
	r.record([]byte{'b'})
	if !r.overflow || r.buf != nil {
		t.Fatalf("one byte over the cap: overflow %v, buf nil %v", r.overflow, r.buf == nil)
	}
	r.record([]byte{'c'})
	if r.buf != nil {
		t.Fatal("bytes were kept after the overflow")
	}
}

// TestTLSRecordDoesNotAppendAfterSettle checks that a read which reaches record after settle
// cannot add bytes to a buffer that settle has released.
func TestTLSRecordDoesNotAppendAfterSettle(t *testing.T) {
	r := &recordConn{started: time.Now()}
	r.active.Store(true)
	r.record([]byte("ab"))
	r.mu.Lock()
	r.active.Store(false)
	r.buf = nil
	r.mu.Unlock()
	r.record([]byte("cd"))
	if r.buf != nil {
		t.Fatalf("record appended after settle: %q", r.buf)
	}
}

// TestTLSPlainHTTPBytesAreExact checks a plain HTTP request,
// in one write or in three, is kept in order, and the rest stays in the socket. The prefix and the
// rest together are exactly the bytes the prober sent.
func TestTLSPlainHTTPBytesAreExact(t *testing.T) {
	for _, tc := range []struct {
		name   string
		extra  int
		writes int
	}{
		{"short request, one write", 0, 1},
		{"short request, three writes", 0, 3},
		{"20 KiB request, one write", 20 * 1024, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
			if tc.extra > 0 {
				req = append(req, bytes.Repeat([]byte{'A'}, tc.extra)...)
			}
			srvSock, cli := recPair(t)
			srv := recServer(t, srvSock, benchServerConfig(t))
			srv.SetDeadline(time.Now().Add(5 * time.Second))
			go func() {
				step := (len(req) + tc.writes - 1) / tc.writes
				for off := 0; off < len(req); off += step {
					end := min(off+step, len(req))
					cli.Write(req[off:end])
					if tc.writes > 1 {
						time.Sleep(20 * time.Millisecond)
					}
				}
			}()
			if _, err := srv.Read(make([]byte, 16)); err == nil {
				t.Fatal("plain HTTP handshake succeeded")
			}
			prefix, _, socket, wrote, overflow, ok := srv.PreHandshakeRecord()
			if !ok {
				t.Fatal("PreHandshakeRecord ok = false after a failed handshake")
			}
			if wrote || overflow {
				t.Fatalf("wrote %v, overflow %v; want false, false", wrote, overflow)
			}
			if len(prefix) == 0 || !bytes.HasPrefix(req, prefix) {
				t.Fatalf("prefix %q is not the start of the request", prefix)
			}
			got := append(append([]byte{}, prefix...), recReadN(socket, len(req)-len(prefix))...)
			if !bytes.Equal(got, req) {
				t.Fatalf("prefix and rest are %d bytes, the request is %d; not byte-exact", len(got), len(req))
			}
		})
	}
}

// TestTLSFirstRecordNoAlert checks a plain HTTP request gets no output from the TLS layer, so
// the prober sees nothing from the server before a relay would start.
func TestTLSFirstRecordNoAlert(t *testing.T) {
	srvSock, cli := recPair(t)
	srv := recServer(t, srvSock, benchServerConfig(t))
	srv.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := cli.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Read(make([]byte, 16)); err == nil {
		t.Fatal("plain HTTP handshake succeeded")
	}
	_, _, _, wrote, _, ok := srv.PreHandshakeRecord()
	if !ok || wrote {
		t.Fatalf("ok %v, wrote %v; want true, false", ok, wrote)
	}
	cli.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if n, err := cli.Read(make([]byte, 64)); n != 0 || err == nil {
		t.Fatalf("prober received %d bytes from the TLS layer (err %v)", n, err)
	}
}

// TestTLSEOFPrefixReported checks three bytes of a prefix, then FIN.
// The recorder reports the three bytes. raywire decides what to do with them.
func TestTLSEOFPrefixReported(t *testing.T) {
	srvSock, cli := recPair(t)
	srv := recServer(t, srvSock, benchServerConfig(t))
	srv.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := cli.Write([]byte("GET")); err != nil {
		t.Fatal(err)
	}
	cli.Close()
	if err := srv.Handshake(); err == nil {
		t.Fatal("handshake succeeded on a truncated record")
	}
	prefix, _, _, wrote, _, ok := srv.PreHandshakeRecord()
	if !ok || wrote || string(prefix) != "GET" {
		t.Fatalf("ok %v, wrote %v, prefix %q", ok, wrote, prefix)
	}
}

// TestTLSSilentProbeLastIsAccept checks a probe that sends nothing
// has no recorded bytes, so the idle clock is the accept time, and the TLS layer wrote nothing.
func TestTLSSilentProbeLastIsAccept(t *testing.T) {
	srvSock, _ := recPair(t)
	srv := recServer(t, srvSock, benchServerConfig(t))
	srv.SetDeadline(time.Now().Add(recSilentDeadline))
	if err := srv.Handshake(); err == nil {
		t.Fatal("handshake succeeded with no bytes")
	}
	prefix, last, socket, wrote, overflow, ok := srv.PreHandshakeRecord()
	if !ok || len(prefix) != 0 || wrote || overflow {
		t.Fatalf("ok %v, prefix %d, wrote %v, overflow %v", ok, len(prefix), wrote, overflow)
	}
	if !last.Equal(srv.rec.started) {
		t.Fatalf("last %v is not the accept time %v", last, srv.rec.started)
	}
	if socket != srvSock {
		t.Fatal("socket is not the connection passed to Server")
	}
}

// TestTLSPartialPrefixLastIsLastRead checks two bytes of a prefix, then silence.
// The prefix is those bytes, and last is the time of the read that returned them.
func TestTLSPartialPrefixLastIsLastRead(t *testing.T) {
	srvSock, cli := recPair(t)
	srv := recServer(t, srvSock, benchServerConfig(t))
	srv.SetDeadline(time.Now().Add(recSilentDeadline))
	if _, err := cli.Write([]byte("GE")); err != nil {
		t.Fatal(err)
	}
	if err := srv.Handshake(); err == nil {
		t.Fatal("handshake succeeded on a short prefix")
	}
	prefix, last, _, wrote, _, ok := srv.PreHandshakeRecord()
	if !ok || string(prefix) != "GE" || wrote {
		t.Fatalf("ok %v, prefix %q, wrote %v", ok, prefix, wrote)
	}
	if !last.After(srv.rec.started) {
		t.Fatalf("last %v is not after the accept time %v", last, srv.rec.started)
	}
}

// TestTLSRecordOverflowGivesNoPrefix checks a TLS-looking record with a 16 KiB body makes the
// recorder overflow, the TLS layer answers, and no prefix is returned.
func TestTLSRecordOverflowGivesNoPrefix(t *testing.T) {
	srvSock, cli := recPair(t)
	srv := recServer(t, srvSock, benchServerConfig(t))
	srv.SetDeadline(time.Now().Add(5 * time.Second))
	rec := append([]byte{0x16, 0x03, 0x03, 0x40, 0x00}, bytes.Repeat([]byte{0xff}, 16*1024)...)
	go cli.Write(rec)
	if err := srv.Handshake(); err == nil {
		t.Fatal("handshake succeeded on a bad record")
	}
	prefix, _, _, wrote, overflow, ok := srv.PreHandshakeRecord()
	if !ok || !overflow || prefix != nil || !wrote {
		t.Fatalf("ok %v, overflow %v, prefix %d, wrote %v; want true, true, nil, true", ok, overflow, len(prefix), wrote)
	}
}

// TestTLS13StalledHelloOneFlight checks a valid TLS 1.3 ClientHello and
// then silence. The TLS layer writes its flight, and the recorder keeps the hello.
func TestTLS13StalledHelloOneFlight(t *testing.T) {
	testStalledHello(t, gotls.VersionTLS13)
}

// TestTLS12FlightNoDecoy checks the TLS 1.2 case of the same stall.
func TestTLS12FlightNoDecoy(t *testing.T) {
	testStalledHello(t, gotls.VersionTLS12)
}

func testStalledHello(t *testing.T, version uint16) {
	hello := recCaptureHello(t, version)
	srvSock, cli := recPair(t)
	cfg := benchServerConfig(t)
	cfg.MaxVersion = version
	srv := recServer(t, srvSock, cfg)
	srv.SetDeadline(time.Now().Add(recSilentDeadline))
	if _, err := cli.Write(hello); err != nil {
		t.Fatal(err)
	}
	if err := srv.Handshake(); err == nil {
		t.Fatal("handshake succeeded without a client flight")
	}
	prefix, _, _, wrote, overflow, ok := srv.PreHandshakeRecord()
	if !ok || overflow || !wrote {
		t.Fatalf("ok %v, overflow %v, wrote %v; want true, false, true", ok, overflow, wrote)
	}
	if !bytes.Equal(prefix, hello) {
		t.Fatalf("prefix is %d bytes, the ClientHello is %d", len(prefix), len(hello))
	}
	cli.SetReadDeadline(time.Now().Add(time.Second))
	if flight := recReadN(cli, 1); len(flight) == 0 || flight[0] != 0x16 {
		t.Fatalf("prober got %x first; want the handshake record type 0x16", flight)
	}
}

// TestTLSBadRecordAfterHelloAnswered checks a valid ClientHello, then a record that the
// TLS layer rejects. The TLS layer writes its own output, which the recorder reports as wrote.
func TestTLSBadRecordAfterHelloAnswered(t *testing.T) {
	hello := recCaptureHello(t, gotls.VersionTLS13)
	bad := []byte{0x17, 0x03, 0x03, 0x00, 0x03, 0x01, 0x02, 0x03}
	srvSock, cli := recPair(t)
	srv := recServer(t, srvSock, benchServerConfig(t))
	srv.SetDeadline(time.Now().Add(5 * time.Second))
	sent := append(append([]byte{}, hello...), bad...)
	if _, err := cli.Write(sent); err != nil {
		t.Fatal(err)
	}
	if err := srv.Handshake(); err == nil {
		t.Fatal("handshake succeeded on a bad record")
	}
	prefix, _, _, wrote, overflow, ok := srv.PreHandshakeRecord()
	if !ok || overflow || !wrote {
		t.Fatalf("ok %v, overflow %v, wrote %v; want true, false, true", ok, overflow, wrote)
	}
	if len(prefix) < len(hello) || !bytes.HasPrefix(sent, prefix) {
		t.Fatalf("prefix is %d bytes; it must be a prefix of the hello and the bad record, at least %d bytes", len(prefix), len(hello))
	}
}

// TestTLSFirstReadRunsHandshake checks that a first Read, with no explicit Handshake, runs the
// handshake as its own call and settles the recorder when it succeeds.
func TestTLSFirstReadRunsHandshake(t *testing.T) {
	srvSock, cli := recPair(t)
	srv := recServer(t, srvSock, benchServerConfig(t))
	srv.SetDeadline(time.Now().Add(10 * time.Second))
	cc := recClientConn(cli, 0)
	clientDone := make(chan error, 1)
	go func() {
		if err := cc.Handshake(); err != nil {
			clientDone <- err
			return
		}
		_, err := cc.Write([]byte("ping"))
		clientDone <- err
	}()
	got := make([]byte, 4)
	if _, err := io.ReadFull(srv, got); err != nil || string(got) != "ping" {
		t.Fatalf("first Read got %q, %v", got, err)
	}
	if err := <-clientDone; err != nil {
		t.Fatal(err)
	}
	if srv.rec.active.Load() {
		t.Fatal("recording still active after a first Read that completed the handshake")
	}
	srv.rec.mu.Lock()
	dropped := srv.rec.buf == nil
	srv.rec.mu.Unlock()
	if !dropped {
		t.Fatal("buffer kept after a first Read that completed the handshake")
	}
	if _, _, _, _, _, ok := srv.PreHandshakeRecord(); ok {
		t.Fatal("PreHandshakeRecord ok after a successful first Read")
	}
}

// TestTLSServerOverNonTCPConn checks a connection that is not TCP, such as a KCP stream, gets
// the same recorder. The accessor returns the bytes and the socket passed to Server.
func TestTLSServerOverNonTCPConn(t *testing.T) {
	a, b := net.Pipe()
	t.Cleanup(func() {
		a.Close()
		b.Close()
	})
	srv := recServer(t, a, benchServerConfig(t))
	srv.SetDeadline(time.Now().Add(5 * time.Second))
	req := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	go b.Write(req)
	if _, err := srv.Read(make([]byte, 16)); err == nil {
		t.Fatal("plain HTTP handshake succeeded over a pipe")
	}
	prefix, _, socket, wrote, overflow, ok := srv.PreHandshakeRecord()
	if !ok || wrote || overflow || !bytes.Equal(prefix, req) {
		t.Fatalf("ok %v, wrote %v, overflow %v, prefix %q", ok, wrote, overflow, prefix)
	}
	if socket != a {
		t.Fatal("socket is not the connection passed to Server")
	}
}

// TestTLSAccessorReturnsOnce checks the accessor rule: ok is true once after a failure, and false
// before the handshake ends, after a success, and on every later call.
func TestTLSAccessorReturnsOnce(t *testing.T) {
	srvSock, cli := recPair(t)
	srv := recServer(t, srvSock, benchServerConfig(t))
	if _, _, _, _, _, ok := srv.PreHandshakeRecord(); ok {
		t.Fatal("ok before any handshake")
	}
	srv.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := cli.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	if err := srv.Handshake(); err == nil {
		t.Fatal("handshake succeeded on plain HTTP")
	}
	if _, _, _, _, _, ok := srv.PreHandshakeRecord(); !ok {
		t.Fatal("first call after a failure: ok false")
	}
	if _, _, _, _, _, ok := srv.PreHandshakeRecord(); ok {
		t.Fatal("second call returned ok")
	}
}

// TestTLSNoRecordingAfterHandshake checks that after a successful handshake the recorder is off, its
// buffer is gone, the accessor says ok = false, and 1 MiB of data in each direction is byte-exact.
func TestTLSNoRecordingAfterHandshake(t *testing.T) {
	srvSock, cli := recPair(t)
	srv := recServer(t, srvSock, benchServerConfig(t))
	srv.SetDeadline(time.Now().Add(20 * time.Second))
	cc := recClientConn(cli, 0)
	clientDone := recHandshake(cc)
	if err := srv.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-clientDone; err != nil {
		t.Fatal(err)
	}
	if srv.rec.active.Load() {
		t.Fatal("recording still active after a successful handshake")
	}
	srv.rec.mu.Lock()
	dropped := srv.rec.buf == nil && !srv.rec.overflow
	lastAtSuccess := srv.rec.last // the handshake's own reads set last; nothing may move it after this
	srv.rec.mu.Unlock()
	if !dropped {
		t.Fatal("buffer kept after a successful handshake")
	}
	if _, _, _, _, _, ok := srv.PreHandshakeRecord(); ok {
		t.Fatal("PreHandshakeRecord ok after a successful handshake")
	}

	payload := make([]byte, 1<<20)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() {
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(srv, got); err != nil {
			serverDone <- err
			return
		}
		_, err := srv.Write(got)
		serverDone <- err
	}()
	go cc.Write(payload)
	back := make([]byte, len(payload))
	if _, err := io.ReadFull(cc, back); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, payload) {
		t.Fatal("echo is not byte-exact")
	}
	// The data above went through both Read paths of the server. A recorder that kept copying
	// application data would hold bytes here, set overflow, or move last with each read.
	srv.rec.mu.Lock()
	kept := srv.rec.buf != nil || srv.rec.overflow || !srv.rec.last.Equal(lastAtSuccess) || srv.rec.active.Load()
	srv.rec.mu.Unlock()
	if kept {
		t.Fatal("the recorder kept application data after a successful handshake")
	}
}

// TestTLSRecordReadAfterSettleKeepsNothing checks the recorder's own Read, the path that carries
// application data after a successful handshake, once recording is off. It needs no handshake and no
// timing, so it runs in normal and -race builds alike. A recorder that still copies after settle
// keeps the 4 KiB payload and sets last.
func TestTLSRecordReadAfterSettleKeepsNothing(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	r := &recordConn{Conn: a, started: time.Now()}
	r.active.Store(false) // a successful handshake has ended recording (settle)
	payload := bytes.Repeat([]byte{'x'}, 4096)
	go b.Write(payload)
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(r, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("the recorder's Read changed the data")
	}
	r.mu.Lock()
	kept := r.buf != nil || r.overflow || !r.last.IsZero()
	r.mu.Unlock()
	if kept {
		t.Fatal("the recorder copied application data after recording was off")
	}
}

// recAllocRoundTrips is the number of 1 KiB echo round trips in one allocation window.
const recAllocRoundTrips = 1000

// recAllocWindows is the number of measured windows per connection kind. The smallest count is
// kept: other goroutines in the test process can only add allocations to a window, never remove
// them, so the minimum is the loop's own count, and a real per-call allocation shows in every window.
const recAllocWindows = 3

// recAllocTolerance is the extra allocations per round trip that the wrapper may have over bare
// crypto/tls. The counter is process-wide, so a stray goroutine (a client's session-ticket read, a
// leftover from an earlier test) adds a few allocations to a window: over 180 runs of this test the
// noise was at most 0.005 per round trip. A real allocation on each Read or Write adds at least one
// per round trip, twenty times the tolerance.
const recAllocTolerance = 0.05

// recEchoAllocs runs the echo loop on one connection, after a warm-up, and returns the smallest
// number of heap allocations per round trip over recAllocWindows windows. Each window runs
// runtime.GC first, so a pool cleared by a collection is refilled before it is measured.
func recEchoAllocs(t *testing.T, cfg *gotls.Config, wrap bool) float64 {
	t.Helper()
	srvSock, cli := recPair(t)
	var srv net.Conn
	if wrap {
		srv = Server(srvSock, cfg)
	} else {
		srv = gotls.Server(srvSock, cfg)
	}
	cc := recClientConn(cli, 0)
	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		if cc.Handshake() != nil {
			return
		}
		tmp := make([]byte, 1024)
		for {
			if _, err := io.ReadFull(cc, tmp); err != nil {
				return
			}
			if _, err := cc.Write(tmp); err != nil {
				return
			}
		}
	}()
	if err := srv.(interface{ Handshake() error }).Handshake(); err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 1024)
	in := make([]byte, 1024)
	round := func() {
		for i := 0; i < recAllocRoundTrips; i++ {
			if _, err := srv.Write(out); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(srv, in); err != nil {
				t.Fatal(err)
			}
		}
	}
	round() // warm-up: the first round trips grow buffers and finish the session setup
	best := -1.0
	for w := 0; w < recAllocWindows; w++ {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		round()
		runtime.ReadMemStats(&after)
		if per := float64(after.Mallocs-before.Mallocs) / recAllocRoundTrips; best < 0 || per < best {
			best = per
		}
	}
	srvSock.Close()
	cli.Close()
	<-echoDone
	return best
}

// TestTLSNoAllocAfterHandshake checks that the recorder adds no allocation after the handshake. The
// same echo loop runs on the wrapper and on a bare crypto/tls connection, back to back in this test,
// and the allocations per round trip are compared with recAllocTolerance. The tolerance is far below
// one allocation per call, so a per-Read or per-Write allocation fails it. The test runs in normal
// builds: race instrumentation changes the counts.
func TestTLSNoAllocAfterHandshake(t *testing.T) {
	if recRaceDetector {
		t.Skip("allocation counts vary under the race detector; the test runs in normal builds")
	}
	cfg := benchServerConfig(t)
	bare := recEchoAllocs(t, cfg, false)
	wrapped := recEchoAllocs(t, cfg, true)
	t.Logf("allocations per round trip: bare crypto/tls %.4f, wrapper %.4f (tolerance %.2f)", bare, wrapped, recAllocTolerance)
	if wrapped > bare+recAllocTolerance {
		t.Fatalf("wrapper allocates %.4f per round trip, bare crypto/tls %.4f (tolerance %.2f)", wrapped, bare, recAllocTolerance)
	}
}

// recRaceResult is one ok = true answer of a PreHandshakeRecord call.
type recRaceResult struct {
	prefix          []byte
	wrote, overflow bool
}

// TestTLSRecorderRace checks a failing handshake and a successful one run in parallel, and the
// accessor is polled from other goroutines while they run. It is meant to run under -race, and it
// also checks the answers: the failing connection gives exactly one ok = true answer, with the
// request as its prefix and wrote false, and the successful connection never gives ok = true.
func TestTLSRecorderRace(t *testing.T) {
	cfg := benchServerConfig(t)
	const req = "GET / HTTP/1.1\r\n\r\n"
	for i := 0; i < 4; i++ {
		srvFail, cliFail := recPair(t)
		failConn := recServer(t, srvFail, cfg)
		failConn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := cliFail.Write([]byte(req)); err != nil {
			t.Fatal(err)
		}

		srvOK, cliOK := recPair(t)
		okConn := recServer(t, srvOK, cfg)
		okConn.SetDeadline(time.Now().Add(5 * time.Second))
		okClient := recClientConn(cliOK, 0)
		okDone := recHandshake(okClient)

		var (
			wg      sync.WaitGroup
			mu      sync.Mutex
			failGot []recRaceResult // ok = true answers of failConn, from any caller
			okGot   int             // ok = true answers of okConn, which must stay zero
		)
		wg.Add(4)
		go func() {
			defer wg.Done()
			if err := failConn.Handshake(); err == nil {
				t.Error("plain HTTP handshake succeeded")
			}
		}()
		go func() {
			defer wg.Done()
			for k := 0; k < 200; k++ {
				if prefix, _, _, wrote, overflow, ok := failConn.PreHandshakeRecord(); ok {
					mu.Lock()
					failGot = append(failGot, recRaceResult{prefix, wrote, overflow})
					mu.Unlock()
				}
			}
		}()
		go func() {
			defer wg.Done()
			if err := okConn.Handshake(); err != nil {
				t.Error(err)
				return
			}
			if _, err := okConn.Write([]byte("pong")); err != nil {
				t.Error(err)
			}
		}()
		go func() {
			defer wg.Done()
			for k := 0; k < 200; k++ {
				if _, _, _, _, _, ok := okConn.PreHandshakeRecord(); ok {
					mu.Lock()
					okGot++
					mu.Unlock()
				}
			}
			if err := <-okDone; err != nil {
				t.Error(err)
			}
		}()
		wg.Wait()

		// The accessor answers once. The poller may have taken the answer already; if not, this
		// call takes it. Either way exactly one ok = true answer exists.
		if prefix, _, _, wrote, overflow, ok := failConn.PreHandshakeRecord(); ok {
			failGot = append(failGot, recRaceResult{prefix, wrote, overflow})
		}
		if len(failGot) != 1 {
			t.Fatalf("failing connection gave %d ok = true answers, want exactly 1", len(failGot))
		}
		if got := failGot[0]; len(got.prefix) == 0 || !bytes.HasPrefix([]byte(req), got.prefix) {
			t.Fatalf("failing connection prefix %q is not the start of the request %q", got.prefix, req)
		} else if got.wrote || got.overflow {
			t.Fatalf("failing connection wrote %v, overflow %v; want false, false for plain HTTP", got.wrote, got.overflow)
		}
		if _, _, _, _, _, ok := okConn.PreHandshakeRecord(); ok {
			okGot++
		}
		if okGot != 0 {
			t.Fatalf("successful connection gave %d ok = true answers, want 0", okGot)
		}
	}
}

// TestTLSConcurrentFirstReadWrite checks the first Read and the first Write of one server
// connection run at the same time. The bare crypto/tls control runs the same exchange.
func TestTLSConcurrentFirstReadWrite(t *testing.T) {
	cfg := benchServerConfig(t)
	for _, wrap := range []bool{false, true} {
		name := "bare"
		if wrap {
			name = "wrapper"
		}
		t.Run(name, func(t *testing.T) {
			srvSock, cli := recPair(t)
			var srv net.Conn
			if wrap {
				srv = Server(srvSock, cfg)
			} else {
				srv = gotls.Server(srvSock, cfg)
			}
			srv.SetDeadline(time.Now().Add(10 * time.Second))
			cc := recClientConn(cli, 0)
			clientDone := make(chan error, 1)
			go func() {
				if err := cc.Handshake(); err != nil {
					clientDone <- err
					return
				}
				if _, err := cc.Write([]byte("ping")); err != nil {
					clientDone <- err
					return
				}
				got := make([]byte, 4)
				_, err := io.ReadFull(cc, got)
				if err == nil && string(got) != "pong" {
					err = io.ErrUnexpectedEOF
				}
				clientDone <- err
			}()
			var wg sync.WaitGroup
			var readErr, writeErr error
			got := make([]byte, 4)
			wg.Add(2)
			go func() {
				defer wg.Done()
				_, readErr = io.ReadFull(srv, got)
			}()
			go func() {
				defer wg.Done()
				_, writeErr = srv.Write([]byte("pong"))
			}()
			wg.Wait()
			if readErr != nil || writeErr != nil || string(got) != "ping" {
				t.Fatalf("read %q %v, write %v", got, readErr, writeErr)
			}
			if err := <-clientDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestTLSNetConnIsSocket checks that NetConn returns the socket, not the recorder, for server and
// client connections. The socket is a *net.TCPConn, so UnwrapRawConn reaches it.
func TestTLSNetConnIsSocket(t *testing.T) {
	srvSock, cli := recPair(t)
	srv := recServer(t, srvSock, benchServerConfig(t))
	if srv.NetConn() != srvSock {
		t.Fatal("server NetConn is not the socket")
	}
	if _, ok := srv.NetConn().(*net.TCPConn); !ok {
		t.Fatalf("server NetConn is %T, want *net.TCPConn", srv.NetConn())
	}
	cc, ok := Client(cli, benchClientConfig()).(*Conn)
	if !ok {
		t.Fatal("Client does not return *Conn")
	}
	if cc.NetConn() != cli {
		t.Fatal("client NetConn is not the socket")
	}
	if _, _, _, _, _, ok := cc.PreHandshakeRecord(); cc.rec != nil || ok {
		t.Fatal("client connection has a recorder")
	}
}

// TestTLSCloseWriteAndWriteMultiBuffer checks CloseWrite and WriteMultiBuffer behave as before
// the recorder. CloseWrite fails before the handshake, and after it sends close_notify.
func TestTLSCloseWriteAndWriteMultiBuffer(t *testing.T) {
	srvSock, cli := recPair(t)
	srv := recServer(t, srvSock, benchServerConfig(t))
	srv.SetDeadline(time.Now().Add(10 * time.Second))
	if err := srv.CloseWrite(); err == nil {
		t.Fatal("CloseWrite before the handshake succeeded")
	}
	cc := recClientConn(cli, 0)
	clientDone := recHandshake(cc)
	if err := srv.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-clientDone; err != nil {
		t.Fatal(err)
	}
	b := buf.New()
	b.Write([]byte("hello"))
	if err := srv.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(cc, got); err != nil || string(got) != "hello" {
		t.Fatalf("read %q, %v", got, err)
	}
	if err := srv.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := cc.Read(got); err != io.EOF {
		t.Fatalf("after CloseWrite the peer read %v, want io.EOF", err)
	}
}

// TestTLSSuppressCloseNotifyClosesSocket checks that with SuppressCloseNotify, Close closes the socket
// without a close_notify, so the peer's next read fails.
func TestTLSSuppressCloseNotifyClosesSocket(t *testing.T) {
	srvSock, cli := recPair(t)
	srv := recServer(t, srvSock, benchServerConfig(t))
	srv.SetDeadline(time.Now().Add(10 * time.Second))
	cc := recClientConn(cli, 0)
	clientDone := recHandshake(cc)
	if err := srv.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-clientDone; err != nil {
		t.Fatal(err)
	}
	srv.SuppressCloseNotify()
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	cli.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := cc.Read(make([]byte, 1)); err == nil {
		t.Fatal("peer read succeeded after the server closed")
	}
}
