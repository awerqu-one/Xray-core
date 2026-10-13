package raywire

import (
	"bytes"
	"context"
	ctls "crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
)

// tlsServerCfg returns a TLS server configuration with a self-signed certificate.
func tlsServerCfg(t *testing.T) *ctls.Config {
	t.Helper()
	return &ctls.Config{Certificates: []ctls.Certificate{selfSignedCert(t)}}
}

// httpRequest returns a plain HTTP request of exactly n bytes. The padding is one header.
func httpRequest(t *testing.T, n int) []byte {
	t.Helper()
	const head = "GET / HTTP/1.1\r\nHost: x\r\nX-Pad: "
	const tail = "\r\n\r\n"
	if n < len(head)+len(tail) {
		t.Fatalf("a request of %d bytes is too short", n)
	}
	return []byte(head + strings.Repeat("a", n-len(head)-len(tail)) + tail)
}

// splitChunks cuts b into parts pieces of nearly equal size.
func splitChunks(b []byte, parts int) [][]byte {
	var out [][]byte
	for i := range parts {
		lo, hi := i*len(b)/parts, (i+1)*len(b)/parts
		out = append(out, b[lo:hi])
	}
	return out
}

// tlsResult is what one TLS-wrapped probe produced.
type tlsResult struct {
	serverErr error
	got       []byte
	waited    time.Duration // from the first write to the banner, when held
	readErr   error
}

// tlsProbe runs the pre-auth stage of srv over the TLS wrapper of one loopback connection.
// The prober writes chunks, pausing between them. With hold it waits for the decoy's banner
// before it ends its side, as exchangeHeld does. Without hold it ends its side at once.
func tlsProbe(t *testing.T, srv *Server, cfg *ctls.Config, chunks [][]byte, hold bool) tlsResult {
	t.Helper()
	server, prober := tcpPair(t)
	wrapped := xtls.Server(server, cfg)
	done := make(chan error, 1)
	go func() {
		_, err := srv.handlePreAuth(context.Background(), wrapped, srv.pad)
		done <- err
	}()

	var r tlsResult
	if err := prober.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	for i, c := range chunks {
		if i > 0 {
			time.Sleep(10 * time.Millisecond)
		}
		if _, err := prober.Write(c); err != nil {
			t.Fatal(err)
		}
	}
	if hold {
		banner := make([]byte, len(bannerText))
		if _, err := io.ReadFull(prober, banner); err != nil {
			t.Fatalf("no banner: %v", err)
		}
		r.waited = time.Since(start)
		r.got = banner
	}
	if err := prober.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	rest, err := io.ReadAll(prober)
	r.got = append(r.got, rest...)
	r.readErr = err

	select {
	case r.serverErr = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("pre-auth stage did not return")
	}
	if n := srv.adm.pendingCount(); n != 0 {
		t.Fatalf("%d pre-auth slots still in use", n)
	}
	return r
}

// tlsStalled sends the bytes of hello over the TLS wrapper and then, when junk is set, waits
// for the first byte the server writes and sends junk. It never ends its side, so the server
// decides on its own budget. It returns the decision and everything the prober read.
func tlsStalled(t *testing.T, srv *Server, cfg *ctls.Config, hello, junk []byte) (serverErr error, got []byte, readErr error) {
	t.Helper()
	server, prober := tcpPair(t)
	wrapped := xtls.Server(server, cfg)
	done := make(chan error, 1)
	go func() {
		_, err := srv.handlePreAuth(context.Background(), wrapped, srv.pad)
		done <- err
	}()
	if err := prober.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := prober.Write(hello); err != nil {
		t.Fatal(err)
	}
	if junk != nil {
		first := make([]byte, 1)
		if _, err := io.ReadFull(prober, first); err != nil {
			t.Fatalf("no server flight: %v", err)
		}
		got = append(got, first...)
		if _, err := prober.Write(junk); err != nil {
			t.Fatal(err)
		}
	}
	rest, err := io.ReadAll(prober)
	got = append(got, rest...)
	readErr = err

	select {
	case serverErr = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("pre-auth stage did not return")
	}
	return serverErr, got, readErr
}

// recordingWriter keeps the first Write of a client and fails it, so that a TLS client
// returns after it has written its ClientHello and waits for no server.
type recordingWriter struct {
	net.Conn
	hello []byte
}

func (r *recordingWriter) Write(p []byte) (int, error) {
	if r.hello == nil {
		r.hello = append([]byte(nil), p...)
	}
	return 0, errors.New("recorded")
}

// clientHello returns the first flight of a TLS client with cfg: its ClientHello record.
func clientHello(t *testing.T, cfg *ctls.Config) []byte {
	t.Helper()
	cc, sc := net.Pipe()
	defer cc.Close()
	defer sc.Close()
	rec := &recordingWriter{Conn: cc}
	_ = ctls.Client(rec, cfg).Handshake()
	if rec.hello == nil {
		t.Fatal("the TLS client wrote no ClientHello")
	}
	return rec.hello
}

// tlsRecords returns the content type and the first body byte of each complete TLS
// record in b. A record cut short ends the scan.
func tlsRecords(b []byte) (types, first []byte) {
	for len(b) >= 5 {
		n := int(binary.BigEndian.Uint16(b[3:5]))
		if len(b) < 5+n {
			break
		}
		body := b[5 : 5+n]
		types = append(types, b[0])
		if len(body) > 0 {
			first = append(first, body[0])
		} else {
			first = append(first, 0)
		}
		b = b[5+n:]
	}
	return types, first
}

// countServerHellos counts the plaintext ServerHello messages in the records of b.
func countServerHellos(b []byte) int {
	types, first := tlsRecords(b)
	n := 0
	for i, typ := range types {
		if typ == 0x16 && first[i] == 0x02 {
			n++
		}
	}
	return n
}

// testCounter is a stats counter for the wrappers of a connection.
type testCounter struct{ v int64 }

func (c *testCounter) Value() int64 { return c.v }
func (c *testCounter) Set(v int64) int64 {
	old := c.v
	c.v = v
	return old
}
func (c *testCounter) Add(d int64) int64 {
	old := c.v
	c.v += d
	return old
}

// fakeTLSConn stands in for a TLS server connection whose handshake failed before raywire
// read a byte. Its first read fails with a non-EOF error, and it reports what the TLS layer
// read, whether the TLS layer wrote, and whether it overflowed.
type fakeTLSConn struct {
	net.Conn
	prefix   []byte
	last     time.Time
	wrote    bool
	overflow bool
}

var errFakeFirstRecord = errors.New("fake: the first record is not a TLS handshake")

func (c *fakeTLSConn) Read(p []byte) (int, error) { return 0, errFakeFirstRecord }

func (c *fakeTLSConn) PreHandshakeRecord() (prefix []byte, last time.Time, socket net.Conn, wrote, overflow, ok bool) {
	return c.prefix, c.last, c.Conn, c.wrote, c.overflow, true
}

// netConnWrap is a wrapper with a NetConn accessor, as REALITY and TLS connections have.
type netConnWrap struct {
	net.Conn
	inner net.Conn
}

func (w netConnWrap) NetConn() net.Conn { return w.inner }

// hiddenConn is a wrapper with no accessor, as the header camouflage wrapper has.
type hiddenConn struct{ net.Conn }

// recordingDecoy starts a decoy that counts the connections it gets and keeps the bytes it
// reads, and answers nothing. The returned function reports the bytes after the decoy has
// seen the end of the stream.
func recordingDecoy(t *testing.T) (xnet.Destination, func() []byte) {
	t.Helper()
	got := make(chan []byte, 1)
	dest := startDecoy(t, func(c net.Conn) {
		in, _ := io.ReadAll(c)
		got <- in
	})
	return dest, func() []byte {
		select {
		case in := <-got:
			return in
		case <-time.After(3 * time.Second):
			return nil
		}
	}
}

// TestTLSPlainHTTPReachesDecoyByteExact is T-H3-1. A plain HTTP request on a tcp-tls
// inbound reaches the decoy byte for byte, in one write or in three, and the prober gets
// the decoy's answer at once. (b) is in TestTLSPrefixSilentAfterFourBytes.
func TestTLSPlainHTTPReachesDecoyByteExact(t *testing.T) {
	setPreAuthTimeout(t, 5*time.Second)
	decoy := startBannerDecoy(t)
	srv := newProbeServer(t, xnet.DestinationFromAddr(decoy))
	cfg := tlsServerCfg(t)

	cases := []struct {
		name  string
		probe []byte
		parts int
	}{
		{"27 bytes, one write", []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), 1},
		{"27 bytes, three writes", []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), 3},
		{"64 bytes, one write", httpRequest(t, 64), 1},
		{"1000 bytes, three writes", httpRequest(t, 1000), 3},
		{"20507 bytes, one write", httpRequest(t, 20507), 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := tlsProbe(t, srv, cfg, splitChunks(tc.probe, tc.parts), true)
			if reason := reasonOf(r.serverErr); reason != "read" {
				t.Fatalf("decision = %v, want reason read", r.serverErr)
			}
			if r.readErr != nil {
				t.Fatalf("prober read error %v, want the decoy's reply to its end", r.readErr)
			}
			if r.waited > time.Second {
				t.Fatalf("decoy answered after %v, want at once", r.waited)
			}
			if want := heldDirect(t, decoy, tc.probe); !bytes.Equal(r.got, want) {
				t.Fatalf("prober read %d bytes through raywire, %d direct", len(r.got), len(want))
			}
		})
	}
}

// TestTLSPrefixSilentAfterFourBytes is T-H3-1(b). One to four bytes of a probe prefix, then
// silence: the TLS layer waits for a fifth byte, so the relay starts at the budget's end with
// the recorded bytes, and its idle clock starts at the last byte.
func TestTLSPrefixSilentAfterFourBytes(t *testing.T) {
	setPreAuthTimeout(t, 400*time.Millisecond)
	decoy := startBannerDecoy(t)
	srv := newProbeServer(t, xnet.DestinationFromAddr(decoy))
	cfg := tlsServerCfg(t)

	for _, probe := range []string{"G", "GET", "GET "} {
		t.Run(probe, func(t *testing.T) {
			server, prober := tcpPair(t)
			wrapped := xtls.Server(server, cfg)
			done := make(chan error, 1)
			go func() {
				_, err := srv.handlePreAuth(context.Background(), wrapped, srv.pad)
				done <- err
			}()
			got, waited := exchangeHeld(t, prober, []byte(probe))
			var serverErr error
			select {
			case serverErr = <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("pre-auth stage did not return")
			}
			if reason := reasonOf(serverErr); reason != "deadline" {
				t.Fatalf("decision = %v, want reason deadline", serverErr)
			}
			if waited < 300*time.Millisecond {
				t.Fatalf("decoy answered after %v, before the budget", waited)
			}
			if want := heldDirect(t, decoy, []byte(probe)); !bytes.Equal(got, want) {
				t.Fatalf("prober read %q through raywire, %q direct", got, want)
			}
		})
	}
}

// startMuteDecoy starts a decoy that reads what it is sent and never writes back. Unlike
// startSilentDecoy, which echoes, no byte moves from it, so a relay to it is ended only by
// its idle limit or by the prober.
func startMuteDecoy(t *testing.T) *net.TCPAddr {
	t.Helper()
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.AcceptTCP()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr)
}

// TestTLSPrefixIdleClockFromLastByte is the idle half of T-H3-1(b). Four bytes of a probe
// prefix arrive, then silence. The pre-auth budget ends at 1.5 s, and the relay starts there
// with the recorded bytes. The decoy never writes, so no byte moves after the relay starts,
// and the idle clock runs from the last byte: the relay closes both sides 2 s after the bytes.
// A clock restarted at the budget's end would close at 3.5 s.
func TestTLSPrefixIdleClockFromLastByte(t *testing.T) {
	setPreAuthTimeout(t, 1500*time.Millisecond)
	setRelayTimers(t, 2*time.Second, 5*time.Minute)
	decoy := startMuteDecoy(t)
	srv := newProbeServer(t, xnet.DestinationFromAddr(decoy))
	server, prober := tcpPair(t)
	wrapped := xtls.Server(server, tlsServerCfg(t))
	done := make(chan error, 1)
	go func() {
		_, err := srv.handlePreAuth(context.Background(), wrapped, srv.pad)
		done <- err
	}()

	if err := prober.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := prober.Write([]byte("GET ")); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	// The prober sends nothing more and does not close, so the end it reads is the relay's close.
	got, err := io.ReadAll(prober)
	if err != nil {
		t.Fatalf("the relay did not close the prober: %v", err)
	}
	closedAfter := time.Since(start)
	if len(got) != 0 {
		t.Fatalf("a silent decoy sent %q", got)
	}

	select {
	case serverErr := <-done:
		if reason := reasonOf(serverErr); reason != "deadline" {
			t.Fatalf("decision = %v, want reason deadline", serverErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pre-auth stage did not return after the relay closed")
	}
	if closedAfter < 1800*time.Millisecond || closedAfter > 2750*time.Millisecond {
		t.Fatalf("relay closed %v after the probe's bytes, want about 2 s from the last byte", closedAfter)
	}
}

// TestTLSEOFPrefixStaysClosed is T-H3-5 (owner rule O-5). Three bytes of a prefix, then the
// end of the stream: no decoy is dialed, and the prober gets a clean end.
func TestTLSEOFPrefixStaysClosed(t *testing.T) {
	dials := countDials(t, errors.New("unexpected dial"))
	srv := newProbeServer(t, xnet.DestinationFromAddr(startBannerDecoy(t)))

	r := tlsProbe(t, srv, tlsServerCfg(t), [][]byte{[]byte("GET")}, false)
	if reason := reasonOf(r.serverErr); reason != "eof" {
		t.Fatalf("decision = %v, want reason eof", r.serverErr)
	}
	if len(r.got) != 0 || r.readErr != nil {
		t.Fatalf("prober read %q, error %v; want a clean end", r.got, r.readErr)
	}
	if n := dials.Load(); n != 0 {
		t.Fatalf("decoy dialed %d times for a closed prefix", n)
	}
}

// TestTLSFirstRecordNoAlert is T-H3-6, which closes B-5 for the raywire side. A plain HTTP
// request on the TLS wrapper leaves the wrapper with nothing written, so the failure is a
// relay of the recorded bytes and not a second flight, and the prober receives nothing
// from the server until the decoy answers.
func TestTLSFirstRecordNoAlert(t *testing.T) {
	setPreAuthTimeout(t, 2*time.Second)
	srv := newProbeServer(t, xnet.Destination{}, newKey(t))
	server, prober := tcpPair(t)
	wrapped := xtls.Server(server, tlsServerCfg(t))

	req := httpRequest(t, 64)
	if _, err := prober.Write(req); err != nil {
		t.Fatal(err)
	}
	_, err := serverHandshake(wrapped, srv.privateKey, srv.authorize, srv.replay, srv.seen, srv.keys, srv.pad)
	if reason := reasonOf(err); reason != "read" {
		t.Fatalf("decision = %v, want reason read", err)
	}
	prefix, _, _, wrote, overflow, found := tlsPrefix(wrapped)
	if !found || wrote || overflow {
		t.Fatalf("tlsPrefix: found %v, wrote %v, overflow %v; want found and nothing written", found, wrote, overflow)
	}
	if len(prefix) == 0 || !bytes.HasPrefix(req, prefix) {
		t.Fatalf("recorded prefix %q is not the start of the request", prefix)
	}
	if err := prober.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	if n, err := prober.Read(buf); n != 0 || err == nil || !isTimeout(err) {
		t.Fatalf("prober received %d bytes (%q) from the server before the relay, error %v", n, buf[:n], err)
	}
}

// TestTLSOverflowClosesWithoutDecoy is T-H3-2 (E7). A TLS-looking record whose declared
// body is 16 KiB carries more than the recording cap before the handshake ends. The
// recording is dropped, so no decoy is dialed, and the prober gets the TLS layer's output
// and a clean end.
func TestTLSOverflowClosesWithoutDecoy(t *testing.T) {
	dials := countDials(t, errors.New("unexpected dial"))
	srv := newProbeServer(t, xnet.DestinationFromAddr(startBannerDecoy(t)))

	record := append([]byte{0x16, 0x03, 0x03, 0x40, 0x00}, randomBytes(t, 16*1024)...)
	r := tlsProbe(t, srv, tlsServerCfg(t), [][]byte{record}, false)
	if reason := reasonOf(r.serverErr); reason == "" {
		t.Fatalf("decision = %v, want a HandshakeError", r.serverErr)
	}
	if n := dials.Load(); n != 0 {
		t.Fatalf("decoy dialed %d times after an overflow", n)
	}
	if bytes.Contains(r.got, []byte(bannerText)) {
		t.Fatal("the decoy's banner reached the prober after an overflow")
	}
	if len(r.got) > 0 && r.got[0] != 0x15 {
		t.Fatalf("server output after an overflow starts with record type %#x, want an alert or nothing", r.got[0])
	}
	if r.readErr != nil {
		t.Fatalf("prober read error %v after an overflow, want a clean end", r.readErr)
	}
}

// TestTLSSilentProbeMatchesRawTCP is T-H3-7. A silent TLS probe is relayed from the socket,
// with no prefix, and its close comes at the same time after accept as a silent raw TCP
// probe's (TestEmptyProbeMatchesSilentDecoy).
func TestTLSSilentProbeMatchesRawTCP(t *testing.T) {
	setPreAuthTimeout(t, 300*time.Millisecond)
	setRelayTimers(t, 600*time.Millisecond, 5*time.Minute)
	srv := newProbeServer(t, xnet.DestinationFromAddr(startBannerDecoy(t)))
	cfg := tlsServerCfg(t)

	measure := func(wrap bool) time.Duration {
		server, prober := tcpPair(t)
		var conn net.Conn = server
		if wrap {
			conn = xtls.Server(server, cfg)
		}
		start := time.Now()
		done := make(chan error, 1)
		go func() {
			_, err := srv.handlePreAuth(context.Background(), conn, srv.pad)
			done <- err
		}()
		if err := prober.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(prober); err != nil {
			t.Fatalf("read until the relay closed: %v", err)
		}
		elapsed := time.Since(start)
		select {
		case err := <-done:
			if reason := reasonOf(err); reason != "deadline" {
				t.Fatalf("decision = %v, want reason deadline", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("pre-auth stage did not return")
		}
		return elapsed
	}

	raw := measure(false)
	wrapped := measure(true)
	if d := wrapped - raw; d > 200*time.Millisecond || d < -200*time.Millisecond {
		t.Fatalf("silent TLS probe closed after %v, silent raw probe after %v", wrapped, raw)
	}
}

// TestTLSPlainHTTPLargeRelayedExact is T-H3-14 (E6). Twenty KiB of plain HTTP in one write
// is relayed byte-exact to the decoy, with no overflow.
func TestTLSPlainHTTPLargeRelayedExact(t *testing.T) {
	decoy := startBannerDecoy(t)
	srv := newProbeServer(t, xnet.DestinationFromAddr(decoy))
	req := httpRequest(t, 20507)
	r := tlsProbe(t, srv, tlsServerCfg(t), [][]byte{req}, false)
	if reason := reasonOf(r.serverErr); reason != "read" {
		t.Fatalf("decision = %v, want reason read", r.serverErr)
	}
	if want := probeDirect(t, decoy, req); !bytes.Equal(r.got, want) {
		t.Fatalf("prober read %d bytes through raywire, %d direct", len(r.got), len(want))
	}
}

// TestTLS12FlightNoDecoy is T-H3-15 (the TLS 1.2 case of review finding 9). A TLS 1.2 client
// sends a valid ClientHello and stalls. The server writes its flight, so the failure is the
// TLS layer's and no decoy is dialed. The prober gets the flight and then a clean end.
func TestTLS12FlightNoDecoy(t *testing.T) {
	setPreAuthTimeout(t, 300*time.Millisecond)
	dials := countDials(t, errors.New("unexpected dial"))
	srv := newProbeServer(t, xnet.DestinationFromAddr(startBannerDecoy(t)))
	serverCfg := tlsServerCfg(t)
	serverCfg.MaxVersion = ctls.VersionTLS12
	clientCfg := &ctls.Config{InsecureSkipVerify: true, MaxVersion: ctls.VersionTLS12}

	got, err := stalledFlight(t, srv, serverCfg, clientHello(t, clientCfg))
	if err != nil {
		t.Fatalf("prober read error %v, want a clean end after the flight", err)
	}
	if len(got) == 0 || got[0] != 0x16 {
		t.Fatalf("prober read %x, want the server flight", got)
	}
	if n := dials.Load(); n != 0 {
		t.Fatalf("decoy dialed %d times after a TLS 1.2 flight", n)
	}
}

// TestTLS13StalledHelloOneFlight is T-H3-16 (E5). A TLS 1.3 client sends a valid ClientHello
// and stalls. The prober gets one ServerHello and a clean end, with no second flight and no
// decoy answer, against a TLS decoy and against a plain HTTP decoy.
func TestTLS13StalledHelloOneFlight(t *testing.T) {
	setPreAuthTimeout(t, 300*time.Millisecond)
	hello := clientHello(t, &ctls.Config{InsecureSkipVerify: true})

	decoys := []struct {
		name string
		dest func(t *testing.T) xnet.Destination
	}{
		{"tls decoy", func(t *testing.T) xnet.Destination {
			return startTLSDecoy(t, make(chan time.Time, 1))
		}},
		{"plain http decoy", func(t *testing.T) xnet.Destination {
			return startDecoy(t, func(c net.Conn) {
				_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
			})
		}},
	}
	for _, d := range decoys {
		t.Run(d.name, func(t *testing.T) {
			dials := countDials(t, errors.New("unexpected dial"))
			srv := newProbeServer(t, d.dest(t))
			got, err := stalledFlight(t, srv, tlsServerCfg(t), hello)
			if err != nil {
				t.Fatalf("prober read error %v, want a clean end after the flight", err)
			}
			if n := countServerHellos(got); n != 1 {
				t.Fatalf("%d ServerHello messages, want exactly 1", n)
			}
			if strings.Contains(string(got), "HTTP/1.1 400") {
				t.Fatal("a decoy answer followed the TLS flight")
			}
			if n := dials.Load(); n != 0 {
				t.Fatalf("decoy dialed %d times after a TLS flight", n)
			}
		})
	}
}

// stalledFlight sends a ClientHello and then waits, without a further byte, until the
// server closes. It returns what the prober read and the read error.
func stalledFlight(t *testing.T, srv *Server, cfg *ctls.Config, hello []byte) ([]byte, error) {
	t.Helper()
	serverErr, got, readErr := tlsStalled(t, srv, cfg, hello, nil)
	if reasonOf(serverErr) == "" {
		t.Fatalf("decision = %v, want a HandshakeError", serverErr)
	}
	if reasonOf(serverErr) != "deadline" && reasonOf(serverErr) != "read" {
		t.Fatalf("decision = %v, want reason deadline after the flight", serverErr)
	}
	return got, readErr
}

// TestTLS13BadRecordAlertThenClose is T-H3-17. A bad record after a valid ClientHello gets
// the TLS layer's alert and then a clean end. No decoy bytes reach the prober.
func TestTLS13BadRecordAlertThenClose(t *testing.T) {
	dials := countDials(t, errors.New("unexpected dial"))
	srv := newProbeServer(t, xnet.DestinationFromAddr(startBannerDecoy(t)))
	hello := clientHello(t, &ctls.Config{InsecureSkipVerify: true})
	// An application data record before the client's Finished is a protocol violation.
	junk := []byte{0x17, 0x03, 0x03, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'}

	serverErr, got, readErr := tlsStalled(t, srv, tlsServerCfg(t), hello, junk)
	if reasonOf(serverErr) == "" {
		t.Fatalf("decision = %v, want a HandshakeError", serverErr)
	}
	if readErr != nil {
		t.Fatalf("prober read error %v, want a clean end after the alert", readErr)
	}
	// After the ServerHello every record is encrypted, so the alert is an application data
	// record of 19 bytes: two alert bytes, the content type and the 16-byte tag.
	var lastType byte
	var lastLen int
	for rest := got; len(rest) >= 5; {
		n := int(binary.BigEndian.Uint16(rest[3:5]))
		if len(rest) < 5+n {
			break
		}
		lastType, lastLen = rest[0], n
		rest = rest[5+n:]
	}
	if lastType != 0x17 || lastLen != 19 {
		t.Fatalf("last server record has type %#x and %d bytes, want an encrypted alert (0x17, 19 bytes)", lastType, lastLen)
	}
	if strings.Contains(string(got), bannerText) {
		t.Fatal("the decoy's banner reached the prober after a TLS alert")
	}
	if n := dials.Load(); n != 0 {
		t.Fatalf("decoy dialed %d times after a TLS alert", n)
	}
}

// TestTLSProbeCountersMatchPlain is T-H3-18 (review finding 17). The bytes of a TLS probe
// that are relayed are counted by the connection's read counter, as a plain TCP probe's are.
// The prefix that the TLS layer read is counted once.
func TestTLSProbeCountersMatchPlain(t *testing.T) {
	decoy := startBannerDecoy(t)
	srv := newProbeServer(t, xnet.DestinationFromAddr(decoy))
	probe := httpRequest(t, 1000)

	count := func(wrap bool) int64 {
		server, prober := tcpPair(t)
		var inner net.Conn = server
		if wrap {
			inner = xtls.Server(server, tlsServerCfg(t))
		}
		rc, wc := &testCounter{}, &testCounter{}
		conn := &stat.CounterConnection{Connection: inner, ReadCounter: rc, WriteCounter: wc}
		done := make(chan error, 1)
		go func() {
			_, err := srv.handlePreAuth(context.Background(), conn, srv.pad)
			done <- err
		}()
		if _, err := prober.Write(probe); err != nil {
			t.Fatal(err)
		}
		if err := prober.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(prober); err != nil {
			t.Fatal(err)
		}
		<-done
		return rc.Value()
	}

	plain := count(false)
	tlsCount := count(true)
	if plain != int64(len(probe)) {
		t.Fatalf("plain probe counted %d bytes read, want %d", plain, len(probe))
	}
	if tlsCount != plain {
		t.Fatalf("TLS probe counted %d bytes read, a plain probe %d", tlsCount, plain)
	}
}

// TestTLSUnderProxyProtoRequireUnchanged is T-H3-19 (R-H3-6, owner decision O-10). On a
// listener that requires a PROXY header, a plain HTTP probe gets the old reaction: the TLS
// layer records nothing, and the decoy receives no request bytes. The test fails when the
// policy changes, and then the spec must be updated.
func TestTLSUnderProxyProtoRequireUnchanged(t *testing.T) {
	received := make(chan []byte, 1)
	decoy := startDecoy(t, func(c net.Conn) {
		in, _ := io.ReadAll(c)
		received <- in
	})
	srv := newProbeServer(t, decoy)

	// The listener is the production one. internet.ListenSystem wraps it with the PROXY policy of
	// transport/internet/system_listener.go when acceptProxyProtocol is set, so a change to that
	// policy changes the outcome of this test. The test does not build a policy of its own.
	ln, err := internet.ListenSystem(context.Background(), &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}, &internet.SocketConfig{AcceptProxyProtocol: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	if _, ok := ln.(*proxyproto.Listener); !ok {
		t.Fatalf("ListenSystem with acceptProxyProtocol returned %T, want the PROXY listener", ln)
	}
	type acceptResult struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		c, err := ln.Accept()
		accepted <- acceptResult{c, err}
	}()
	prober, err := net.DialTCP("tcp", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer prober.Close()
	var server net.Conn
	select {
	case r := <-accepted:
		if r.err != nil {
			t.Fatal(r.err)
		}
		server = r.conn
	case <-time.After(5 * time.Second):
		t.Fatal("listener did not accept the probe")
	}

	done := make(chan error, 1)
	go func() {
		_, err := srv.handlePreAuth(context.Background(), xtls.Server(server, tlsServerCfg(t)), srv.pad)
		done <- err
	}()
	_, _ = prober.Write(httpRequest(t, 64))
	_ = prober.CloseWrite()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("pre-auth stage did not return")
	}
	select {
	case in := <-received:
		if len(in) != 0 {
			t.Fatalf("decoy received %q under a PROXY header requirement, want nothing", in)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("decoy was not reached or did not end")
	}
}

// TestTLSUnderHeaderCamouflageUnchanged is T-H3-20 (R-H3-7, owner decision O-11). Above
// the TLS wrapper, a wrapper without an accessor hides the TLS layer, so tlsPrefix finds
// nothing and the decoy receives no request bytes.
func TestTLSUnderHeaderCamouflageUnchanged(t *testing.T) {
	dest, received := recordingDecoy(t)
	srv := newProbeServer(t, dest)
	server, prober := tcpPair(t)
	tlsConn := xtls.Server(server, tlsServerCfg(t))
	hidden := hiddenConn{Conn: tlsConn}

	if _, _, _, _, _, found := tlsPrefix(hidden); found {
		t.Fatal("tlsPrefix found a TLS layer under a wrapper with no accessor")
	}

	done := make(chan error, 1)
	go func() {
		_, err := srv.handlePreAuth(context.Background(), hidden, srv.pad)
		done <- err
	}()
	_, _ = prober.Write(httpRequest(t, 64))
	_ = prober.CloseWrite()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("pre-auth stage did not return")
	}
	if in := received(); len(in) != 0 {
		t.Fatalf("decoy received %q under header camouflage, want nothing", in)
	}
}

// TestFailureBranchRelaysRecordedPrefix is the relay of section 5.4 on a fake wrapper: a
// non-TLS first record (wrote false, no overflow) is relayed to the decoy with the recorded
// bytes first, and the rest of the stream after them.
func TestFailureBranchRelaysRecordedPrefix(t *testing.T) {
	prefix := []byte("GET / HTTP/1.1\r\n")
	dest := startDecoy(t, func(c net.Conn) {
		in, _ := io.ReadAll(c)
		_, _ = c.Write(in)
	})
	srv := newProbeServer(t, dest)
	server, prober := tcpPair(t)
	conn := &fakeTLSConn{Conn: server, prefix: prefix, last: time.Now()}
	done := make(chan error, 1)
	go func() {
		_, err := srv.handlePreAuth(context.Background(), conn, srv.pad)
		done <- err
	}()
	_, _ = prober.Write([]byte("tail"))
	_ = prober.CloseWrite()
	got, err := io.ReadAll(prober)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("pre-auth stage did not return")
	}
	if want := append(append([]byte(nil), prefix...), []byte("tail")...); !bytes.Equal(got, want) {
		t.Fatalf("decoy answered %q, want its echo of the recorded prefix and the tail %q", got, want)
	}
}

// TestFailureBranchNoDialAfterAnswerOrOverflow checks the two cases where the TLS layer's
// output or an overflow forbids the relay: the decoy is not dialed and the prober gets a
// clean end.
func TestFailureBranchNoDialAfterAnswerOrOverflow(t *testing.T) {
	for _, tc := range []struct {
		name     string
		wrote    bool
		overflow bool
	}{{"the TLS layer wrote", true, false}, {"the record overflowed", false, true}} {
		t.Run(tc.name, func(t *testing.T) {
			dials := countDials(t, errors.New("unexpected dial"))
			srv := newProbeServer(t, xnet.DestinationFromAddr(startBannerDecoy(t)))
			server, prober := tcpPair(t)
			conn := &fakeTLSConn{Conn: server, prefix: []byte("GET / HTTP/1.1\r\n"), last: time.Now(), wrote: tc.wrote, overflow: tc.overflow}
			done := make(chan error, 1)
			go func() {
				_, err := srv.handlePreAuth(context.Background(), conn, srv.pad)
				done <- err
			}()
			got, err := io.ReadAll(prober)
			if err != nil {
				t.Fatalf("prober read error %v, want a clean end", err)
			}
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("pre-auth stage did not return")
			}
			if len(got) != 0 {
				t.Fatalf("prober read %q, want nothing from the server", got)
			}
			if n := dials.Load(); n != 0 {
				t.Fatalf("decoy dialed %d times", n)
			}
		})
	}
}

// TestTLSPrefixWalkFindsNearestWrapper checks the walk of tlsPrefix: it stops at the first
// wrapper that answers, and it finds a TLS wrapper below accessors, within the depth limit.
func TestTLSPrefixWalkFindsNearestWrapper(t *testing.T) {
	server, _ := tcpPair(t)
	inner := &fakeTLSConn{Conn: server, prefix: []byte("inner")}
	outer := &fakeTLSConn{Conn: inner, prefix: []byte("outer")}
	prefix, _, _, _, _, found := tlsPrefix(outer)
	if !found || string(prefix) != "outer" {
		t.Fatalf("walk returned %q, found %v; want the nearest wrapper", prefix, found)
	}

	var deep net.Conn = &fakeTLSConn{Conn: server, prefix: []byte("deep")}
	for range maxUnwrap - 1 {
		deep = netConnWrap{Conn: deep, inner: deep}
	}
	prefix, _, _, _, _, found = tlsPrefix(deep)
	if !found || string(prefix) != "deep" {
		t.Fatalf("a TLS wrapper at depth %d: found %v, prefix %q", maxUnwrap-1, found, prefix)
	}

	var tooDeep net.Conn = &fakeTLSConn{Conn: server, prefix: []byte("too deep")}
	for range maxUnwrap + 1 {
		tooDeep = netConnWrap{Conn: tooDeep, inner: tooDeep}
	}
	if _, _, _, _, _, found := tlsPrefix(tooDeep); found {
		t.Fatalf("a TLS wrapper past the depth limit was found")
	}

	plain, _ := tcpPair(t)
	if _, _, _, _, _, found := tlsPrefix(plain); found {
		t.Fatal("a plain connection gave a TLS prefix")
	}
}

// TestCounterSocketCountsPrefixOnce checks counterSocket: the prefix of a TLS probe is added
// to the read counter once, the socket keeps the same counters, and a connection without
// counters gives the socket itself.
func TestCounterSocketCountsPrefixOnce(t *testing.T) {
	server, _ := tcpPair(t)
	rc, wc := &testCounter{}, &testCounter{}
	conn := &stat.CounterConnection{Connection: &fakeTLSConn{Conn: server}, ReadCounter: rc, WriteCounter: wc}

	out := counterSocket(conn, server, 5)
	if rc.Value() != 5 {
		t.Fatalf("read counter = %d after a 5-byte prefix, want 5", rc.Value())
	}
	cc, ok := out.(*stat.CounterConnection)
	if !ok || cc.ReadCounter != rc || cc.WriteCounter != wc || cc.Connection != server {
		t.Fatalf("counterSocket returned %T, want a counter wrapper of the socket with the same counters", out)
	}
	if counterSocket(server, server, 5) != net.Conn(server) {
		t.Fatal("counterSocket of a connection without counters is not the socket")
	}
	counterSocket(conn, server, 0)
	if rc.Value() != 5 {
		t.Fatalf("a zero prefix changed the read counter to %d", rc.Value())
	}
}

// TestTLSRecordHeaderErrorIsReadReason checks that a first record that is not TLS gives
// raywire the reason read, and that the TLS wrapper keeps the first record it read.
func TestTLSRecordHeaderErrorIsReadReason(t *testing.T) {
	server, prober := tcpPair(t)
	wrapped := xtls.Server(server, tlsServerCfg(t))
	if _, err := prober.Write([]byte("GET / HTTP/1.1\r\n")); err != nil {
		t.Fatal(err)
	}
	_, err := serverHandshake(wrapped, newKey(t), func([]byte) (*Account, bool) { return nil, false }, NewReplayFilter(), nil, testHeadKeys(), defaultPadPolicy())
	var he *HandshakeError
	if !errors.As(err, &he) || he.Reason != "read" {
		t.Fatalf("decision = %v, want reason read", err)
	}
	prefix, _, _, _, _, found := tlsPrefix(wrapped)
	if !found || len(prefix) < 5 {
		t.Fatalf("tlsPrefix found %v with %d recorded bytes, want the first record", found, len(prefix))
	}
}
