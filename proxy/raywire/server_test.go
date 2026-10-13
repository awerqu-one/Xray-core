package raywire

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// bannerText opens every reply of the banner decoy.
const bannerText = "decoy-banner;"

// startBannerDecoy serves each connection with bannerText, then echoes what it
// reads until the peer ends. Its reply to a probe is the banner followed by the
// probe's bytes, however the bytes are chunked.
func startBannerDecoy(t *testing.T) *net.TCPAddr {
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
				c.Write([]byte(bannerText))
				echo(c)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr)
}

// newProbeServer returns a server that accepts the given client keys and relays
// failed connections to fallback. A zero fallback means silent close.
func newProbeServer(t *testing.T, fallback xnet.Destination, clients ...noise.DHKey) *Server {
	t.Helper()
	s := &Server{
		privateKey:       newKey(t),
		keys:             testHeadKeys(),
		seen:             newSeenHeads(seenHeadCap, seenHeadTTL, handshakeClock()),
		clients:          make(map[string]*Account, len(clients)),
		pad:              defaultPadPolicy(),
		fallback:         fallback,
		allowSilentClose: !fallback.IsValid(),
		policyManager:    fakePolicy{},
		replay:           newReplayFilterAt(handshakeClock()),
		adm:              newAdmission(maxPendingHandshakes, maxPendingPerIP),
	}
	for _, c := range clients {
		s.clients[string(c.Public)] = &Account{PublicKey: c.Public}
	}
	// Closing the server stops its head-failure summary, so no timer from this test
	// logs into a later test.
	t.Cleanup(func() { s.Close() })
	return s
}

// setPreAuthTimeout shortens the pre-auth budget for one test.
func setPreAuthTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	old := preAuthTimeout
	preAuthTimeout = d
	t.Cleanup(func() { preAuthTimeout = old })
}

// readUntilEOF reads c to its end, or fails after limit. It returns the error
// rather than failing the test, since a refused connection may end in a reset.
func readUntilEOF(c net.Conn, limit time.Duration) ([]byte, error) {
	if err := c.SetReadDeadline(time.Now().Add(limit)); err != nil {
		return nil, err
	}
	return io.ReadAll(c)
}

// reasonOf returns the decision reason of a failed pre-auth stage, or "" when
// the error is not a decision about the peer.
func reasonOf(err error) string {
	if he, ok := err.(*HandshakeError); ok {
		return he.Reason
	}
	return ""
}

// probeOutcome is what one connection produced: the bytes the prober read, the
// prober's own first error, and the pre-auth stage's error, which names the
// decision.
type probeOutcome struct {
	got       []byte
	proberErr error
	serverErr error
}

// probeViaServer sends probe to srv over a loopback connection, ends the
// prober's side, and collects what comes back. It fails the test if the
// pre-auth stage does not return, or if it leaves a slot in use.
func probeViaServer(t *testing.T, srv *Server, probe []byte) probeOutcome {
	t.Helper()
	server, prober := tcpPair(t)
	done := make(chan error, 1)
	go func() {
		_, err := srv.handlePreAuth(context.Background(), server, srv.pad)
		done <- err
	}()

	var o probeOutcome
	_, o.proberErr = prober.Write(probe)
	if err := prober.CloseWrite(); o.proberErr == nil {
		o.proberErr = err
	}
	var err error
	o.got, err = readUntilEOF(prober, 5*time.Second)
	if o.proberErr == nil {
		o.proberErr = err
	}

	select {
	case o.serverErr = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("pre-auth stage did not return")
	}
	if n := srv.adm.pendingCount(); n != 0 {
		t.Fatalf("%d pre-auth slots still in use", n)
	}
	return o
}

// probeDirect sends probe straight to the decoy. Its reply is what a prober
// should read through raywire.
func probeDirect(t *testing.T, decoy *net.TCPAddr, probe []byte) []byte {
	t.Helper()
	c, err := net.DialTCP("tcp", nil, decoy)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write(probe); err != nil {
		t.Fatal(err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := readUntilEOF(c, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// errMsg1Recorded fails the write that carries the first message.
var errMsg1Recorded = errors.New("first message recorded")

// msg1Recorder keeps the first message that a client writes and fails the
// write, so ClientHandshake returns at once and waits for no peer.
type msg1Recorder struct {
	net.Conn
	msg []byte
}

func (r *msg1Recorder) Write(p []byte) (int, error) {
	r.msg = append([]byte(nil), p...)
	return 0, errMsg1Recorded
}

// recordMsg1 returns the first message that a client with clientKey sends to
// serverPublic, with its timestamp taken at the time at.
func recordMsg1(t *testing.T, clientKey noise.DHKey, serverPublic []byte, at time.Time) []byte {
	t.Helper()
	cc, sc := net.Pipe()
	defer cc.Close()
	defer sc.Close()

	saved := handshakeClock
	handshakeClock = func() time.Time { return at }
	defer func() { handshakeClock = saved }()

	rec := &msg1Recorder{Conn: cc}
	_, err := ClientHandshake(rec, clientKey, serverPublic, testKeys(), defaultPadPolicy())
	if !errors.Is(err, errMsg1Recorded) {
		t.Fatalf("client handshake error = %v, want the recorded first message", err)
	}
	return rec.msg
}

// forgedMsg1 returns a first message whose head carries a valid tag under testPSK and
// whose length word decodes to n1 under the server's key, followed by n1 random bytes.
// It is built by a holder of the PSK. The server reads all of it and fails the Noise
// check. With n1 out of range, it stops at the length word.
func forgedMsg1(t *testing.T, serverKey noise.DHKey, n1 int) []byte {
	t.Helper()
	_, _, R, err := selectEphemeral(wireEphemeral)
	if err != nil {
		t.Fatal(err)
	}
	return append(headWithLength(t, serverKey, testPSK, R, n1), randomBytes(t, n1)...)
}

// Rows 1, 3, 4, 5, 7, 9, 10, 11, 13 of section 12.2. Each probe is sent, then
// the prober ends its side. The decoy must get the same bytes as the reply to a
// direct connection, and the server must decide for the stated reason.
func TestProbesReachDecoyLikeDirectConnection(t *testing.T) {
	decoy := startBannerDecoy(t)
	clientKey, otherKey := newKey(t), newKey(t)
	srv := newProbeServer(t, xnet.DestinationFromAddr(decoy), clientKey)
	now := time.Now()

	probes := []struct {
		name   string
		probe  []byte
		reason string // "" when several decisions are correct
	}{
		{"one byte then end", []byte{0x17}, "eof"},
		{"TLS record start", []byte("\x16\x03client hello"), "prefix"},
		{"HTTP request line", []byte("GET / HTTP/1.0\r\n\r\n"), "prefix"},
		{"length out of range", append(forgedMsg1(t, srv.privateKey, 0), "tail after the decision"...), "length"},
		{"Noise failure", forgedMsg1(t, srv.privateKey, 72), "noise"},
		{"wrong server key", recordMsg1(t, clientKey, otherKey.Public, now), ""},
		{"unauthorized key", recordMsg1(t, otherKey, srv.privateKey.Public, now), "unauthorized"},
		{"stale timestamp", recordMsg1(t, clientKey, srv.privateKey.Public, now.Add(-10*time.Minute)), "replay"},
	}
	for _, p := range probes {
		t.Run(p.name, func(t *testing.T) {
			o := probeViaServer(t, srv, p.probe)
			if o.proberErr != nil {
				t.Fatalf("prober error: %v", o.proberErr)
			}
			if want := p.reason; want != "" && reasonOf(o.serverErr) != want {
				t.Fatalf("decision = %v, want reason %q", o.serverErr, want)
			}
			want := probeDirect(t, decoy, p.probe)
			if !bytes.HasPrefix(want, []byte(bannerText)) {
				t.Fatalf("direct reply %q does not start with the banner", want)
			}
			if !bytes.Equal(o.got, want) {
				t.Fatalf("prober read %q through raywire, %q direct", o.got, want)
			}
		})
	}
}

// exchangeHeld sends probe, then waits for the banner before it ends its side.
// A decoy that is reached only at the pre-auth deadline answers late, so this is
// how the prober reads it. It returns every byte read and the time the banner
// took.
func exchangeHeld(t *testing.T, c *net.TCPConn, probe []byte) ([]byte, time.Duration) {
	t.Helper()
	if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := c.Write(probe); err != nil {
		t.Fatal(err)
	}
	banner := make([]byte, len(bannerText))
	if _, err := io.ReadFull(c, banner); err != nil {
		t.Fatalf("no banner: %v", err)
	}
	waited := time.Since(start)
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	rest, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	return append(banner, rest...), waited
}

// Rows 2, 6, 8 and 21 of section 12.2. The prober holds the connection, so the
// server decides at its pre-auth deadline and relays what it has read. The
// budget is shortened for the test.
func TestHeldProbesReachDecoyAtDeadline(t *testing.T) {
	setPreAuthTimeout(t, 200*time.Millisecond)
	decoy := startBannerDecoy(t)
	srv := newProbeServer(t, xnet.DestinationFromAddr(decoy))

	probes := []struct {
		name  string
		probe []byte
	}{
		{"nothing sent", nil},
		{"three bytes", []byte("abc")},
		{"one byte", []byte{0x17}},
		// Row 8: a length word in range, so the server waits for the rest of msg1.
		{"in-range length, no rest", forgedMsg1(t, srv.privateKey, 72)[:hsHeadLen]},
	}
	for _, p := range probes {
		t.Run(p.name, func(t *testing.T) {
			server, prober := tcpPair(t)
			done := make(chan error, 1)
			go func() {
				_, err := srv.handlePreAuth(context.Background(), server, srv.pad)
				done <- err
			}()
			got, waited := exchangeHeld(t, prober, p.probe)

			var serverErr error
			select {
			case serverErr = <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("pre-auth stage did not return")
			}
			if reason := reasonOf(serverErr); reason != "deadline" {
				t.Fatalf("decision = %v, want reason deadline", serverErr)
			}
			if waited < 150*time.Millisecond {
				t.Fatalf("banner after %v, before the pre-auth deadline", waited)
			}
			if n := srv.adm.pendingCount(); n != 0 {
				t.Fatalf("%d pre-auth slots still in use", n)
			}

			direct, err := net.DialTCP("tcp", nil, decoy)
			if err != nil {
				t.Fatal(err)
			}
			defer direct.Close()
			want, _ := exchangeHeld(t, direct, p.probe)
			if !bytes.Equal(got, want) {
				t.Fatalf("prober read %q through raywire, %q direct", got, want)
			}
		})
	}
}

// Row 12, and the success path. A first message that the server accepts is
// answered. The same bytes sent again are a replay, and the decoy must see them
// as a direct connection would.
func TestReplayedFirstMessageReachesDecoy(t *testing.T) {
	decoy := startBannerDecoy(t)
	clientKey := newKey(t)
	srv := newProbeServer(t, xnet.DestinationFromAddr(decoy), clientKey)
	msg1 := recordMsg1(t, clientKey, srv.privateKey.Public, time.Now())

	type result struct {
		rc  *Conn
		err error
	}
	server, prober := tcpPair(t)
	done := make(chan result, 1)
	go func() {
		rc, err := srv.handlePreAuth(context.Background(), server, srv.pad)
		done <- result{rc, err}
	}()
	if _, err := prober.Write(msg1); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("first copy refused: %v", r.err)
		}
		r.rc.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("first copy was not accepted")
	}
	if n := srv.adm.pendingCount(); n != 0 {
		t.Fatalf("%d pre-auth slots still in use after success", n)
	}

	o := probeViaServer(t, srv, msg1)
	if o.proberErr != nil {
		t.Fatalf("prober error on the replay: %v", o.proberErr)
	}
	if reason := reasonOf(o.serverErr); reason != "seen" {
		t.Fatalf("replay decision = %v, want reason seen", o.serverErr)
	}
	if want := probeDirect(t, decoy, msg1); !bytes.Equal(o.got, want) {
		t.Fatalf("prober read %q through raywire, %q direct", o.got, want)
	}
}

// Row 1 of section 12.2. A connection that closes before any byte is closed
// without a dial, and the prober reads nothing.
func TestEmptyCloseGetsNoDecoy(t *testing.T) {
	dials := countDials(t, errors.New("unexpected dial"))
	srv := newProbeServer(t, xnet.DestinationFromAddr(startBannerDecoy(t)))

	o := probeViaServer(t, srv, nil)
	if o.proberErr != nil || len(o.got) != 0 {
		t.Fatalf("prober read %q, error %v; want a clean end", o.got, o.proberErr)
	}
	if reason := reasonOf(o.serverErr); reason != "eof" {
		t.Fatalf("decision = %v, want reason eof", o.serverErr)
	}
	if n := dials.Load(); n != 0 {
		t.Fatalf("decoy dialed %d times for an empty connection", n)
	}
}

// Row 20 of section 12.2. Without a decoy, a failed connection is closed at the
// decision. The prober may see a reset, but it reads no bytes.
func TestNoDecoyClosesAtDecision(t *testing.T) {
	dials := countDials(t, errors.New("unexpected dial"))
	srv := newProbeServer(t, xnet.Destination{})

	o := probeViaServer(t, srv, []byte("GET / HTTP/1.0\r\n\r\n"))
	if len(o.got) != 0 {
		t.Fatalf("prober read %q with no decoy", o.got)
	}
	if reason := reasonOf(o.serverErr); reason != "prefix" {
		t.Fatalf("decision = %v, want reason prefix", o.serverErr)
	}
	if n := dials.Load(); n != 0 {
		t.Fatalf("dialed %d times with no decoy", n)
	}
}

// Row 18 of section 12.2. With every relay slot taken, a failed connection is
// closed without a dial.
func TestFullRelayPoolClosesWithoutDial(t *testing.T) {
	oldAdm := relayAdm
	relayAdm = newAdmission(1, maxRelaysPerIP)
	t.Cleanup(func() { relayAdm = oldAdm })
	if _, ok := relayAdm.TryAcquire("127.0.0.1"); !ok {
		t.Fatal("new relay pool has no free slot")
	}
	dials := countDials(t, errors.New("unexpected dial"))
	srv := newProbeServer(t, xnet.DestinationFromAddr(startBannerDecoy(t)))

	o := probeViaServer(t, srv, []byte("GET / HTTP/1.0\r\n\r\n"))
	if len(o.got) != 0 {
		t.Fatalf("prober read %q from a refused relay", o.got)
	}
	if reason := reasonOf(o.serverErr); reason != "prefix" {
		t.Fatalf("decision = %v, want reason prefix", o.serverErr)
	}
	if n := dials.Load(); n != 0 {
		t.Fatalf("decoy dialed %d times with a full relay pool", n)
	}
}

// Row 19 of section 12.2. When the decoy cannot be dialed, the prober is closed
// and reads nothing.
func TestUnreachableDecoyClosesProber(t *testing.T) {
	dials := countDials(t, errors.New("connection refused"))
	srv := newProbeServer(t, xnet.DestinationFromAddr(startBannerDecoy(t)))

	o := probeViaServer(t, srv, []byte("GET / HTTP/1.0\r\n\r\n"))
	if len(o.got) != 0 {
		t.Fatalf("prober read %q after a failed dial", o.got)
	}
	if n := dials.Load(); n != 1 {
		t.Fatalf("decoy dialed %d times, want 1", n)
	}
}

// fixedAddr is a net.Addr with a fixed text form.
type fixedAddr string

func (a fixedAddr) Network() string { return "tcp" }
func (a fixedAddr) String() string  { return string(a) }

// addrConn reports a fixed remote address, so that a test chooses the host a
// connection comes from.
type addrConn struct {
	net.Conn
	addr net.Addr
}

func (c addrConn) RemoteAddr() net.Addr { return c.addr }

// TestSourceKey checks the key of the per-source caps. An IPv4 address is its own key,
// an IPv4-mapped address is keyed as IPv4, an IPv6 address is keyed by its /64, and a
// zone is dropped.
func TestSourceKey(t *testing.T) {
	cases := map[string]string{
		"203.0.113.5:4000":        "203.0.113.5",
		"[::ffff:203.0.113.5]:80": "203.0.113.5",
		"[2001:db8::1]:443":       "2001:db8::/64",
		"[2001:db8::ffff]:443":    "2001:db8::/64",
		"[fe80::1%eth0]:443":      "fe80::/64",
		"pipe":                    "pipe",
	}
	for addr, want := range cases {
		if got := sourceKey(fixedAddr(addr)); got != want {
			t.Errorf("sourceKey(%q) = %q, want %q", addr, got, want)
		}
	}
	if sourceKey(nil) != "" {
		t.Error("sourceKey(nil) is not empty")
	}
}

func TestAdmissionLimitsTotalAndPerHost(t *testing.T) {
	a := newAdmission(3, 2)
	const host = "198.51.100.1"
	acquire := func(h string) func() {
		t.Helper()
		release, ok := a.TryAcquire(h)
		if !ok {
			t.Fatalf("slot for %s refused below its limits", h)
		}
		return release
	}
	refuse := func(h string) {
		t.Helper()
		if _, ok := a.TryAcquire(h); ok {
			t.Fatalf("slot for %s granted past a limit", h)
		}
	}

	a1 := acquire(host)
	a2 := acquire(host)
	refuse(host) // the per-host limit is 2
	b := acquire("198.51.100.2")
	refuse("198.51.100.3") // the total limit is 3
	a1()
	a1() // a second release gives nothing back
	if n := a.pendingCount(); n != 2 {
		t.Fatalf("pending = %d after a double release, want 2", n)
	}
	c := acquire("198.51.100.3")
	a2()
	b()
	c()
	if n := a.pendingCount(); n != 0 {
		t.Fatalf("pending = %d after every release, want 0", n)
	}
	if len(a.perHost) != 0 {
		t.Fatalf("%d hosts still counted after every release", len(a.perHost))
	}
}

// TestPreAuthLimitsLeaveRoomForRealClients checks the pre-auth limits at their
// configured size. One source may hold maxPendingPerIP connections in the
// pre-auth stage, and the server holds maxPendingHandshakes across sources. A
// connection past either limit is refused, and no earlier one is.
func TestPreAuthLimitsLeaveRoomForRealClients(t *testing.T) {
	adm := newAdmission(maxPendingHandshakes, maxPendingPerIP)
	const busy = "203.0.113.30"
	for i := 0; i < maxPendingPerIP; i++ {
		if _, ok := adm.TryAcquire(busy); !ok {
			t.Fatalf("connection %d from one source refused below the per-source limit", i+1)
		}
	}
	if _, ok := adm.TryAcquire(busy); ok {
		t.Fatal("connection past the per-source limit admitted")
	}
	for i := maxPendingPerIP; i < maxPendingHandshakes; i++ {
		if _, ok := adm.TryAcquire(strconv.Itoa(i)); !ok {
			t.Fatalf("connection %d refused below the total limit", i+1)
		}
	}
	if n := adm.pendingCount(); n != maxPendingHandshakes {
		t.Fatalf("pending = %d, want %d", n, maxPendingHandshakes)
	}
	if _, ok := adm.TryAcquire("198.51.100.200"); ok {
		t.Fatal("connection past the total limit admitted")
	}
}

// refusedProbe runs the pre-auth stage for a connection from addr, while adm is
// full. The server must close the connection without reading it. The client's
// write then fails, and no decoy is dialed.
func refusedProbe(t *testing.T, adm *admission, addr string) {
	t.Helper()
	srv := newProbeServer(t, xnet.Destination{})
	srv.adm = adm
	dials := countDials(t, errors.New("unexpected dial"))

	client, server := net.Pipe()
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	before := adm.pendingCount()
	done := make(chan error, 1)
	go func() {
		_, err := srv.handlePreAuth(context.Background(), addrConn{Conn: server, addr: fixedAddr(addr)}, srv.pad)
		done <- err
	}()

	// net.Pipe holds a write until it is read or the far end closes. The write
	// fails only because the server closed without reading.
	if _, err := client.Write([]byte("GET ")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("write error = %v, want io.ErrClosedPipe from a connection closed unread", err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("refused connection was accepted")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pre-auth stage did not return")
	}
	if n := adm.pendingCount(); n != before {
		t.Fatalf("pending = %d after a refusal, want %d", n, before)
	}
	if n := dials.Load(); n != 0 {
		t.Fatalf("decoy dialed %d times for a refused connection", n)
	}
}

// Row 17 of section 12.2. Both the per-host and the total limits refuse a
// connection at once, without reading it.
func TestRefusedConnectionIsNotRead(t *testing.T) {
	t.Run("per host", func(t *testing.T) {
		adm := newAdmission(maxPendingHandshakes, maxPendingPerIP)
		for i := 0; i < maxPendingPerIP; i++ {
			if _, ok := adm.TryAcquire("203.0.113.7"); !ok {
				t.Fatalf("slot %d of the host refused below its limit", i)
			}
		}
		refusedProbe(t, adm, "203.0.113.7:5555")
	})
	t.Run("total", func(t *testing.T) {
		adm := newAdmission(2, maxPendingPerIP)
		for _, h := range []string{"203.0.113.1", "203.0.113.2"} {
			if _, ok := adm.TryAcquire(h); !ok {
				t.Fatalf("slot for %s refused below the total limit", h)
			}
		}
		refusedProbe(t, adm, "203.0.113.9:5555")
	})
}

// A client that the server accepts sends a request through Process. The
// destination answers through a fake dispatcher, and the reply reaches the
// client.
func TestClientRequestThroughProcess(t *testing.T) {
	clientKey := newKey(t)
	srv := newProbeServer(t, xnet.Destination{}, clientKey)

	// The destination echoes what the client uploads, then ends its output.
	upR, upW := pipe.New(pipe.WithoutSizeLimit())
	downR, downW := pipe.New(pipe.WithoutSizeLimit())
	go func() {
		buf.Copy(upR, downW)
		downW.Close()
	}()

	client, server := tcpPair(t)
	served := make(chan error, 1)
	go func() {
		served <- srv.Process(context.Background(), xnet.Network_TCP, server,
			fakeDispatcher{&transport.Link{Reader: downR, Writer: upW}})
	}()

	rc, err := ClientHandshake(client, clientKey, srv.privateKey.Public, testKeys(), defaultPadPolicy())
	if err != nil {
		t.Fatal(err)
	}
	header, err := encodeHeader(xnet.TCPDestination(xnet.ParseAddress("192.0.2.10"), 80))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rc.Write(header); err != nil {
		t.Fatal(err)
	}
	if _, err := rc.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if err := rc.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := rc.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(got) != "ping" {
		t.Fatalf("destination echoed %q, want %q", got, "ping")
	}
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("Process: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Process did not return")
	}
}

// TestRejectedProbeIsNotAnError covers a probe that Process closes at its decision.
// Process returns nil for it, so the server does not log every probe at info level.
// The decision is logged at debug level only.
func TestRejectedProbeIsNotAnError(t *testing.T) {
	logs := captureLogs(t)
	srv := newProbeServer(t, xnet.Destination{}) // no decoy: the probe is closed

	server, prober := tcpPair(t)
	if _, err := prober.Write([]byte("GET / HTTP/1.0\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	if err := srv.Process(context.Background(), xnet.Network_TCP, server, fakeDispatcher{}); err != nil {
		t.Fatalf("Process returned %v for a rejected probe, want nil", err)
	}

	lines := logs.lines()
	if len(lines) == 0 {
		t.Fatal("rejected probe was not logged")
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, "[Debug]") {
			t.Fatalf("rejected probe logged as %q, want debug level", line)
		}
	}
}

// coreContext returns a context that carries a core instance with the default
// policy manager, which NewServer and NewClient read.
func coreContext(t *testing.T) context.Context {
	t.Helper()
	v, err := core.New(&core.Config{})
	if err != nil {
		t.Fatal(err)
	}
	return context.WithValue(context.Background(), core.XrayKey(1), v)
}

// serverConfig returns a configuration that NewServer accepts, with a loopback
// fallback and no padding section. A test changes one field of it.
func serverConfig(t *testing.T) *ServerConfig {
	t.Helper()
	return &ServerConfig{
		PrivateKey: newKey(t).Private,
		Psk:        testPSK,
		Clients:    []*Account{{PublicKey: newKey(t).Public}},
		Fallback:   "127.0.0.1:8443",
	}
}

// TestNewServerValidation checks each configuration rule that NewServer applies.
// The limits are inclusive, so the values at each limit are accepted.
func TestNewServerValidation(t *testing.T) {
	ctx := coreContext(t)
	cases := []struct {
		name    string
		edit    func(*ServerConfig)
		wantErr string // empty when NewServer must accept the configuration
	}{
		{"padding handshake above the limit", func(c *ServerConfig) {
			c.Padding = &Padding{Handshake: 513}
		}, "padding handshake must be between 0 and 512"},
		{"padding frame above the limit", func(c *ServerConfig) {
			c.Padding = &Padding{Frame: 1025}
		}, "padding frame must be between 0 and 1024"},
		{"padding bucket below the minimum", func(c *ServerConfig) {
			c.Padding = &Padding{Bucket: 15}
		}, "padding bucket must be 0 or between 16 and 4096"},
		{"padding bucket above the maximum", func(c *ServerConfig) {
			c.Padding = &Padding{Bucket: 4097}
		}, "padding bucket must be 0 or between 16 and 4096"},
		{"padding at the limits", func(c *ServerConfig) {
			c.Padding = &Padding{Handshake: 512, Frame: 1024, Bucket: 4096}
		}, ""},
		{"padding at the minimum bucket", func(c *ServerConfig) {
			c.Padding = &Padding{Bucket: 16}
		}, ""},
		{"no fallback and no silent close", func(c *ServerConfig) {
			c.Fallback = ""
		}, `"fallback" is required unless "allowSilentClose" is set`},
		{"no fallback with silent close", func(c *ServerConfig) {
			c.Fallback = ""
			c.AllowSilentClose = true
		}, ""},
		{"fallback without a port", func(c *ServerConfig) {
			c.Fallback = "127.0.0.1"
		}, `"fallback" must be host:port`},
		{"fallback port zero", func(c *ServerConfig) {
			c.Fallback = "127.0.0.1:0"
		}, `"fallback" port must be between 1 and 65535`},
		{"fallback port too large", func(c *ServerConfig) {
			c.Fallback = "127.0.0.1:65536"
		}, `"fallback" port must be between 1 and 65535`},
		{"fallback without a host", func(c *ServerConfig) {
			c.Fallback = ":443"
		}, `"fallback" must name a host`},
		{"fallback IPv4 wildcard", func(c *ServerConfig) {
			c.Fallback = "0.0.0.0:443"
		}, `"fallback" must not be a wildcard address`},
		{"fallback IPv6 wildcard", func(c *ServerConfig) {
			c.Fallback = "[::]:443"
		}, `"fallback" must not be a wildcard address`},
		{"fallback IPv6 wildcard with a zone", func(c *ServerConfig) {
			c.Fallback = "[::%lo]:443"
		}, `"fallback" host must not have a zone`},
		{"fallback bare zero host", func(c *ServerConfig) {
			c.Fallback = "0:443"
		}, `"fallback" host must be a canonical IP address or a domain name`},
		{"private key of the wrong length", func(c *ServerConfig) {
			c.PrivateKey = make([]byte, 31)
		}, "private key must be 32 bytes"},
		{"client key of the wrong length", func(c *ServerConfig) {
			c.Clients = []*Account{{PublicKey: make([]byte, 31)}}
		}, "client 0 public key must be 32 bytes"},
		{"no clients", func(c *ServerConfig) {
			c.Clients = nil
		}, `"clients" must contain at least one client`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := serverConfig(t)
			tc.edit(config)
			_, err := NewServer(ctx, config)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("NewServer: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("NewServer error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

// TestNewServerStoresSettings checks what NewServer keeps from a valid
// configuration: the fallback, the silent-close flag and the padding.
func TestNewServerStoresSettings(t *testing.T) {
	ctx := coreContext(t)

	s, err := NewServer(ctx, serverConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	if got := s.fallback.NetAddr(); got != "127.0.0.1:8443" {
		t.Fatalf("fallback = %q, want 127.0.0.1:8443", got)
	}
	if s.allowSilentClose {
		t.Fatal("silent close is set without being configured")
	}

	silent := serverConfig(t)
	silent.Fallback = ""
	silent.AllowSilentClose = true
	s, err = NewServer(ctx, silent)
	if err != nil {
		t.Fatal(err)
	}
	if s.fallback.IsValid() || !s.allowSilentClose {
		t.Fatalf("fallback %v, silent close %v; want no fallback and silent close", s.fallback, s.allowSilentClose)
	}

	explicit := serverConfig(t)
	explicit.Padding = &Padding{Handshake: 0, Frame: 0, Bucket: 0}
	s, err = NewServer(ctx, explicit)
	if err != nil {
		t.Fatal(err)
	}
	if s.pad != (padPolicy{}) {
		t.Fatalf("explicit zero padding gave %+v, want all off", s.pad)
	}
}

// TestNewServerNilPaddingUsesDefaults checks that a missing padding section
// means the defaults, and not zero padding.
func TestNewServerNilPaddingUsesDefaults(t *testing.T) {
	s, err := NewServer(coreContext(t), serverConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	if s.pad != defaultPadPolicy() {
		t.Fatalf("pad = %+v, want the defaults %+v", s.pad, defaultPadPolicy())
	}
}
