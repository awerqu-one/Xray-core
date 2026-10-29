package raywire

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/flynn/noise"
	xnet "github.com/xtls/xray-core/common/net"
)

// probeGap spaces the bytes of the slow probe (row 21). The probe fits well
// inside the test budget, so it still arrives before the decision.
const probeGap = 50 * time.Millisecond

// probeCase is one probe class of section 12.2 as the harness sends it.
type probeCase struct {
	name  string
	probe []byte
	// held makes the prober wait for the decoy's banner before it ends its
	// side. Only a held probe shows the decoy's answer at the deadline, or
	// that the answer came at once.
	held bool
	// gap pauses between single bytes.
	gap time.Duration
	// reasons are the decisions that the row allows.
	reasons []string
	// atDeadline marks a row that raywire decides at the pre-auth deadline.
	atDeadline bool
	// warm is a first message that the server accepts before the probe, so
	// that the probe is a replay.
	warm []byte
}

// deadlineSpy records the first deadline that the server sets on its end of
// the connection. That is the pre-auth deadline, which held probes are timed
// against. It keeps CloseWrite, so the relay takes the TCP half-close path.
type deadlineSpy struct {
	net.Conn
	deadline time.Time
}

func (s *deadlineSpy) SetDeadline(t time.Time) error {
	s.note(t)
	return s.Conn.SetDeadline(t)
}

func (s *deadlineSpy) SetReadDeadline(t time.Time) error {
	s.note(t)
	return s.Conn.SetReadDeadline(t)
}

func (s *deadlineSpy) note(t time.Time) {
	if s.deadline.IsZero() && !t.IsZero() {
		s.deadline = t
	}
}

func (s *deadlineSpy) CloseWrite() error {
	cw, ok := s.Conn.(closeWriter)
	if !ok {
		return errors.New("probe: connection cannot half-close")
	}
	return cw.CloseWrite()
}

// probeReply is what the prober read in one exchange. bannerAt is the time the
// whole banner had arrived, for an exchange that waited for it.
type probeReply struct {
	got      []byte
	bannerAt time.Time
	err      error
}

// exchange sends probe on c and then reads until the peer ends. A held exchange
// waits for the banner before it ends its own side, so a decoy that answers
// late is seen as a prober would see it. gap pauses between single bytes.
func exchange(c *net.TCPConn, probe []byte, held bool, gap time.Duration) probeReply {
	var r probeReply
	if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		r.err = err
		return r
	}
	if gap == 0 {
		if _, err := c.Write(probe); err != nil {
			r.err = err
			return r
		}
	} else {
		for i := range probe {
			if i > 0 {
				time.Sleep(gap)
			}
			if _, err := c.Write(probe[i : i+1]); err != nil {
				r.err = err
				return r
			}
		}
	}
	if held {
		banner := make([]byte, len(bannerText))
		if _, err := io.ReadFull(c, banner); err != nil {
			r.err = err
			return r
		}
		r.bannerAt = time.Now()
		r.got = banner
	}
	if err := c.CloseWrite(); err != nil {
		r.err = err
		return r
	}
	rest, err := io.ReadAll(c)
	r.got = append(r.got, rest...)
	r.err = err
	return r
}

// directExchange sends probe straight to the decoy. Its reply is what the
// prober should read through raywire.
func directExchange(t *testing.T, decoy *net.TCPAddr, probe []byte, held bool) probeReply {
	t.Helper()
	c, err := net.DialTCP("tcp", nil, decoy)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return exchange(c, probe, held, 0)
}

// served is the server's side of one probe: the decision, the pre-auth
// deadline it set, and the prober's view.
type served struct {
	reply    probeReply
	decision error
	deadline time.Time
}

// serveProbe runs the pre-auth stage of srv on one loopback connection, and
// sends probe on the other end. It fails the test if the stage does not return
// or leaves a slot in use.
func serveProbe(t *testing.T, srv *Server, probe []byte, held bool, gap time.Duration) served {
	t.Helper()
	before := srv.adm.pendingCount()
	server, prober := tcpPair(t)
	spy := &deadlineSpy{Conn: server}
	done := make(chan error, 1)
	go func() {
		rc, err := srv.handlePreAuth(context.Background(), spy, srv.pad)
		if rc != nil {
			rc.Close()
		}
		done <- err
	}()

	var s served
	s.reply = exchange(prober, probe, held, gap)
	select {
	case s.decision = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("pre-auth stage did not return")
	}
	s.deadline = spy.deadline
	if n := srv.adm.pendingCount(); n != before {
		t.Fatalf("%d pre-auth slots in use after the decision, want %d", n, before)
	}
	return s
}

// acceptFirst sends msg1 to srv and requires that it is accepted, so that a
// later copy of the same bytes is a replay.
func acceptFirst(t *testing.T, srv *Server, msg1 []byte) {
	t.Helper()
	server, prober := tcpPair(t)
	type result struct {
		rc  *Conn
		err error
	}
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
}

// randomBytes returns n random bytes.
func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// probeCases lists the rows of section 12.2 that raywire relays, and the
// decisions each one allows. The rows with no relay are in
// TestRefusedProbesSendNothing. Row 1 is in TestEmptyProbeMatchesSilentDecoy.
func probeCases(t *testing.T, srv *Server, clientKey, otherKey noise.DHKey, now time.Time) []probeCase {
	t.Helper()
	serverPublic := srv.privateKey.Public
	prefix := []string{"prefix"}
	length := []string{"length"}
	noiseFail := []string{"noise"}
	deadline := []string{"deadline"}
	tag := []string{"tag"}
	replayA := recordMsg1(t, clientKey, serverPublic, now)
	replayB := recordMsg1(t, clientKey, serverPublic, now)

	return []probeCase{
		{name: "row 2 nothing sent, held to the deadline", held: true, reasons: deadline, atDeadline: true},
		{name: "row 3 one byte then end", probe: []byte{0x17}, reasons: []string{"eof"}},
		{name: "row 4 TLS start, held", probe: []byte(prefixTable2), held: true, reasons: prefix},
		{name: "row 4 TLS start, then end", probe: []byte("\x16\x03client hello"), reasons: prefix},
		{name: "row 5 HTTP method, held", probe: []byte("GET "), held: true, reasons: prefix},
		{name: "row 5 SSH banner, then end", probe: []byte("SSH-2.0-probe\r\n"), reasons: prefix},
		{name: "row 6 three bytes, held to the deadline", probe: []byte("abc"), held: true, reasons: deadline, atDeadline: true},
		// 34 silent bytes are short of the 50-byte head, so the server waits for the
		// deadline. The same bytes followed by the end are a plain end of stream.
		{name: "silent 34 bytes, held to the deadline", probe: randomHead(t, 34), held: true, reasons: deadline, atDeadline: true},
		{name: "silent 34 bytes, then end", probe: randomHead(t, 34), reasons: []string{"eof"}},
		{name: "row 7 random 50 bytes, held", probe: randomHead(t, hsHeadLen), held: true, reasons: tag},
		{name: "row 7 random 50 bytes, then end", probe: randomHead(t, hsHeadLen), reasons: tag},
		{name: "row 7 valid first message with a W1 bit flipped, held", probe: flipBit(recordMsg1(t, clientKey, serverPublic, now), hsKeyLen*8+3), held: true, reasons: tag},
		{name: "row 7 valid first message with bit 255 flipped, then end", probe: flipBit(recordMsg1(t, clientKey, serverPublic, now), 255), reasons: tag},
		{name: "row 8 in-range length, held to the deadline", probe: forgedMsg1(t, srv.privateKey, 72)[:hsHeadLen], held: true, reasons: deadline, atDeadline: true},
		{name: "row 9 bad tail behind a valid length, held", probe: forgedMsg1(t, srv.privateKey, 72), held: true, reasons: noiseFail},
		{name: "row 9 bad tail behind a valid length, then end", probe: forgedMsg1(t, srv.privateKey, 72), reasons: noiseFail},
		// A wrong server key changes the tag, so the server decides at byte 50.
		{name: "row 10 wrong server key, then end", probe: recordMsg1(t, clientKey, otherKey.Public, now), reasons: tag},
		{name: "row 11 unauthorized key, held", probe: recordMsg1(t, otherKey, serverPublic, now), held: true, reasons: []string{"unauthorized"}},
		{name: "row 11 unauthorized key, then end", probe: recordMsg1(t, otherKey, serverPublic, now), reasons: []string{"unauthorized"}},
		{name: "row 12 replay, held", probe: replayB, held: true, reasons: []string{"seen"}, warm: replayB},
		{name: "row 12 replay, then end", probe: replayA, reasons: []string{"seen"}, warm: replayA},
		{name: "row 13 timestamp ahead of the skew, held", probe: recordMsg1(t, clientKey, serverPublic, aheadOfSkew(now)), held: true, reasons: []string{"replay"}},
		// A restart empties the replay cache, so a first message from before the
		// filter's start is refused. Its timestamp is one second early, which is
		// inside the skew window, so only the filter's start refuses it.
		{name: "row 12 restart, first message from before the start, held", probe: recordMsg1(t, clientKey, serverPublic, srv.replay.notBefore.Add(-time.Second)), held: true, reasons: []string{"replay"}},
		{name: "row 12 restart, first message from before the start, then end", probe: recordMsg1(t, clientKey, serverPublic, srv.replay.notBefore.Add(-time.Second)), reasons: []string{"replay"}},
		{name: "row 21 slow probe, held to the deadline", probe: []byte("abc"), held: true, gap: probeGap, reasons: deadline, atDeadline: true},
		{name: "row 22 junk after a length out of range, then end", probe: append(forgedMsg1(t, srv.privateKey, 0), randomBytes(t, 30)...), reasons: length},
		{name: "row 22 junk after a length out of range, held", probe: append(forgedMsg1(t, srv.privateKey, 0), randomBytes(t, 30)...), held: true, reasons: length},
	}
}

// checkDecision requires that err is a HandshakeError with one of the reasons.
func checkDecision(t *testing.T, err error, reasons []string) {
	t.Helper()
	var he *HandshakeError
	if !errors.As(err, &he) {
		t.Fatalf("decision = %v, want a HandshakeError", err)
	}
	if !slices.Contains(reasons, he.Reason) {
		t.Fatalf("decision reason %q, want one of %q", he.Reason, reasons)
	}
}

// checkTiming requires the banner to come at or after the pre-auth deadline for
// the rows that raywire decides at the deadline, and before it for the rest.
func checkTiming(t *testing.T, p probeCase, s served) {
	t.Helper()
	if !p.held {
		return
	}
	if s.deadline.IsZero() {
		t.Fatal("pre-auth deadline was never set")
	}
	if p.atDeadline {
		if s.reply.bannerAt.Before(s.deadline) {
			t.Fatalf("banner at %v, before the pre-auth deadline %v", s.reply.bannerAt, s.deadline)
		}
		return
	}
	if !s.reply.bannerAt.Before(s.deadline) {
		t.Fatalf("banner at %v, after the pre-auth deadline %v; the decision waited for it", s.reply.bannerAt, s.deadline)
	}
}

// TestProbeEquivalence sends each relayed probe class of section 12.2 through
// raywire and straight to the decoy. The prober must read the same bytes both
// ways. Each reply must start with the banner, so that the test cannot pass on
// two empty replies.
func TestProbeEquivalence(t *testing.T) {
	setPreAuthTimeout(t, 200*time.Millisecond)
	decoy := startBannerDecoy(t)
	clientKey, otherKey := newKey(t), newKey(t)
	srv := newProbeServer(t, xnet.DestinationFromAddr(decoy), clientKey)

	for _, p := range probeCases(t, srv, clientKey, otherKey, time.Now()) {
		t.Run(p.name, func(t *testing.T) {
			if p.warm != nil {
				acceptFirst(t, srv, p.warm)
			}
			s := serveProbe(t, srv, p.probe, p.held, p.gap)
			if s.reply.err != nil {
				t.Fatalf("prober error: %v", s.reply.err)
			}
			checkDecision(t, s.decision, p.reasons)
			if !bytes.HasPrefix(s.reply.got, []byte(bannerText)) {
				t.Fatalf("prober read %q through raywire, want the decoy's reply", s.reply.got)
			}

			want := directExchange(t, decoy, p.probe, p.held)
			if want.err != nil {
				t.Fatalf("direct prober error: %v", want.err)
			}
			if !bytes.Equal(s.reply.got, want.got) {
				t.Fatalf("prober read %q through raywire, %q direct", s.reply.got, want.got)
			}
			checkTiming(t, p, s)
		})
	}
}

// TestEmptyProbeMatchesSilentDecoy covers row 1. A connection that ends before
// its first byte is closed with no dial. The decoy here waits for input, as an
// HTTP or TLS server does, so a direct connection also ends with no byte. A
// decoy that speaks first would send its banner on a direct connection, and
// raywire never dials for such a connection, so the two cannot match.
func TestEmptyProbeMatchesSilentDecoy(t *testing.T) {
	setPreAuthTimeout(t, 200*time.Millisecond)
	decoy := startSilentDecoy(t)
	srv := newProbeServer(t, xnet.DestinationFromAddr(decoy))
	dials := countDials(t, errors.New("unexpected dial"))

	s := serveProbe(t, srv, nil, false, 0)
	if s.reply.err != nil || len(s.reply.got) != 0 {
		t.Fatalf("prober read %q, error %v; want a clean end", s.reply.got, s.reply.err)
	}
	checkDecision(t, s.decision, []string{"eof"})
	if n := dials.Load(); n != 0 {
		t.Fatalf("decoy dialed %d times for an empty connection", n)
	}

	want := directExchange(t, decoy, nil, false)
	if want.err != nil || len(want.got) != 0 {
		t.Fatalf("direct connection read %q, error %v; want a clean end", want.got, want.err)
	}
}

// startSilentDecoy serves each connection by echoing what it reads, and sends
// nothing on connect. It answers an empty connection with a plain end.
func startSilentDecoy(t *testing.T) *net.TCPAddr {
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
				echo(c)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr)
}

// endedByPeer reports whether err is one of the ends that a refused connection
// may show: a clean end, a reset, a broken pipe, or a half-close on a socket the
// server has already closed (ENOTCONN, which the prober's CloseWrite may see).
func endedByPeer(err error) bool {
	return err == nil || errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ENOTCONN)
}

// refuseProbe sends probe to srv and checks the prober's view of a refused
// connection: no byte, an end (FIN or RST), and an end well before the
// pre-auth deadline. It returns the server's decision.
func refuseProbe(t *testing.T, srv *Server, probe []byte) error {
	t.Helper()
	started := time.Now()
	s := serveProbe(t, srv, probe, false, 0)
	if len(s.reply.got) != 0 {
		t.Fatalf("prober read %q from a refused connection", s.reply.got)
	}
	if !endedByPeer(s.reply.err) {
		t.Fatalf("prober error = %v, want an end or a reset", s.reply.err)
	}
	if elapsed := time.Since(started); elapsed >= preAuthTimeout {
		t.Fatalf("refused connection ended after %v, which is not before the pre-auth deadline", elapsed)
	}
	return s.decision
}

// fillAdmission takes n pre-auth slots for host and keeps them.
func fillAdmission(t *testing.T, adm *admission, host string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, ok := adm.TryAcquire(host); !ok {
			t.Fatalf("slot %d for %s refused below its limit", i, host)
		}
	}
}

// TestRefusedProbesSendNothing covers rows 17 to 20. raywire sends no byte in
// these rows, so the prober's bytes cannot match a direct connection, which the
// decoy answers. The test asserts the observable that section 12.2 gives for
// them: no byte, an end, and no wait for the pre-auth deadline. In rows 18 to
// 20 the handshake decides first, and then the relay refuses or cannot dial.
func TestRefusedProbesSendNothing(t *testing.T) {
	setPreAuthTimeout(t, 200*time.Millisecond)
	decoy := xnet.DestinationFromAddr(startBannerDecoy(t))
	probe := []byte("GET / HTTP/1.0\r\n\r\n")

	t.Run("row 17 per-host limit full", func(t *testing.T) {
		srv := newProbeServer(t, decoy)
		fillAdmission(t, srv.adm, "127.0.0.1", maxPendingPerIP)
		dials := countDials(t, errors.New("unexpected dial"))

		if err := refuseProbe(t, srv, probe); err == nil || reasonOf(err) != "" {
			t.Fatalf("decision = %v, want a refusal before any read", err)
		}
		if n := dials.Load(); n != 0 {
			t.Fatalf("decoy dialed %d times for a refused connection", n)
		}
	})

	t.Run("row 17 total limit full", func(t *testing.T) {
		srv := newProbeServer(t, decoy)
		srv.adm = newAdmission(2, maxPendingPerIP)
		fillAdmission(t, srv.adm, "198.51.100.1", 1)
		fillAdmission(t, srv.adm, "198.51.100.2", 1)
		dials := countDials(t, errors.New("unexpected dial"))

		if err := refuseProbe(t, srv, probe); err == nil || reasonOf(err) != "" {
			t.Fatalf("decision = %v, want a refusal before any read", err)
		}
		if n := dials.Load(); n != 0 {
			t.Fatalf("decoy dialed %d times for a refused connection", n)
		}
	})

	t.Run("row 18 relay pool full", func(t *testing.T) {
		srv := newProbeServer(t, decoy)
		srv.relay = newAdmission(1, maxRelaysPerIP)
		if _, ok := srv.relay.TryAcquire("127.0.0.1"); !ok {
			t.Fatal("new relay pool has no free slot")
		}
		dials := countDials(t, errors.New("unexpected dial"))

		checkDecision(t, refuseProbe(t, srv, probe), []string{"prefix"})
		if n := dials.Load(); n != 0 {
			t.Fatalf("decoy dialed %d times with a full relay pool", n)
		}
	})

	t.Run("row 19 decoy unreachable", func(t *testing.T) {
		srv := newProbeServer(t, decoy)
		dials := countDials(t, errors.New("connection refused"))

		checkDecision(t, refuseProbe(t, srv, probe), []string{"prefix"})
		if n := dials.Load(); n != 1 {
			t.Fatalf("decoy dialed %d times, want 1", n)
		}
	})

	t.Run("row 20 no decoy and silent close", func(t *testing.T) {
		srv := newProbeServer(t, xnet.Destination{})
		dials := countDials(t, errors.New("unexpected dial"))

		checkDecision(t, refuseProbe(t, srv, probe), []string{"prefix"})
		if n := dials.Load(); n != 0 {
			t.Fatalf("dialed %d times with no decoy", n)
		}
	})
}
