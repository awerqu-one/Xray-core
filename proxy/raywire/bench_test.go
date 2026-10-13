package raywire

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/flynn/noise"
)

// benchConn is an in-memory net.Conn for benchmarks. Reads come from in, writes go
// to out, and every written byte is counted. Deadlines are no-ops.
type benchConn struct {
	net.Conn
	in  io.Reader
	out io.Writer
	n   int
}

func (c *benchConn) Read(p []byte) (int, error) { return c.in.Read(p) }

func (c *benchConn) Write(p []byte) (int, error) {
	c.n += len(p)
	return c.out.Write(p)
}

func (c *benchConn) SetDeadline(time.Time) error { return nil }
func (c *benchConn) Close() error                { return nil }

// loopConn runs the server side synchronously inside each client Write, so the
// client can be timed alone. When b is set, the timer is stopped while the
// server runs.
type loopConn struct {
	net.Conn
	b         *testing.B
	serverKey noise.DHKey
	authorize func([]byte) bool
	pol       padPolicy
	reply     bytes.Buffer
	srv       *Conn
	msg1      int
}

func (c *loopConn) Write(p []byte) (int, error) {
	c.msg1 += len(p)
	if c.b != nil {
		c.b.StopTimer()
	}
	// A failed server leaves reply empty, so the client's Read returns io.EOF.
	c.srv, _ = ServerHandshake(&benchConn{in: bytes.NewReader(p), out: &c.reply}, c.serverKey, c.authorize, NewReplayFilter(), nil, testHeadKeys(), c.pol)
	if c.b != nil {
		c.b.StartTimer()
	}
	return len(p), nil
}

func (c *loopConn) Read(p []byte) (int, error)  { return c.reply.Read(p) }
func (c *loopConn) SetDeadline(time.Time) error { return nil }
func (c *loopConn) Close() error                { return nil }

// benchKeys returns a fresh server and client key for a benchmark.
func benchKeys(b *testing.B) (server, client noise.DHKey) {
	b.Helper()
	var err error
	if server, err = GenerateKey(); err != nil {
		b.Fatal(err)
	}
	if client, err = GenerateKey(); err != nil {
		b.Fatal(err)
	}
	return server, client
}

// establish returns a client Conn whose handshake ran against a real server Conn.
func establish(b *testing.B, pol padPolicy) *Conn {
	b.Helper()
	serverKey, clientKey := benchKeys(b)
	lc := &loopConn{
		serverKey: serverKey,
		authorize: func(pub []byte) bool { return bytes.Equal(pub, clientKey.Public) },
		pol:       pol,
	}
	cli, err := ClientHandshake(lc, clientKey, serverKey.Public, testKeys(), pol)
	if err != nil {
		b.Fatal(err)
	}
	return cli
}

// BenchmarkClientHandshake times the client side of one handshake. The server
// side runs inside the client's first Write with the timer stopped.
func BenchmarkClientHandshake(b *testing.B) {
	serverKey, clientKey := benchKeys(b)
	authorize := func(pub []byte) bool { return bytes.Equal(pub, clientKey.Public) }
	pol := defaultPadPolicy()

	msg1 := 0
	b.ResetTimer()
	for range b.N {
		lc := &loopConn{b: b, serverKey: serverKey, authorize: authorize, pol: pol}
		if _, err := ClientHandshake(lc, clientKey, serverKey.Public, testKeys(), pol); err != nil {
			b.Fatal(err)
		}
		msg1 += lc.msg1
	}
	b.ReportMetric(float64(msg1)/float64(b.N), "msg1-B/op")
}

// BenchmarkServerHandshake times the server side of one handshake on a recorded
// msg1. The client that produced msg1 runs with the timer stopped.
func BenchmarkServerHandshake(b *testing.B) {
	serverKey, clientKey := benchKeys(b)
	authorize := func(pub []byte) bool { return bytes.Equal(pub, clientKey.Public) }
	pol := defaultPadPolicy()

	for range b.N {
		b.StopTimer()
		var msg1 bytes.Buffer
		// The client fails reading msg2, which is empty here. msg1 is all it needs.
		if _, err := ClientHandshake(&benchConn{in: strings.NewReader(""), out: &msg1}, clientKey, serverKey.Public, testKeys(), pol); err == nil {
			b.Fatal("client handshake succeeded without a server reply")
		}
		replay := NewReplayFilter()
		b.StartTimer()

		if _, err := ServerHandshake(&benchConn{in: bytes.NewReader(msg1.Bytes()), out: io.Discard}, serverKey, authorize, replay, nil, testHeadKeys(), pol); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkServerJunkProbe times the server on a junk probe of one head, whose tag
// does not verify. The server decides at byte 50 with one HMAC and reads nothing
// more, so this is the whole pre-auth cost of a junk probe.
func BenchmarkServerJunkProbe(b *testing.B) {
	serverKey, _ := benchKeys(b)
	// A fixed head keeps the bytes, and so the probe, the same on every run. Its first
	// bytes match no probe table entry, so the server reads the whole head.
	probe := bytes.Repeat([]byte{0x5a}, hsHeadLen)
	allowAll := func([]byte) bool { return true }
	replay := NewReplayFilter()
	pol := defaultPadPolicy()

	b.ResetTimer()
	for range b.N {
		_, err := ServerHandshake(&benchConn{in: bytes.NewReader(probe), out: io.Discard}, serverKey, allowAll, replay, nil, testHeadKeys(), pol)
		var he *HandshakeError
		if !errors.As(err, &he) || he.Reason != "tag" {
			b.Fatalf("junk probe was not decided on the tag: %v", err)
		}
	}
}

// BenchmarkServerReplayedHead times the server on a valid first message that it has
// already accepted. The head and the remainder pass S6 to S13 in full, and the replay
// filter refuses the message at S14. No threshold applies, and the result goes to
// BENCH.txt (residual R11).
func BenchmarkServerReplayedHead(b *testing.B) {
	serverKey, clientKey := benchKeys(b)
	authorize := func(pub []byte) bool { return bytes.Equal(pub, clientKey.Public) }
	pol := defaultPadPolicy()

	var msg1 bytes.Buffer
	// The client fails reading msg2, which is empty here. msg1 is all it needs.
	if _, err := ClientHandshake(&benchConn{in: strings.NewReader(""), out: &msg1}, clientKey, serverKey.Public, testKeys(), pol); err == nil {
		b.Fatal("client handshake succeeded without a server reply")
	}
	replay := NewReplayFilter()
	if _, err := ServerHandshake(&benchConn{in: bytes.NewReader(msg1.Bytes()), out: io.Discard}, serverKey, authorize, replay, nil, testHeadKeys(), pol); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for range b.N {
		_, err := ServerHandshake(&benchConn{in: bytes.NewReader(msg1.Bytes()), out: io.Discard}, serverKey, authorize, replay, nil, testHeadKeys(), pol)
		var he *HandshakeError
		if !errors.As(err, &he) || he.Reason != "replay" {
			b.Fatalf("replayed first message was not refused as a replay: %v", err)
		}
	}
}

// BenchmarkServerSeenHead times the server on a valid first message whose head was
// accepted and is still remembered (seen.go). The tag verifies, the wire key is found,
// and the server answers at byte 50 with no DH and no Noise. Compare it with
// BenchmarkServerJunkProbe (target: within 2x) and with BenchmarkServerReplayedHead.
func BenchmarkServerSeenHead(b *testing.B) {
	serverKey, clientKey := benchKeys(b)
	authorize := func(pub []byte) bool { return bytes.Equal(pub, clientKey.Public) }
	pol := defaultPadPolicy()

	var msg1 bytes.Buffer
	// The client fails reading msg2, which is empty here. msg1 is all it needs.
	if _, err := ClientHandshake(&benchConn{in: strings.NewReader(""), out: &msg1}, clientKey, serverKey.Public, testKeys(), pol); err == nil {
		b.Fatal("client handshake succeeded without a server reply")
	}
	seen := newSeenHeads(seenHeadCap, seenHeadTTL, time.Now())
	b.Cleanup(seen.Close)
	allow := func(pub []byte) (*Account, bool) { return &Account{PublicKey: pub}, authorize(pub) }
	if _, err := serverHandshake(&benchConn{in: bytes.NewReader(msg1.Bytes()), out: io.Discard}, serverKey, allow, NewReplayFilter(), seen, testHeadKeys(), pol); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for range b.N {
		_, err := serverHandshake(&benchConn{in: bytes.NewReader(msg1.Bytes()), out: io.Discard}, serverKey, allow, NewReplayFilter(), seen, testHeadKeys(), pol)
		var he *HandshakeError
		if !errors.As(err, &he) || he.Reason != "seen" {
			b.Fatalf("remembered first message was not answered as seen: %v", err)
		}
	}
}

// benchPads are the frame padding modes measured in the frame benchmarks.
var benchPads = []struct {
	name string
	pol  padPolicy
}{
	{"off", padPolicy{}},
	{"default", defaultPadPolicy()},
	{"bucket256", padPolicy{Handshake: 255, Bucket: 256}},
}

// BenchmarkWrite measures sealing and sending one Write, for each padding mode.
// The wire bytes per call show the frame overhead.
func BenchmarkWrite(b *testing.B) {
	for _, size := range []int{1, 64 << 10} {
		for _, m := range benchPads {
			b.Run(sizeName(size)+"/"+m.name, func(b *testing.B) {
				cli := establish(b, m.pol)
				sink := &benchConn{out: io.Discard}
				cli.Conn = sink
				cli.pad = m.pol
				cli.firstFrameHS = false

				payload := make([]byte, size)
				b.SetBytes(int64(size))
				b.ResetTimer()
				for range b.N {
					if _, err := cli.Write(payload); err != nil {
						b.Fatal(err)
					}
				}
				b.ReportMetric(float64(sink.n)/float64(b.N), "wire-B/op")
			})
		}
	}
}

func sizeName(n int) string {
	if n >= 1<<10 {
		return "64KiB"
	}
	return "1B"
}
