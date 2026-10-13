package raywire

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// connPair returns an authenticated client and server Conn over an in-memory
// pipe.
func connPair(t *testing.T) (client, server *Conn) {
	t.Helper()
	return connPairPad(t, defaultPadPolicy(), defaultPadPolicy())
}

// connPairPad is connPair with the pad policy of each side given by the caller.
func connPairPad(t *testing.T, cpol, spol padPolicy) (client, server *Conn) {
	t.Helper()

	clientKey, serverKey := newKey(t), newKey(t)
	cc, sc := net.Pipe()
	client, server, cerr, serr := runHandshake(t, cc, sc, clientKey, serverKey.Public, serverKey, cpol, spol)
	if cerr != nil || serr != nil {
		t.Fatalf("handshake: client=%v server=%v", cerr, serr)
	}
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	return client, server
}

// testPadModes covers every pad mode: off, the defaults, a bucket, and the
// largest pad that the sender may configure.
var testPadModes = []struct {
	name string
	pol  padPolicy
}{
	{"off", padPolicy{}},
	{"default", defaultPadPolicy()},
	{"bucket 256", padPolicy{Handshake: 255, Frame: 32, Bucket: 256}},
	{"maximum pad", padPolicy{Handshake: maxHandshakePad, Frame: maxFramePad}},
}

// fakeConn is a net.Conn whose reads come from r. Each Write is kept in out, and
// its size is recorded in writes, so a test can see what a Conn sends. The other
// methods come from the embedded Conn, which may be nil if a test never uses them.
type fakeConn struct {
	net.Conn
	r      io.Reader
	out    bytes.Buffer
	writes []int
}

func (c *fakeConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func (c *fakeConn) Write(p []byte) (int, error) {
	c.writes = append(c.writes, len(p))
	return c.out.Write(p)
}

// serveWire makes conn read its frames from wire instead of its transport. The
// receive state stays the same, so wire must hold frames that the peer sealed in
// order. The returned reader shows how many bytes were read.
func serveWire(conn *Conn, wire []byte) *bytes.Reader {
	src := bytes.NewReader(wire)
	conn.Conn = &fakeConn{Conn: conn.Conn, r: src}
	return src
}

// sealFrames seals each body plaintext as one frame, in order, with the send
// state of client, and returns the wire bytes. It builds frames that writeFrameV2
// would not send, such as an unknown type or a body that is too short.
func sealFrames(t *testing.T, client *Conn, bodies ...[]byte) []byte {
	t.Helper()

	var wire []byte
	for _, body := range bodies {
		frame, err := sealFrame(client.send, body)
		if err != nil {
			t.Fatal(err)
		}
		wire = append(wire, frame...)
	}
	return wire
}

// pattern returns n bytes of content that is not repetitive, so that a misplaced
// byte shows up in a comparison.
func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i/251)
	}
	return b
}

// frameBounds returns the smallest and largest body length that frameBp may
// choose for a payload of n bytes under pol.
func frameBounds(n int, pol padPolicy, firstHS bool) (lo, hi int) {
	lo = frameHeaderSize + n
	if pol.Bucket > 0 {
		b := min(roundUp(lo, pol.Bucket), maxFrameBody)
		return b, b
	}
	pad := pol.Frame
	if firstHS {
		pad = pol.Handshake
	}
	return lo, min(lo+pad, maxFrameBody)
}

// sendFrames writes one data frame of each size in sizes, then ends the stream. A
// size above the policy's frame payload is split by Write, as a caller's would be.
func sendFrames(c *Conn, sizes []int) error {
	for _, n := range sizes {
		if n > c.pad.maxPayload() {
			if _, err := c.Write(pattern(n)); err != nil {
				return err
			}
			continue
		}
		if err := c.writeFrameV2(frameData, pattern(n)); err != nil {
			return err
		}
	}
	return c.CloseWrite()
}

// checkFrames reads back the payloads that sendFrames wrote, then checks for the
// end of the stream.
func checkFrames(t *testing.T, c *Conn, sizes []int) {
	t.Helper()

	for _, n := range sizes {
		got := make([]byte, n)
		if _, err := io.ReadFull(c, got); err != nil {
			t.Fatalf("read %d-byte payload: %v", n, err)
		}
		if !bytes.Equal(got, pattern(n)) {
			t.Fatalf("%d-byte payload differs from the one sent", n)
		}
	}
	if n, err := c.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("Read after the last payload = %d, %v; want 0, io.EOF", n, err)
	}
}

func TestHalfCloseRoundTrip(t *testing.T) {
	client, server := connPair(t)

	sendErr := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte("request"))
		if err == nil {
			err = client.CloseWrite()
		}
		sendErr <- err
	}()

	request, err := io.ReadAll(server)
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	if string(request) != "request" {
		t.Fatalf("server got %q, want %q", request, "request")
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("client upload: %v", err)
	}

	// The server's direction is still open after the client's end of stream.
	go func() {
		_, err := server.Write([]byte("response"))
		if err == nil {
			err = server.CloseWrite()
		}
		sendErr <- err
	}()

	response, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(response) != "response" {
		t.Fatalf("client got %q, want %q", response, "response")
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("server reply: %v", err)
	}
}

func TestCloseWriteWhileReading(t *testing.T) {
	client, server := connPair(t)

	type result struct {
		data []byte
		err  error
	}
	readDone := make(chan result, 1)
	go func() {
		buf := make([]byte, 16)
		n, err := client.Read(buf)
		readDone <- result{buf[:n], err}
	}()

	// net.Pipe is synchronous, so CloseWrite returns only after the server
	// reads the frame. The server reads in its own goroutine, and a timeout
	// reports a CloseWrite that waits for the blocked Read.
	serverDone := make(chan error, 1)
	go func() {
		_, err := io.ReadAll(server)
		serverDone <- err
	}()
	closeDone := make(chan error, 1)
	go func() {
		closeDone <- client.CloseWrite()
	}()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("CloseWrite: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("CloseWrite blocked behind the pending Read")
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server read: %v", err)
	}
	if _, err := server.Write([]byte("pong")); err != nil {
		t.Fatalf("server write: %v", err)
	}

	r := <-readDone
	if r.err != nil || string(r.data) != "pong" {
		t.Fatalf("client read = %q, %v; want %q, nil", r.data, r.err, "pong")
	}
}

func TestTruncatedStreamIsUnexpectedEOF(t *testing.T) {
	client, server := connPair(t)

	// Closing without CloseWrite looks like a peer that stopped at a frame
	// boundary. Read must not report that as a clean end.
	sendErr := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte("partial"))
		if err == nil {
			err = client.Close()
		}
		sendErr <- err
	}()

	got, err := io.ReadAll(server)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("server read error = %v, want io.ErrUnexpectedEOF", err)
	}
	if string(got) != "partial" {
		t.Fatalf("server got %q before the error, want %q", got, "partial")
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("client: %v", err)
	}
}

func TestTruncatedFrameIsUnexpectedEOF(t *testing.T) {
	cases := []struct {
		name string
		n    int // bytes of the frame that reach the reader
	}{
		{"no bytes", 0},
		{"partial header", 5},
		{"header only", frameHdrCipher},
		{"partial body", frameHdrCipher + 5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server := connPair(t)
			wire := sealFrames(t, client, []byte{frameData, 0, 3, 'a', 'b', 'c'})
			serveWire(server, wire[:tc.n])

			got, err := io.ReadAll(server)
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("server read error = %v, want io.ErrUnexpectedEOF", err)
			}
			if len(got) != 0 {
				t.Fatalf("server got %q from a truncated frame", got)
			}
		})
	}
}

func TestCloseWriteSendsOneEndOfStream(t *testing.T) {
	client, server := connPair(t)

	// net.Pipe blocks until read, so the first CloseWrite runs beside the
	// server's Read.
	closeErr := make(chan error, 1)
	go func() {
		closeErr <- client.CloseWrite()
	}()
	if n, err := server.Read(make([]byte, 8)); n != 0 || err != io.EOF {
		t.Fatalf("server Read = %d, %v; want 0, io.EOF", n, err)
	}
	if err := <-closeErr; err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if _, err := client.Write([]byte("late")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("Write after CloseWrite = %v, want io.ErrClosedPipe", err)
	}

	// A write deadline in the past makes any frame write fail at once, so a
	// second CloseWrite that sent a frame would return an error.
	if err := client.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatalf("second CloseWrite: %v", err)
	}

	// No extra frame may be on the wire. The read deadline turns a silent
	// stream into a timeout error.
	if err := server.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := server.readFrameV2(); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("readFrameV2 after second CloseWrite = %v, want a deadline timeout", err)
	}
	// io.EOF is returned again on every later call, without reading the stream.
	if n, err := server.Read(make([]byte, 8)); n != 0 || err != io.EOF {
		t.Fatalf("second server Read = %d, %v; want 0, io.EOF", n, err)
	}
}

func TestEmptyWriteSendsNothing(t *testing.T) {
	client, _ := connPair(t)

	if err := client.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	for _, p := range [][]byte{nil, {}} {
		if n, err := client.Write(p); n != 0 || err != nil {
			t.Fatalf("Write(%v) = %d, %v; want 0, nil", p, n, err)
		}
	}
}

func TestEmptyDataFrameSkipped(t *testing.T) {
	client, server := connPair(t)

	sendErr := make(chan error, 1)
	go func() {
		// An empty data frame, then one with a byte, then the end of stream.
		err := client.writeFrameV2(frameData, nil)
		if err == nil {
			err = client.writeFrameV2(frameData, []byte("x"))
		}
		if err == nil {
			err = client.writeFrameV2(frameEnd, nil)
		}
		sendErr <- err
	}()

	got, err := io.ReadAll(server)
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	if string(got) != "x" {
		t.Fatalf("server got %q, want %q", got, "x")
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("client: %v", err)
	}
}

func TestUnknownFrameTypeRejected(t *testing.T) {
	for _, typ := range []byte{0x02, 0x7f} {
		t.Run(fmt.Sprintf("type 0x%02x", typ), func(t *testing.T) {
			client, server := connPair(t)
			serveWire(server, sealFrames(t, client, []byte{typ, 0, 0}))

			_, err := server.Read(make([]byte, 16))
			want := fmt.Sprintf("0x%02x", typ)
			if err == nil || errors.Is(err, io.EOF) || !strings.Contains(err.Error(), want) {
				t.Fatalf("server read error = %v, want an error that names type %s", err, want)
			}
		})
	}
}

func TestMalformedFrameRejected(t *testing.T) {
	cases := []struct {
		name string
		body []byte
		want error
	}{
		{"end-of-stream with payload", []byte{frameEnd, 0, 1, 'x'}, errEndHasPayload},
		{"payload past the body", []byte{frameData, 0, 5, 'x'}, errFramePastBody},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server := connPair(t)
			serveWire(server, sealFrames(t, client, tc.body))

			_, err := server.Read(make([]byte, 16))
			if !errors.Is(err, tc.want) {
				t.Fatalf("server read error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestShortBodyPrefixFailsAfterHeader(t *testing.T) {
	client, server := connPair(t)
	// A header that authenticates and says the body is 2 bytes. The 3-byte
	// prefix does not fit, so the reader must stop before the body.
	wire := sealFrames(t, client, []byte{frameData, 0})
	src := serveWire(server, wire)

	_, err := server.Read(make([]byte, 16))
	if !errors.Is(err, errFrameTooShort) {
		t.Fatalf("server read error = %v, want %v", err, errFrameTooShort)
	}
	if read := len(wire) - src.Len(); read != frameHdrCipher {
		t.Fatalf("reader consumed %d bytes, want the %d-byte header only", read, frameHdrCipher)
	}
}

func TestFlippedHeaderFailsAfterHeader(t *testing.T) {
	client, server := connPair(t)
	wire := sealFrames(t, client, []byte{frameData, 0, 4, 'd', 'a', 't', 'a'})
	wire[0] ^= 0x01

	src := serveWire(server, wire)
	_, err := server.Read(make([]byte, 16))
	if !errors.Is(err, errFrameAuth) {
		t.Fatalf("server read error = %v, want %v", err, errFrameAuth)
	}
	if read := len(wire) - src.Len(); read != frameHdrCipher {
		t.Fatalf("reader consumed %d bytes, want the %d-byte header only", read, frameHdrCipher)
	}
}

func TestFlippedBodyFailsAuthentication(t *testing.T) {
	client, server := connPair(t)
	wire := sealFrames(t, client, []byte{frameData, 0, 4, 'd', 'a', 't', 'a'})
	wire[len(wire)-1] ^= 0x01

	src := serveWire(server, wire)
	_, err := server.Read(make([]byte, 16))
	if !errors.Is(err, errFrameAuth) {
		t.Fatalf("server read error = %v, want %v", err, errFrameAuth)
	}
	if src.Len() != 0 {
		t.Fatalf("reader left %d bytes unread, want the whole frame read", src.Len())
	}
}

// TestBadHeaderAllocatesNoBody checks the allocation rule. A header that fails
// authentication must not cause the body buffer to be allocated, since the body
// length is the peer's choice.
func TestBadHeaderAllocatesNoBody(t *testing.T) {
	_, server := connPair(t)

	// The decryption output and the AEAD nonce are the only allocations here.
	// A body buffer would add a third, and it could be 64 KiB.
	const maxAllocs = 2
	junk := bytes.Repeat([]byte{0xAB}, frameHdrCipher)
	src := bytes.NewReader(nil)
	rx := newConn(&fakeConn{r: src}, nil, server.recv, padPolicy{}, false)

	failed := false
	allocs := testing.AllocsPerRun(100, func() {
		src.Reset(junk)
		if _, err := rx.readFrameV2(); !errors.Is(err, errFrameAuth) {
			failed = true
		}
	})
	if failed {
		t.Fatal("a bad header did not fail authentication")
	}
	if allocs > maxAllocs {
		t.Fatalf("a bad header allocated %v times, want at most %d", allocs, maxAllocs)
	}
}

func TestRoundTripPadModes(t *testing.T) {
	sizes := []int{0, 1, 39, 40, 8192, maxPlaintext}
	for _, m := range testPadModes {
		t.Run(m.name, func(t *testing.T) {
			client, server := connPairPad(t, m.pol, m.pol)

			sendErr := make(chan error, 1)
			go func() { sendErr <- sendFrames(client, sizes) }()
			checkFrames(t, server, sizes)
			if err := <-sendErr; err != nil {
				t.Fatalf("client: %v", err)
			}

			// The other direction uses the server's pad, with the same checks.
			go func() { sendErr <- sendFrames(server, sizes) }()
			checkFrames(t, client, sizes)
			if err := <-sendErr; err != nil {
				t.Fatalf("server: %v", err)
			}
		})
	}
}

func TestFrameWireSize(t *testing.T) {
	padSource(t, 11)
	client, server := connPair(t)
	sizes := []int{0, 1, 13, 61, 8192, maxPlaintext}

	for _, m := range testPadModes {
		for _, firstHS := range []bool{false, true} {
			for _, n := range sizes {
				sink := &fakeConn{}
				c := newConn(sink, client.send, nil, m.pol, firstHS)
				// A frame above the policy's payload limit is refused, not sent.
				if n > m.pol.maxPayload() {
					if err := c.writeFrameV2(frameData, pattern(n)); err != errFrameTooLarge {
						t.Fatalf("%s n=%d: got %v, want errFrameTooLarge", m.name, n, err)
					}
					continue
				}
				if err := c.writeFrameV2(frameData, pattern(n)); err != nil {
					t.Fatal(err)
				}

				// The receiver authenticates the header, so the body length it finds
				// is the one the sender chose.
				rx := newConn(&fakeConn{r: bytes.NewReader(sink.out.Bytes())}, nil, server.recv, padPolicy{}, false)
				pt, err := rx.readFrameV2()
				if err != nil {
					t.Fatalf("%s firstHS=%v n=%d: %v", m.name, firstHS, n, err)
				}
				bp := len(pt)
				if got, want := sink.writes[0], frameHdrCipher+bp+tagSize; got != want {
					t.Fatalf("%s firstHS=%v n=%d: wire size %d, want %d (34 + Bp, Bp = %d)", m.name, firstHS, n, got, want, bp)
				}
				lo, hi := frameBounds(n, m.pol, firstHS)
				if bp < lo || bp > hi {
					t.Fatalf("%s firstHS=%v n=%d: Bp = %d, want in [%d, %d]", m.name, firstHS, n, bp, lo, hi)
				}
			}
		}
	}
}

func TestBucketFrameSizes(t *testing.T) {
	padSource(t, 12)
	client, _ := connPair(t)

	for _, block := range []int{16, 256, 4096} {
		for _, n := range []int{0, 1, 13, 61, 64, 65, 8192, maxPlaintext} {
			sink := &fakeConn{}
			pol := padPolicy{Frame: 32, Bucket: block}
			c := newConn(sink, client.send, nil, pol, false)
			// A payload that would need a body past the 2-byte length is refused, so
			// every body that is sent is a whole number of blocks.
			if n > pol.maxPayload() {
				if err := c.writeFrameV2(frameData, pattern(n)); err != errFrameTooLarge {
					t.Fatalf("bucket %d n=%d: got %v, want errFrameTooLarge", block, n, err)
				}
				continue
			}
			if err := c.writeFrameV2(frameData, pattern(n)); err != nil {
				t.Fatal(err)
			}
			bp := sink.writes[0] - frameHdrCipher - tagSize
			if bp%block != 0 {
				t.Fatalf("bucket %d n=%d: Bp = %d is not a multiple of the block", block, n, bp)
			}
			if bp < frameHeaderSize+n {
				t.Fatalf("bucket %d n=%d: Bp = %d is below the payload", block, n, bp)
			}
		}
	}
}

// TestFirstFrameUsesHandshakePad checks the sender's pad range. The client's
// first frame takes the handshake range, and the frame after it takes the frame
// range.
func TestFirstFrameUsesHandshakePad(t *testing.T) {
	padSource(t, 13)
	client, _ := connPair(t)
	pol := padPolicy{Handshake: 255, Frame: 32}

	const draws = 10000
	var bins [8]int // handshake pads 0..255, in bins of 32
	beyondFrame := 0
	for range draws {
		sink := &fakeConn{}
		c := newConn(sink, client.send, nil, pol, true)
		if err := c.writeFrameV2(frameData, nil); err != nil {
			t.Fatal(err)
		}
		if err := c.writeFrameV2(frameData, nil); err != nil {
			t.Fatal(err)
		}
		first := sink.writes[0] - frameHdrCipher - tagSize - frameHeaderSize
		second := sink.writes[1] - frameHdrCipher - tagSize - frameHeaderSize
		if first < 0 || first > 255 {
			t.Fatalf("first frame pad = %d, want in [0, 255]", first)
		}
		if second < 0 || second > 32 {
			t.Fatalf("second frame pad = %d, want in [0, 32]", second)
		}
		bins[first/32]++
		if first > 32 {
			beyondFrame++
		}
	}

	// A first frame that stayed in the frame range would show up as empty bins.
	if beyondFrame == 0 {
		t.Fatal("no first frame used a pad beyond the frame range")
	}
	// Chi-square over 8 bins with 7 degrees of freedom. The 0.001 critical value
	// is 24.32. The source is seeded, so the result is the same on every run.
	expected := float64(draws) / float64(len(bins))
	chi := 0.0
	for _, c := range bins {
		d := float64(c) - expected
		chi += d * d / expected
	}
	if chi > 24.32 {
		t.Fatalf("first-frame pad chi-square = %.2f, want <= 24.32 (bins %v)", chi, bins)
	}
}

func TestLargePayloadRoundTrip(t *testing.T) {
	client, server := connPair(t)

	// Larger than three full data frames, so Write has to split it.
	payload := make([]byte, 3*maxPlaintext+123)
	for i := range payload {
		payload[i] = byte(i * 7)
	}

	sendErr := make(chan error, 1)
	go func() {
		_, err := client.Write(payload)
		if err == nil {
			err = client.CloseWrite()
		}
		sendErr <- err
	}()

	got, err := io.ReadAll(server)
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload mismatch")
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("client write: %v", err)
	}
}
