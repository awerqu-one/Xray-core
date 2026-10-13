package raywire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	mrand "math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/flynn/noise"
	"golang.org/x/crypto/curve25519"
)

// fuzzKey returns the key pair with the given byte repeated as its private half.
func fuzzKey(tb testing.TB, seed byte) noise.DHKey {
	tb.Helper()
	k, err := keyFromPrivate(bytes.Repeat([]byte{seed}, 32))
	if err != nil {
		tb.Fatal(err)
	}
	return k
}

// makeMsg1 returns a valid msg1 from clientKey to serverPublic, with the default pad.
func makeMsg1(tb testing.TB, clientKey noise.DHKey, serverPublic []byte) []byte {
	tb.Helper()
	return makeMsg1Pad(tb, clientKey, serverPublic, defaultPadPolicy())
}

// makeMsg1Pad is makeMsg1 with the handshake pad given.
func makeMsg1Pad(tb testing.TB, clientKey noise.DHKey, serverPublic []byte, pol padPolicy) []byte {
	tb.Helper()
	cc := newMemConn(nil)
	if _, err := ClientHandshake(cc, clientKey, serverPublic, testKeys(), pol); err == nil {
		tb.Fatal("client handshake succeeded without a server reply")
	}
	return cc.out.Bytes()
}

// FuzzServerHandshake feeds arbitrary bytes to the responder. It must not panic.
// A rejection reports exactly the bytes it read, which are a prefix of the input
// and at most hsMaxConsumed long. An acceptance needs a msg1 that the PSK holder and
// the authorized client could have sent. Any such msg1 is accepted, not only the seed,
// so the check is on its structure: the tag must verify, and the length word must
// decode to the bytes read.
func FuzzServerHandshake(f *testing.F) {
	clientKey := fuzzKey(f, 0x31)
	serverKey := fuzzKey(f, 0x32)
	accept := func(pub []byte) bool { return bytes.Equal(pub, clientKey.Public) }

	// Every fuzz worker runs this setup again, and each run must build the same
	// valid msg1, or the seeds from one run would not match the reference of
	// another. The randomness and the clock are fixed until the test ends.
	savedEph, savedPad, savedClock := ephRand, padRand, handshakeClock
	f.Cleanup(func() { ephRand, padRand, handshakeClock = savedEph, savedPad, savedClock })
	ephRand = mrand.NewChaCha8([32]byte{0x61})
	padRand = mrand.NewChaCha8([32]byte{0x62})
	handshakeClock = func() time.Time { return testNow }
	valid := makeMsg1(f, clientKey, serverKey.Public)
	padZero := makeMsg1Pad(f, clientKey, serverKey.Public, padPolicy{})
	padMax := makeMsg1Pad(f, clientKey, serverKey.Public, padPolicy{Handshake: maxHandshakePad})

	// Flipping bit 255 of R_e changes the tag, so it is a plain tag failure in v3.
	topBit := bytes.Clone(valid)
	topBit[hsKeyLen-1] ^= 0x80
	lastTag := bytes.Clone(valid)
	lastTag[len(lastTag)-1] ^= 1
	seeds := [][]byte{
		valid,
		padZero,
		padMax,
		topBit,
		valid[:len(valid)-1],
		lastTag,
		nil,
		[]byte("GET / HTTP/1.1\r\n\r\n"),
		{0x16, 0x03, 0x01},
		make([]byte, hsHeadLen),
		padMax[:hsHeadLen+hsMinN1],
		append(bytes.Clone(padMax), 0),
		make([]byte, hsMaxConsumed+1),
	}
	// Heads of each length around the probe decisions, read from the valid message.
	for _, n := range []int{0, 1, 2, 4, 33, 34, 49, 50, 51} {
		seeds = append(seeds, valid[:min(n, len(valid))])
	}
	// Every head byte flipped in turn. Each one makes the tag fail or a prefix match.
	for i := range hsHeadLen {
		b := bytes.Clone(valid)
		b[i] ^= 0x01
		seeds = append(seeds, b)
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		conn := newMemConn(input)
		_, err := ServerHandshake(conn, serverKey, accept, NewReplayFilter(), nil, testHeadKeys(), defaultPadPolicy())
		if err == nil {
			checkAccepted(t, input, conn, serverKey)
			return
		}
		checkRejected(t, input, conn, err)
	})
}

// checkAccepted requires an accepted input to be a msg1 of the authorized client.
// The tag must verify under the PSK, and the length word, under the server's DH
// secret, must give the remainder the server read. msg2 must have the length of R_s,
// the sealed count and 0 to maxHandshakePad pad bytes. Noise authenticates the rest.
func checkAccepted(t *testing.T, input []byte, conn *memConn, serverKey noise.DHKey) {
	t.Helper()

	if conn.n < hsHeadLen+hsMinN1 || conn.n > hsMaxConsumed {
		t.Fatalf("accepted after %d bytes, outside the msg1 range", conn.n)
	}
	R, W1, T := input[:hsKeyLen], input[hsKeyLen:hsKeyLen+2], input[hsKeyLen+2:hsHeadLen]
	if !bytes.Equal(T, refTag(refHeadKey(testPSK), serverKey.Public, R, W1)) {
		t.Fatal("accepted a head tag that the PSK does not give")
	}
	uc := canonicalDecode(R)
	dh, err := curve25519.X25519(serverKey.Private, uc)
	if err != nil {
		t.Fatalf("accepted an ephemeral point that X25519 rejects: %v", err)
	}
	n1 := int(binary.BigEndian.Uint16(W1) ^ refMaskWord(refMaskKey(testPSK), dh))
	if hsHeadLen+n1 != conn.n {
		t.Fatalf("accepted after %d bytes, but the length word gives %d", conn.n, hsHeadLen+n1)
	}
	if n := conn.out.Len(); n < hsKeyLen+hsCountLen || n > hsKeyLen+hsCountLen+maxHandshakePad {
		t.Fatalf("msg2 is %d bytes", n)
	}
}

// checkRejected requires a rejection to report exactly the bytes it read. Those bytes
// must be a prefix of the input, and the reason must fit the length, for example a
// probe table match at 2 or 4 bytes.
func checkRejected(t *testing.T, input []byte, conn *memConn, err error) {
	t.Helper()

	var he *HandshakeError
	if !errors.As(err, &he) {
		t.Fatalf("rejected with a non-handshake error: %v", err)
	}
	got := he.Consumed
	if len(got) != conn.n || len(got) > hsMaxConsumed {
		t.Fatalf("%s: consumed %d bytes, read %d, limit %d", he.Reason, len(got), conn.n, hsMaxConsumed)
	}
	if !bytes.Equal(got, input[:len(got)]) {
		t.Fatalf("%s: consumed bytes are not a prefix of the input", he.Reason)
	}
	switch he.Reason {
	case "eof":
		if len(got) != len(input) {
			t.Fatalf("eof after %d of %d input bytes", len(got), len(input))
		}
	case "prefix":
		if string(got) != prefixTable2 && !slices.Contains(prefixTable4, string(got)) {
			t.Fatalf("prefix at %d bytes matches no table entry", len(got))
		}
	case "tag", "length", "ephemeral", "seen":
		if len(got) != hsHeadLen {
			t.Fatalf("%s decided after %d bytes, want %d", he.Reason, len(got), hsHeadLen)
		}
	case "noise", "payload", "unauthorized", "replay":
		if len(got) < hsHeadLen+hsMinN1 {
			t.Fatalf("%s decided after %d bytes, before the minimum msg1", he.Reason, len(got))
		}
	default:
		t.Fatalf("unknown reason %q", he.Reason)
	}
}

// frameKeyFuzz is the key of the frame fuzzer's receiver and of its corpus sender.
var frameKeyFuzz = [32]byte{'r', 'a', 'y', 'w', 'i', 'r', 'e', '/', '3'}

// frameBody returns a body plaintext: type, big-endian payload length, payload, and
// pad zeros.
func frameBody(typ byte, payload []byte, pad int) []byte {
	b := make([]byte, frameHeaderSize+len(payload)+pad)
	b[0] = typ
	binary.BigEndian.PutUint16(b[1:frameHeaderSize], uint16(len(payload)))
	copy(b[frameHeaderSize:], payload)
	return b
}

// sealStream seals the bodies in order with one sender, as a client would send them.
func sealStream(tb testing.TB, key [32]byte, bodies ...[]byte) []byte {
	tb.Helper()
	send := noise.UnsafeNewCipherState(cipherSuite, key, 0)
	var out []byte
	for _, b := range bodies {
		wire, err := sealFrame(send, b)
		if err != nil {
			tb.Fatal(err)
		}
		out = append(out, wire...)
	}
	return out
}

// FuzzFrameReader feeds arbitrary bytes to the frame reader. The reader must
// return the same payload and error as an independent decoder, and it must read
// the same number of bytes. A header that fails authentication must stop it within
// frameHdrCipher bytes of that frame.
func FuzzFrameReader(f *testing.F) {
	key := frameKeyFuzz
	data := sealStream(f, key, frameBody(frameData, []byte("hello"), 3), frameBody(frameEnd, nil, 0))
	for _, seed := range [][]byte{
		nil,
		data,
		data[:len(data)-1],
		sealStream(f, key, frameBody(frameData, []byte("hello"), 0)),
		sealStream(f, key, frameBody(frameData, nil, 0), frameBody(frameEnd, nil, 0)),
		sealStream(f, key, frameBody(frameEnd, []byte{1}, 0)),
		sealStream(f, key, frameBody(0x02, nil, 0), frameBody(frameEnd, nil, 0)),
		sealStream(f, key, []byte{frameData, 0}),
		sealStream(f, key, []byte{frameData, 0xff, 0xff}),
		append(bytes.Clone(data), bytes.Repeat([]byte{0xAA}, 40)...),
		bytes.Repeat([]byte{0x5c}, 40),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		src := newMemConn(input)
		c := newConn(src, nil, noise.UnsafeNewCipherState(cipherSuite, key, 0), defaultPadPolicy(), false)
		got, err := io.ReadAll(c)
		want := referenceFrames(input, noise.UnsafeNewCipherState(cipherSuite, key, 0))
		compareFrames(t, got, err, src.n, want)
	})
}

// frameRef is what a correct reader does with a frame stream: the payload it
// returns, the error it returns, and how many bytes it reads before it decides.
type frameRef struct {
	payload []byte
	err     error // io.EOF after an end frame, or the sentinel for the failure
	unknown bool  // the decision was an unknown frame type
	reads   int
	// headerAt is the start of the frame whose header failed, or -1 when the
	// decision is not a header failure.
	headerAt int
}

// referenceFrames decodes the stream in the order of section 8.2, with its own
// receiver. It shares only the constants and the error values with Conn.
func referenceFrames(in []byte, recv *noise.CipherState) frameRef {
	var ref frameRef
	ref.headerAt = -1
	pos := 0
	for {
		if len(in)-pos < frameHdrCipher {
			ref.reads = len(in)
			ref.err = io.ErrUnexpectedEOF
			return ref
		}
		hdr, err := recv.Decrypt(nil, nil, in[pos:pos+frameHdrCipher])
		if err != nil {
			ref.reads = pos + frameHdrCipher
			ref.err = errFrameAuth
			ref.headerAt = pos
			return ref
		}
		bp := int(binary.BigEndian.Uint16(hdr))
		if bp < frameHeaderSize {
			ref.reads = pos + frameHdrCipher
			ref.err = errFrameTooShort
			ref.headerAt = pos
			return ref
		}
		end := pos + frameHdrCipher + bp + tagSize
		if end > len(in) {
			ref.reads = len(in)
			ref.err = io.ErrUnexpectedEOF
			return ref
		}
		pt, err := recv.Decrypt(nil, nil, in[pos+frameHdrCipher:end])
		ref.reads = end
		if err != nil {
			ref.err = errFrameAuth
			return ref
		}
		pos = end
		n := int(binary.BigEndian.Uint16(pt[1:frameHeaderSize]))
		if frameHeaderSize+n > len(pt) {
			ref.err = errFramePastBody
			return ref
		}
		switch pt[0] {
		case frameData:
			ref.payload = append(ref.payload, pt[frameHeaderSize:frameHeaderSize+n]...)
		case frameEnd:
			if n != 0 {
				ref.err = errEndHasPayload
			} else {
				ref.err = io.EOF
			}
			return ref
		default:
			ref.unknown = true
			return ref
		}
	}
}

// compareFrames compares the reader with the reference decoder.
func compareFrames(t *testing.T, got []byte, err error, read int, ref frameRef) {
	t.Helper()

	if !bytes.Equal(got, ref.payload) {
		t.Fatalf("payload: got %d bytes, want %d", len(got), len(ref.payload))
	}
	switch {
	case ref.unknown:
		if err == nil || !strings.Contains(err.Error(), "unknown frame type") {
			t.Fatalf("unknown frame type: got error %v", err)
		}
	case ref.err == io.EOF:
		if err != nil {
			t.Fatalf("end of stream: got error %v", err)
		}
	default:
		if !errors.Is(err, ref.err) {
			t.Fatalf("got error %v, want %v", err, ref.err)
		}
	}
	if read != ref.reads {
		t.Fatalf("read %d bytes, a correct reader reads %d", read, ref.reads)
	}
	if ref.headerAt >= 0 && read-ref.headerAt > frameHdrCipher {
		t.Fatalf("header failure read %d bytes past the frame start, limit %d", read-ref.headerAt, frameHdrCipher)
	}
}
