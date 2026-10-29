package raywire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	mrand "math/rand/v2"
	stdnet "net"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/flynn/noise"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
)

// pinFuzzRandomness makes the ephemeral keys, the padding and the clock fixed, so a
// handshake built in one run is the same in every run. Each fuzz input calls it
// first. The fuzz workers run one input at a time, so the globals are safe.
func pinFuzzRandomness(seed byte) {
	ephRand = mrand.NewChaCha8([32]byte{0x71, seed})
	padRand = mrand.NewChaCha8([32]byte{0x72, seed})
	handshakeClock = func() time.Time { return testNow }
}

// saveFuzzRandomness restores the globals that the fuzz setup changes.
func saveFuzzRandomness(f *testing.F) {
	savedEph, savedPad, savedClock := ephRand, padRand, handshakeClock
	f.Cleanup(func() { ephRand, padRand, handshakeClock = savedEph, savedPad, savedClock })
}

// FuzzClientHandshake feeds arbitrary bytes to the initiator as the server's reply.
// It must not panic. A rejected reply returns no Conn and reads no more than the
// largest reply. An accepted reply must carry the sealed pad count that the server
// sent, since Noise authenticates it, and the same responder point, which the
// canonical decode may write in another form. The pad after the count is not
// authenticated, so its bytes may differ, but the reader must stop at the length
// the count gives.
func FuzzClientHandshake(f *testing.F) {
	clientKey := fuzzKey(f, 0x31)
	serverKey := fuzzKey(f, 0x32)
	saveFuzzRandomness(f)

	pinFuzzRandomness(0x41)
	msg1 := makeMsg1(f, clientKey, serverKey.Public)
	accept := func(pub []byte) bool { return bytes.Equal(pub, clientKey.Public) }
	// replyWith answers msg1 with a server whose handshake pad is p. msg2 keeps its
	// layout in v3, so these are the reply lengths that v2 gave too.
	replyWith := func(p int) []byte {
		pinFuzzRandomness(0x41)
		sc := newMemConn(msg1)
		if _, err := ServerHandshake(sc, serverKey, accept, NewReplayFilter(), nil, testHeadKeys(), padPolicy{Handshake: p}); err != nil {
			f.Fatal(err)
		}
		return sc.out.Bytes()
	}
	reply := replyWith(maxHandshakePad)
	shortest := replyWith(0)
	// The sealed count of each reply the server sent, with the length of that reply.
	sentReplies := map[string]int{
		string(reply[hsKeyLen : hsKeyLen+hsCountLen]):    len(reply),
		string(shortest[hsKeyLen : hsKeyLen+hsCountLen]): len(shortest),
	}

	topBit := bytes.Clone(reply)
	topBit[hsKeyLen-1] ^= 0x80
	badCount := bytes.Clone(reply)
	badCount[hsKeyLen] ^= 1
	lastByte := bytes.Clone(reply)
	lastByte[len(lastByte)-1] ^= 1
	for _, seed := range [][]byte{
		reply,
		shortest,
		topBit,
		badCount,
		lastByte,
		reply[:len(reply)-1],
		reply[:hsKeyLen+hsCountLen],
		reply[:hsKeyLen],
		nil,
		make([]byte, hsKeyLen+hsCountLen+maxHandshakePad),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		pinFuzzRandomness(0x41)
		conn := newMemConn(input)
		rc, err := ClientHandshake(conn, clientKey, serverKey.Public, testKeys(), defaultPadPolicy())
		if err != nil {
			if rc != nil {
				t.Fatalf("handshake failed with %v but returned a connection", err)
			}
			if conn.n > hsKeyLen+hsCountLen+maxHandshakePad {
				t.Fatalf("read %d bytes of the reply, limit %d", conn.n, hsKeyLen+hsCountLen+maxHandshakePad)
			}
			return
		}
		if rc == nil {
			t.Fatal("handshake accepted without a connection")
		}
		if conn.n < hsKeyLen+hsCountLen {
			t.Fatalf("accepted after %d bytes, before the sealed count", conn.n)
		}
		// Each sealed count the server sent fixes the pad length, so the reader must
		// stop at the length of the reply that carries that count.
		want, ok := sentReplies[string(input[hsKeyLen:hsKeyLen+hsCountLen])]
		if !ok {
			t.Fatal("accepted a sealed pad count that the server did not send")
		}
		if conn.n != want {
			t.Fatalf("accepted after %d bytes, the reply with this count is %d", conn.n, want)
		}
		if !bytes.Equal(canonicalDecode(input[:hsKeyLen]), canonicalDecode(reply[:hsKeyLen])) {
			t.Fatal("accepted a responder key that is not the server's")
		}
	})
}

// maxHeaderAddr is the longest address a request header can name.
const maxHeaderAddr = 255

// FuzzDecodeHeader feeds arbitrary bytes to the request header decoder. The header
// is authenticated, but an authorized client may still send any bytes, so the
// decoder must not panic. It reads exactly the header and never more. An accepted
// header must encode again, and decoding that encoding must give the same
// destination, so the server never accepts a header it cannot route.
func FuzzDecodeHeader(f *testing.F) {
	for _, seed := range [][]byte{
		headerWire(1, 443, "example.com"),
		headerWire(2, 53, "1.2.3.4"),
		headerWire(2, 8443, "2001:db8::1"),
		headerWire(1, 80, "::ffff:1.2.3.4"),
		headerWire(1, 443, " "),
		headerWire(1, 443, "\t example.com "),
		headerWire(1, 0, "example.com"),
		headerWire(1, 443, ""),
		headerWire(3, 443, "example.com"),
		headerWire(1, 443, strings.Repeat("a", 255)),
		{1, 0x01, 0xbb, 0xff, 'a'},
		{1, 0x01, 0xbb},
		nil,
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		r := bytes.NewReader(input)
		dest, err := decodeHeader(r)
		used := len(input) - r.Len()
		if err != nil {
			if used > headerFixedLen+maxHeaderAddr {
				t.Fatalf("header failure read %d bytes, the largest header is %d", used, headerFixedLen+maxHeaderAddr)
			}
			return
		}
		if used != headerFixedLen+int(input[3]) {
			t.Fatalf("read %d bytes, the header is %d", used, headerFixedLen+int(input[3]))
		}
		if dest.Port == 0 || dest.Address == nil || (dest.Network != xnet.Network_TCP && dest.Network != xnet.Network_UDP) {
			t.Fatalf("accepted an unusable destination %v", dest)
		}

		block, err := encodeHeader(dest)
		if err != nil {
			t.Fatalf("accepted a header that does not encode: %v", err)
		}
		again, err := decodeHeader(bytes.NewReader(block))
		if err != nil {
			t.Fatalf("encoded header does not decode: %v", err)
		}
		if again.Network != dest.Network || again.Port != dest.Port || again.Address.String() != dest.Address.String() {
			t.Fatalf("round trip changed the destination: %v became %v", dest, again)
		}
		block2, err := encodeHeader(again)
		if err != nil || !bytes.Equal(block, block2) {
			t.Fatalf("second encoding differs: %x and %x, %v", block, block2, err)
		}
	})
}

// headerWire returns a request header with the given network and port byte fields
// and address, as the wire carries them. The address length is taken from addr.
func headerWire(network byte, port uint16, addr string) []byte {
	out := []byte{network, byte(port >> 8), byte(port), byte(len(addr))}
	return append(out, addr...)
}

// refDatagram is one datagram as the wire carries it: the destination block and the
// payload.
type refDatagram struct {
	dest    xnet.Destination
	payload []byte
}

// referenceDatagrams parses a plaintext datagram stream in the order of the UDP
// section, with its own code. It returns the datagrams before the first failure,
// and the failure. io.EOF is a clean end at a datagram boundary.
func referenceDatagrams(in []byte) ([]refDatagram, error) {
	var out []refDatagram
	pos := 0
	for {
		if pos == len(in) {
			return out, io.EOF
		}
		if len(in)-pos < headerFixedLen {
			return out, io.ErrUnexpectedEOF
		}
		network := in[pos]
		port := binary.BigEndian.Uint16(in[pos+1 : pos+3])
		alen := int(in[pos+3])
		pos += headerFixedLen
		if network != networkUDP {
			return out, errDatagramNetwork
		}
		if port == 0 {
			return out, errDatagramPort
		}
		if alen == 0 {
			return out, errDatagramAddress
		}
		if len(in)-pos < alen {
			return out, io.ErrUnexpectedEOF
		}
		addr := in[pos : pos+alen]
		pos += alen
		// Independent of parseDatagramAddress: an address that parses as nothing
		// is refused, a domain whose text is an IP is that IP, and ASCII controls
		// are refused before that parse.
		for _, b := range addr {
			if b < ' ' || b == 0x7F {
				return out, errDatagramAddress
			}
		}
		parsed := xnet.ParseAddress(string(addr))
		if parsed.String() == "" {
			return out, errDatagramAddress
		}
		if parsed.Family().IsDomain() {
			again := xnet.ParseAddress(parsed.String())
			if again.String() != "" && !again.Family().IsDomain() {
				parsed = again
			}
		}
		if len(in)-pos < 2 {
			return out, io.ErrUnexpectedEOF
		}
		size := int(binary.BigEndian.Uint16(in[pos : pos+2]))
		pos += 2
		if len(in)-pos < size {
			return out, io.ErrUnexpectedEOF
		}
		payload := in[pos : pos+size]
		pos += size
		out = append(out, refDatagram{
			dest:    xnet.UDPDestination(parsed, xnet.Port(port)),
			payload: payload,
		})
	}
}

// udpWire returns one datagram in the stream format: the destination block, a
// 2-byte payload length and the payload.
func udpWire(tb testing.TB, address string, port xnet.Port, payload []byte) []byte {
	tb.Helper()
	block, err := encodeHeader(xnet.UDPDestination(xnet.ParseAddress(address), port))
	if err != nil {
		tb.Fatal(err)
	}
	out := append(block, byte(len(payload)>>8), byte(len(payload)))
	return append(out, payload...)
}

// sameDestination compares two destinations by what the wire carries.
func sameDestination(a, b xnet.Destination) bool {
	return a.Network == b.Network && a.Port == b.Port && a.Address.String() == b.Address.String()
}

// FuzzUDPDatagrams checks the UDP framing in both directions. The fuzz input is the
// plaintext of a datagram stream, sealed in small frames as an authorized client
// could send it. The reader must return the datagrams and the failure that the
// reference parser gives. Then the datagrams that were read go out through the
// writer and come back the same, so the two directions use one framing. No
// datagram may be longer than 65535 bytes.
func FuzzUDPDatagrams(f *testing.F) {
	saveFuzzRandomness(f)
	for _, seed := range [][]byte{
		nil,
		udpWire(f, "example.com", 53, []byte("query")),
		append(udpWire(f, "1.2.3.4", 53, nil), udpWire(f, "2001:db8::1", 443, []byte{1, 2, 3})...),
		udpWire(f, "example.com", 53, bytes.Repeat([]byte{7}, 300)),
		udpWire(f, "example.com", 53, nil)[:10],
		headerWire(1, 53, "example.com"),
		headerWire(2, 0, "example.com"),
		headerWire(2, 53, ""),
		headerWire(2, 53, " "),
		{2, 0, 53, 3, 'a', 'b', 'c', 0xff, 0xff, 'x'},
		append(headerWire(2, 53, "example.com"), 0, 0),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		var bodies [][]byte
		for rest := input; len(rest) > 0; {
			n := min(len(rest), 61)
			bodies = append(bodies, frameBody(frameData, rest[:n], 0))
			rest = rest[n:]
		}
		bodies = append(bodies, frameBody(frameEnd, nil, 0))
		wire := sealStream(t, frameKeyFuzz, bodies...)

		src := newMemConn(wire)
		rc := newConn(src, nil, noise.UnsafeNewCipherState(cipherSuite, frameKeyFuzz, 0), padPolicy{}, false)
		pr := newPacketReader(rc)
		var got []refDatagram
		var gotErr error
		for {
			mb, err := pr.ReadMultiBuffer()
			if err != nil {
				gotErr = err
				break
			}
			for _, b := range mb {
				if len(b.Bytes()) > maxDatagramPayload {
					t.Fatalf("datagram of %d bytes", len(b.Bytes()))
				}
				got = append(got, refDatagram{dest: *b.UDP, payload: bytes.Clone(b.Bytes())})
			}
			buf.ReleaseMulti(mb)
		}

		want, wantErr := referenceDatagrams(input)
		if len(got) != len(want) {
			t.Fatalf("read %d datagrams, the reference reads %d", len(got), len(want))
		}
		for i := range want {
			if !sameDestination(got[i].dest, want[i].dest) || !bytes.Equal(got[i].payload, want[i].payload) {
				t.Fatalf("datagram %d differs from the reference", i)
			}
		}
		if wantErr == io.EOF {
			if gotErr != io.EOF {
				t.Fatalf("clean end: got error %v", gotErr)
			}
		} else if !errors.Is(gotErr, wantErr) {
			t.Fatalf("got error %v, the reference gives %v", gotErr, wantErr)
		}

		// Round trip, in the other direction: the datagrams that were read are
		// written with the writer, then read back.
		sink := newMemConn(nil)
		wc := newConn(sink, noise.UnsafeNewCipherState(cipherSuite, frameKeyFuzz, 0), nil, padPolicy{}, false)
		var out buf.MultiBuffer
		for _, d := range want {
			b := newDatagramBuffer(len(d.payload))
			if _, err := b.Write(d.payload); err != nil {
				t.Fatal(err)
			}
			dest := d.dest
			b.UDP = &dest
			out = append(out, b)
		}
		if err := newPacketWriter(wc, xnet.Destination{}).WriteMultiBuffer(out); err != nil {
			t.Fatalf("a datagram that was read cannot be written: %v", err)
		}
		back := newPacketReader(newConn(newMemConn(sink.out.Bytes()), nil,
			noise.UnsafeNewCipherState(cipherSuite, frameKeyFuzz, 0), padPolicy{}, false))
		for i := range want {
			mb, err := back.ReadMultiBuffer()
			if err != nil {
				t.Fatalf("datagram %d does not read back: %v", i, err)
			}
			if !sameDestination(*mb[0].UDP, want[i].dest) || !bytes.Equal(mb[0].Bytes(), want[i].payload) {
				t.Fatalf("datagram %d changed in the round trip", i)
			}
			buf.ReleaseMulti(mb)
		}
	})
}

// FuzzPadPolicy checks the padding limits and the frames they shape. The limits are
// the documented ones, and the typed path must accept exactly the same values as
// them. For a valid policy, a Conn splits any payload into frames. Each frame body
// holds its payload and at most the pad: a whole number of buckets in bucket mode,
// and the handshake pad on the first frame when first is set. A body must never
// exceed the 16-bit length.
func FuzzPadPolicy(f *testing.F) {
	saveFuzzRandomness(f)
	f.Add(uint32(255), uint32(32), uint32(0), uint16(100), true)
	f.Add(uint32(512), uint32(1024), uint32(0), uint16(65535), false)
	f.Add(uint32(0), uint32(0), uint32(16), uint16(65000), false)
	f.Add(uint32(0), uint32(0), uint32(4096), uint16(65535), true)
	f.Add(uint32(0), uint32(0), uint32(4096), uint16(61437), false)
	f.Add(uint32(513), uint32(0), uint32(0), uint16(0), false)
	f.Add(uint32(0), uint32(1025), uint32(0), uint16(0), false)
	f.Add(uint32(0), uint32(0), uint32(15), uint16(0), false)
	f.Add(uint32(0), uint32(0), uint32(4097), uint16(0), false)
	f.Add(uint32(1<<31), uint32(1<<31), uint32(1<<31), uint16(1), true)

	f.Fuzz(func(t *testing.T, handshake, frame, bucket uint32, size uint16, first bool) {
		pinFuzzRandomness(0x51)
		pol := padFromProto(&Padding{Handshake: handshake, Frame: frame, Bucket: bucket})
		wantOK := handshake <= maxHandshakePad && frame <= maxFramePad &&
			(bucket == 0 || (bucket >= minBucket && bucket <= maxBucket))
		if err := pol.validate(); (err == nil) != wantOK {
			t.Fatalf("validate(%d, %d, %d) = %v, want valid %v", handshake, frame, bucket, err, wantOK)
		}
		if !wantOK {
			return
		}

		payload := bytes.Repeat([]byte{0xa5}, int(size))
		sink := newMemConn(nil)
		c := newConn(sink, noise.UnsafeNewCipherState(cipherSuite, frameKeyFuzz, 0), nil, pol, first)
		if _, err := c.Write(payload); err != nil {
			t.Fatal(err)
		}
		if err := c.CloseWrite(); err != nil {
			t.Fatal(err)
		}

		// Each frame is read with its own decoder, from the wire alone.
		recv := noise.UnsafeNewCipherState(cipherSuite, frameKeyFuzz, 0)
		wire := sink.out.Bytes()
		var got []byte
		hsFrame := first
		for pos := 0; ; {
			if len(wire)-pos < frameHdrCipher {
				t.Fatalf("frame header at %d is cut short", pos)
			}
			hdr, err := recv.Decrypt(nil, nil, wire[pos:pos+frameHdrCipher])
			if err != nil {
				t.Fatalf("frame header at %d does not authenticate: %v", pos, err)
			}
			bp := int(binary.BigEndian.Uint16(hdr))
			end := pos + frameHdrCipher + bp + tagSize
			if end > len(wire) {
				t.Fatalf("frame at %d runs past the stream", pos)
			}
			pt, err := recv.Decrypt(nil, nil, wire[pos+frameHdrCipher:end])
			if err != nil || len(pt) != bp || bp < frameHeaderSize {
				t.Fatalf("frame body at %d: length %d, want %d, err %v", pos, len(pt), bp, err)
			}
			n := int(binary.BigEndian.Uint16(pt[1:frameHeaderSize]))
			if frameHeaderSize+n > bp {
				t.Fatalf("frame at %d holds %d payload bytes in a body of %d", pos, n, bp)
			}
			switch pt[0] {
			case frameData:
				got = append(got, pt[frameHeaderSize:frameHeaderSize+n]...)
			case frameEnd:
			default:
				t.Fatalf("frame at %d has type 0x%02x", pos, pt[0])
			}
			if pol.Bucket > 0 {
				if bp%pol.Bucket != 0 {
					t.Fatalf("bucket %d: body of %d bytes is not a whole number of buckets", pol.Bucket, bp)
				}
				if bp-(frameHeaderSize+n) >= pol.Bucket {
					t.Fatalf("bucket %d: body of %d bytes pads a payload of %d by a full bucket", pol.Bucket, bp, n)
				}
			} else {
				pad := pol.Frame
				if hsFrame {
					pad = pol.Handshake
				}
				if bp-(frameHeaderSize+n) > pad {
					t.Fatalf("body of %d bytes pads a payload of %d by more than %d", bp, n, pad)
				}
			}
			hsFrame = false
			pos = end
			if pt[0] == frameEnd {
				if pos != len(wire) {
					t.Fatalf("end-of-stream frame is followed by %d bytes", len(wire)-pos)
				}
				break
			}
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("payload: got %d bytes, want %d", len(got), len(payload))
		}
	})
}

// FuzzElligator feeds arbitrary bytes to the Elligator2 decode. Any 32 bytes must
// decode to a point of the curve. The canonical point must lie in the prime-order
// subgroup, and it must be the same for a wire form and for the decoded point. A
// wire form made by wireForm must decode to the point it encodes, and an encodable
// point must have a preimage that decodes to it.
func FuzzElligator(f *testing.F) {
	saveFuzzRandomness(f)
	pinFuzzRandomness(0x61)
	_, _, valid, err := wireEphemeral()
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range [][]byte{
		valid,
		make([]byte, 32),
		bytes.Repeat([]byte{0xff}, 32),
		bytes.Repeat([]byte{0x01}, 32),
		valid[:31],
		append(bytes.Clone(valid), 0),
		nil,
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, in []byte) {
		if len(in) != 32 {
			if elligatorDecode(in) != nil || canonicalDecode(in) != nil {
				t.Fatalf("a %d-byte input decoded", len(in))
			}
			return
		}
		u := elligatorDecode(in)
		if len(u) != 32 || elliLift(feFromLE(u)) == nil {
			t.Fatalf("decoded value %x is not a point of the curve", u)
		}
		if c := canonicalPoint(u); c != nil {
			if !bytes.Equal(c, canonicalDecode(in)) {
				t.Fatal("canonical decode differs from canonicalPoint of the decoded point")
			}
			if elliLift(feFromLE(c)) == nil {
				t.Fatalf("canonical point %x is not on the curve", c)
			}
			if elliLadder(elliL, feFromLE(c)) != nil {
				t.Fatalf("canonical point %x is not in the prime-order subgroup", c)
			}
		}

		// wireForm must give a wire form of the same point, whatever byte picks its
		// preimage. The top bit of a wire form carries no value.
		r := bytes.Clone(in)
		r[31] &= 0x7f
		if form := wireForm(r, bytes.NewReader([]byte{in[0]})); form != nil {
			if !bytes.Equal(elligatorDecode(form), elligatorF(r)) {
				t.Fatalf("wire form of %x decodes to another point", r)
			}
		}

		if e, ok := elligatorE(u); ok && !bytes.Equal(elligatorF(e), u) {
			t.Fatalf("preimage %x of %x decodes to another point", e, u)
		}
	})
}

// FuzzParseFallback checks the decoy address. An accepted address names a host that
// is not a zone, a wildcard or a numeric form that the resolver may read as one, and
// it has a port from 1 to 65535. The result must parse again to the same destination.
func FuzzParseFallback(f *testing.F) {
	for _, seed := range []string{
		"203.0.113.9:443",
		"example.com:443",
		"[2001:db8::1]:8443",
		"0.0.0.0:443",
		"[::]:443",
		"0:443",
		"0x7f.1:80",
		"example.com:0",
		"example.com:65536",
		"host%lo:80",
		"[fe80::1%lo]:80",
		"",
		":443",
		"example.com",
		"example.com:443:1",
		"1.2.3:80",
		"dead:80",
		" 0.0.0.0:443",
		"0 :1",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, addr string) {
		dest, err := ParseFallback(addr)
		if err != nil {
			if dest.Address != nil || dest.Port != 0 {
				t.Fatalf("refused %q but returned %v", addr, dest)
			}
			return
		}
		if dest.Network != xnet.Network_TCP || dest.Port == 0 || dest.Address == nil {
			t.Fatalf("accepted %q as %v", addr, dest)
		}
		host := dest.Address.String()
		if strings.Contains(host, "%") {
			t.Fatalf("accepted a zoned host %q", host)
		}
		if dest.Address.Family().IsIP() {
			if dest.Address.IP().IsUnspecified() {
				t.Fatalf("accepted a wildcard address %q", addr)
			}
		} else if looksNumeric(host) {
			t.Fatalf("accepted the numeric host %q as a name", host)
		}
		// String brackets an IPv6 host, and JoinHostPort brackets it again.
		bare := strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
		again, err := ParseFallback(stdnet.JoinHostPort(bare, strconv.Itoa(int(dest.Port))))
		if err != nil || again.Port != dest.Port || again.Address.String() != host {
			t.Fatalf("%q does not parse again: %v", addr, err)
		}
	})
}

// assertEmailRules checks an accepted email against the rules that the stats and the
// logs depend on, written out here rather than shared with checkEmail.
func assertEmailRules(t *testing.T, email string) {
	t.Helper()
	if len(email) > maxEmailLen {
		t.Fatalf("accepted an email of %d bytes", len(email))
	}
	if !utf8.ValidString(email) {
		t.Fatalf("accepted an email that is not UTF-8: %q", email)
	}
	for _, r := range email {
		if unicode.IsControl(r) {
			t.Fatalf("accepted a control character in %q", email)
		}
		if r != ' ' && unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp, unicode.Zs) {
			t.Fatalf("accepted a space or invisible character in %q", email)
		}
	}
	if strings.TrimSpace(email) != email {
		t.Fatalf("accepted an email with surrounding spaces: %q", email)
	}
	if strings.Contains(email, ">>>") || strings.HasSuffix(email, ">") {
		t.Fatalf("accepted an email that breaks the stats key: %q", email)
	}
}

// FuzzAccountEmail checks the account rules. An accepted email obeys the rules of
// assertEmailRules. A non-empty email belongs to one key only, and one key may not
// hold two accounts, so the stats cannot merge two clients.
func FuzzAccountEmail(f *testing.F) {
	for _, pair := range [][2]string{
		{"alice@example.com", "bob@example.com"},
		{"", ""},
		{"a>>>b", ""},
		{"trailing>", ""},
		{"​hidden", "hidden"},
		{" x", "x "},
		{"\xff", ""},
		{strings.Repeat("e", 128), strings.Repeat("e", 129)},
		{"a b", "a b"},
		{"ключ@пример", "ключ@пример"},
	} {
		f.Add(pair[0], pair[1])
	}

	f.Fuzz(func(t *testing.T, email, other string) {
		k1 := bytes.Repeat([]byte{1}, 32)
		k2 := bytes.Repeat([]byte{2}, 32)
		if ValidateAccounts([]*Account{{PublicKey: k1, Email: email}}) == nil {
			assertEmailRules(t, email)
		}
		if email != "" && ValidateAccounts([]*Account{{PublicKey: k1, Email: email}, {PublicKey: k2, Email: email}}) == nil {
			t.Fatalf("two keys share the email %q", email)
		}
		if ValidateAccounts([]*Account{{PublicKey: k1, Email: email}, {PublicKey: k1, Email: other}}) == nil {
			t.Fatal("one key holds two accounts")
		}
	})
}

// checkReplayState checks the bookkeeping of a ReplayFilter: the map, the list and the
// per-client counts describe the same entries, and no quota is exceeded.
func checkReplayState(t *testing.T, f *ReplayFilter) {
	t.Helper()
	if len(f.entries) != f.order.Len() || f.order.Len() > maxReplayEntries {
		t.Fatalf("%d map entries and %d list entries", len(f.entries), f.order.Len())
	}
	counts := make(map[string]int)
	var prev time.Time
	for e := f.order.Front(); e != nil; e = e.Next() {
		entry := e.Value.(*replayEntry)
		if f.entries[entry.key] != e {
			t.Fatal("the map does not point at its list element")
		}
		if entry.at.Before(prev) {
			t.Fatal("the list is not in acceptance order")
		}
		prev = entry.at
		counts[entry.client]++
	}
	sum := 0
	for client, n := range f.perClient {
		sum += n
		if n != counts[client] || n > maxReplayPerClient {
			t.Fatalf("client count %d, the list holds %d, quota %d", n, counts[client], maxReplayPerClient)
		}
	}
	if sum != len(f.entries) || len(counts) != len(f.perClient) {
		t.Fatalf("per-client counts sum to %d, entries are %d", sum, len(f.entries))
	}
}

// replayFuzzRecords bounds the handshakes that one FuzzReplayFilter input drives.
const replayFuzzRecords = 256

// FuzzReplayFilter drives the replay filter with a sequence of handshakes. Each
// four-byte record is a client, an ephemeral key, a timestamp offset and a clock
// step. The filter must refuse a timestamp outside the skew window, must not accept
// a key twice inside its window, and must keep its bookkeeping consistent.
func FuzzReplayFilter(f *testing.F) {
	for _, seed := range [][]byte{
		{0, 1, 0, 0, 0, 2, 0, 0},
		{0, 1, 0, 0, 0, 1, 0, 0},
		{0, 1, 127, 0, 0, 1, 0x80, 0},
		{0, 1, 0, 255, 1, 1, 0, 0, 0, 1, 0, 0},
		{0, 1, 0, 0, 1, 1, 0, 0, 2, 1, 0, 0, 3, 1, 0, 0},
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, ops []byte) {
		// The state check walks the whole list after each record, so one input is
		// kept to a bounded number of records.
		ops = ops[:min(len(ops), 4*replayFuzzRecords)]
		filter := NewReplayFilter()
		now := testNow
		for ; len(ops) >= 4; ops = ops[4:] {
			client := string([]byte{'c', ops[0] % 3})
			key := []byte{ops[1] % 6}
			now = now.Add(time.Duration(ops[3]) * 10 * time.Second)
			ts := now.Add(time.Duration(int8(ops[2])) * 30 * time.Second)
			skew := ts.Sub(now)
			inWindow := skew <= maxClockSkew && skew >= -maxClockSkew

			ok := filter.Accept(client, key, ts, now)
			if ok && !inWindow {
				t.Fatalf("accepted a timestamp %v away from the server clock", skew)
			}
			if ok {
				if filter.Accept(client, key, ts, now) {
					t.Fatal("accepted the same key twice in its window")
				}
				if front := filter.order.Front(); front != nil &&
					now.Sub(front.Value.(*replayEntry).at) > replayWindow {
					t.Fatal("kept an entry past its window")
				}
			}
			checkReplayState(t, filter)
		}
	})
}
