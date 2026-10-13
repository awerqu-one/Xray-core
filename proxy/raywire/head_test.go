package raywire

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/flynn/noise"
	xnet "github.com/xtls/xray-core/common/net"
	"golang.org/x/crypto/curve25519"
)

// testPSK is the pre-shared key of every test inbound and client. It is the PSK of
// the known-answer vector in section 18 of the design spec.
var testPSK = bytes.Repeat([]byte{0x33}, pskLen)

// testKeys returns the PSK-derived keys of testPSK, in the form an inbound or a
// client holds them.
func testKeys() pskKeys {
	return derivePSKKeys(testPSK)
}

// testHeadKeys returns the head keys of an inbound with testPSK and no previousPsk, as
// NewServer builds them.
func testHeadKeys() headKeys {
	hk, err := newHeadKeys(testPSK, nil, time.Time{})
	if err != nil {
		panic(err)
	}
	return hk
}

// The functions below restate section 5 of the spec with crypto/hmac only. They do
// not call the package, so the formula tests check the package against the spec.

func refHMAC(key []byte, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

func refPRK(psk []byte) []byte { return refHMAC(psk, []byte("raywire/3 psk")) }

func refHeadKey(psk []byte) []byte { return refHMAC(refPRK(psk), []byte("raywire/4 head key")) }

func refMaskKey(psk []byte) []byte { return refHMAC(refPRK(psk), []byte("raywire/4 w1")) }

func refFingerprint(psk []byte) []byte {
	return refHMAC(refPRK(psk), []byte("raywire/3 fingerprint"))[:4]
}

// refMaskWord is maskWord of section 5: the leading 16 bits of HMAC(keyMask, dh).
func refMaskWord(maskKey, dh []byte) uint16 {
	return binary.BigEndian.Uint16(refHMAC(maskKey, dh)[:2])
}

// refTag is T of section 5: the leading 16 bytes of the tag over the label, the
// server public key, R_e, W1 and the time bucket.
func refTag(headKey, serverPub, R, W1 []byte, bucket uint64) []byte {
	return refHMAC(headKey, []byte("raywire/4 head"), serverPub, R, W1, binary.BigEndian.AppendUint64(nil, bucket))[:16]
}

// testBucket is the time bucket of the test clock.
func testBucket() uint64 { return headBucket(handshakeClock()) }

// refDH is the server's DH secret for the wire form R, computed from the raw point of
// R as section 5 gives it.
func refDH(t testing.TB, serverPrivate, R []byte) []byte {
	t.Helper()
	dh, err := curve25519.X25519(serverPrivate, elligatorDecode(R))
	if err != nil {
		t.Fatal(err)
	}
	return dh
}

// rawHead returns R_e || W1 || T, with T computed under the head key of psk for the
// server public key serverPub.
func rawHead(psk, serverPub, R, W1 []byte) []byte {
	head := make([]byte, 0, hsHeadLen)
	head = append(head, R...)
	head = append(head, W1...)
	return append(head, refTag(refHeadKey(psk), serverPub, R, W1, testBucket())...)
}

// headWithLength returns the head of a msg1 whose remainder is n1 bytes. It is built
// for a holder of the PSK and of the server's public key, whose DH is computed here
// from the server's private key.
func headWithLength(t testing.TB, serverKey noise.DHKey, psk, R []byte, n1 int) []byte {
	t.Helper()
	dh := refDH(t, serverKey.Private, R)
	W1 := binary.BigEndian.AppendUint16(nil, uint16(n1)^refMaskWord(refMaskKey(psk), dh))
	return rawHead(psk, serverKey.Public, R, W1)
}

// checkHeadFormulas checks a complete msg1 against section 5. The tag at [34, 50)
// must match, and the length word must decode to the length of the remainder. It
// returns the decoded remainder length.
func checkHeadFormulas(t testing.TB, msg1 []byte, serverKey noise.DHKey, psk []byte) int {
	t.Helper()
	R, W1, T := msg1[:hsKeyLen], msg1[hsKeyLen:hsKeyLen+2], msg1[hsKeyLen+2:hsHeadLen]
	if !bytes.Equal(T, refTag(refHeadKey(psk), serverKey.Public, R, W1, testBucket())) {
		t.Fatalf("tag %x does not match section 5", T)
	}
	n1 := int(binary.BigEndian.Uint16(W1) ^ refMaskWord(refMaskKey(psk), refDH(t, serverKey.Private, R)))
	if got := len(msg1) - hsHeadLen; got != n1 {
		t.Fatalf("length word decodes to %d, but the remainder is %d bytes", n1, got)
	}
	if n1 < 72 || n1 > 584 {
		t.Fatalf("length word decodes to %d, outside [72, 584]", n1)
	}
	return n1
}

// craftMsg1 builds a first message the way ClientHandshake does, with the given
// prologue and payload, so that a test can send a message that the client never
// would. The head is keyed under psk, and the remainder is the Noise output.
func craftMsg1(t testing.TB, clientKey noise.DHKey, serverPub []byte, label string, psk, payload []byte) []byte {
	t.Helper()
	k, u, R, err := selectEphemeral(wireEphemeral)
	if err != nil {
		t.Fatal(err)
	}
	rng := &scriptedRand{}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cipherSuite,
		Random:        rng,
		Pattern:       noise.HandshakeIK,
		Initiator:     true,
		Prologue:      []byte(label),
		StaticKeypair: clientKey,
		PeerStatic:    serverPub,
	})
	if err != nil {
		t.Fatal(err)
	}
	rng.arm(k)
	out, _, _, err := hs.WriteMessage(nil, payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out[:hsKeyLen], u) {
		t.Fatal("the Noise ephemeral does not match the wire form")
	}
	dh, err := curve25519.X25519(k, serverPub)
	if err != nil {
		t.Fatal(err)
	}
	W1 := binary.BigEndian.AppendUint16(nil, uint16(len(out)-hsKeyLen)^refMaskWord(refMaskKey(psk), dh))
	return append(rawHead(psk, serverPub, R, W1), out[hsKeyLen:]...)
}

// craftV2Msg1 builds a first message in the raywire/2 layout: a 34-byte head whose
// length word is masked by the DH secret alone, and a Noise remainder under the
// prologue "raywire/2".
func craftV2Msg1(t testing.TB, clientKey noise.DHKey, serverPub []byte, payload []byte) []byte {
	t.Helper()
	k, u, R, err := selectEphemeral(wireEphemeral)
	if err != nil {
		t.Fatal(err)
	}
	rng := &scriptedRand{}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cipherSuite,
		Random:        rng,
		Pattern:       noise.HandshakeIK,
		Initiator:     true,
		Prologue:      []byte("raywire/2"),
		StaticKeypair: clientKey,
		PeerStatic:    serverPub,
	})
	if err != nil {
		t.Fatal(err)
	}
	rng.arm(k)
	out, _, _, err := hs.WriteMessage(nil, payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out[:hsKeyLen], u) {
		t.Fatal("the Noise ephemeral does not match the wire form")
	}
	dh, err := curve25519.X25519(k, serverPub)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, dh)
	mac.Write([]byte("raywire/2 w1"))
	W1 := binary.BigEndian.AppendUint16(nil, uint16(len(out)-hsKeyLen)^binary.BigEndian.Uint16(mac.Sum(nil)))
	msg := append(append([]byte(nil), R...), W1...)
	return append(msg, out[hsKeyLen:]...)
}

// randomHead returns n random bytes that do not start with a probe table entry, so
// that the server reads them as a head and not as a probe.
func randomHead(t testing.TB, n int) []byte {
	t.Helper()
	for {
		b := make([]byte, n)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		if !hasPrefix2(b) && !hasPrefix4(b) {
			return b
		}
	}
}

// flipBit returns a copy of b with one bit flipped. Bit i is bit i%8 of byte i/8.
func flipBit(b []byte, bit int) []byte {
	out := bytes.Clone(b)
	out[bit/8] ^= 1 << (bit % 8)
	return out
}

// holdsSlice reports whether v, or a struct inside it, has a byte slice equal to
// want. It follows structs and byte slices only, so it does not walk into maps,
// pointers or interfaces.
func holdsSlice(v reflect.Value, want []byte) bool {
	switch v.Kind() {
	case reflect.Struct:
		for i := range v.NumField() {
			if holdsSlice(v.Field(i), want) {
				return true
			}
		}
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 && bytes.Equal(v.Bytes(), want) {
			return true
		}
	}
	return false
}

func TestHeadLayout(t *testing.T) {
	if hsKeyLen != 32 || hsKeyLen+2 != 34 || headTagLen != 16 || hsHeadLen != 50 {
		t.Fatalf("head constants are R %d, W1 at %d, T %d, head %d; want 32, 34, 16, 50",
			hsKeyLen, hsKeyLen+2, headTagLen, hsHeadLen)
	}
	if hsMinN1 != 72 || hsMaxN1 != 584 || hsMaxConsumed != 634 {
		t.Fatalf("remainder limits are %d, %d and the most consumed is %d; want 72, 584, 634",
			hsMinN1, hsMaxN1, hsMaxConsumed)
	}

	clientKey, serverKey := newKey(t), newKey(t)
	// With P1 = 0 the message is 122 bytes: R_e [0, 32), W1 [32, 34), T [34, 50) and
	// the remainder from 50 on.
	msg1, _ := captureHandshake(t, clientKey, serverKey, padPolicy{})
	if len(msg1) != 122 {
		t.Fatalf("msg1 is %d bytes with P1 = 0, want 122", len(msg1))
	}
	if n1 := checkHeadFormulas(t, msg1, serverKey, testPSK); n1 != 72 {
		t.Fatalf("remainder is %d bytes with P1 = 0, want 72", n1)
	}
}

func TestMaskFormula(t *testing.T) {
	for _, p := range []int{0, 1, 255, 512} {
		clientKey, serverKey := newKey(t), newKey(t)
		for range 4 {
			msg1, _ := captureHandshake(t, clientKey, serverKey, padPolicy{Handshake: p})
			dh := refDH(t, serverKey.Private, msg1[:hsKeyLen])
			mask := refMaskWord(refMaskKey(testPSK), dh)
			if got := int(binary.BigEndian.Uint16(msg1[hsKeyLen:hsKeyLen+2]) ^ mask); got != len(msg1)-hsHeadLen {
				t.Fatalf("P=%d: BE16(W1) XOR maskWord = %d, want 72 + P1 = %d", p, got, len(msg1)-hsHeadLen)
			}
			if got := lengthMask(testKeys().maskKey, dh); got != mask {
				t.Fatalf("P=%d: package mask %04x, spec mask %04x", p, got, mask)
			}
		}
	}
}

func TestTagFormula(t *testing.T) {
	for _, p := range []int{0, 1, 255, 512} {
		clientKey, serverKey := newKey(t), newKey(t)
		for range 4 {
			msg1, _ := captureHandshake(t, clientKey, serverKey, padPolicy{Handshake: p})
			R, W1, T := msg1[:hsKeyLen], msg1[hsKeyLen:hsKeyLen+2], msg1[hsKeyLen+2:hsHeadLen]
			if want := refTag(refHeadKey(testPSK), serverKey.Public, R, W1, testBucket()); !bytes.Equal(T, want) {
				t.Fatalf("P=%d: T = %x, spec gives %x", p, T, want)
			}
			if got := headTag(testKeys().headKey, serverKey.Public, R, W1, testBucket()); !bytes.Equal(got, T) {
				t.Fatalf("P=%d: package tag %x, wire %x", p, got, T)
			}
			// T covers the server's public key, so the same head fails for another server.
			other := newKey(t)
			if bytes.Equal(T, refTag(refHeadKey(testPSK), other.Public, R, W1, testBucket())) {
				t.Fatal("the tag does not depend on the server public key")
			}
		}
	}
}

// TestKnownAnswerMACs checks the values of section 18. The inputs are arbitrary test
// bytes, so the vector exercises the MAC layer only.
func TestKnownAnswerMACs(t *testing.T) {
	psk := bytes.Repeat([]byte{0x33}, 32)
	S := bytes.Repeat([]byte{0x44}, 32)
	R := bytes.Repeat([]byte{0x5a}, 32)
	dh := bytes.Repeat([]byte{0x66}, 32)
	const n1 = 327

	check := func(name string, got []byte, want string) {
		t.Helper()
		if hex.EncodeToString(got) != want {
			t.Fatalf("%s = %x, want %s", name, got, want)
		}
	}
	prk := refPRK(psk)
	check("prk", prk, "427945472d52a856172754e4058e12f6339dc5bac3055b09f9e1ad4f3175507e")
	keyHead := refHeadKey(psk)
	check("keyHead", keyHead, "2afac5177f332c6dc4cb82dcc2ddcded2da58013a6dbba056bf4342d8571fda9")
	keyMask := refMaskKey(psk)
	check("keyMask", keyMask, "78eb39892114136d900a6ea461136d68d70f0d830720a8fa7befc7026f37981d")
	mw := refMaskWord(keyMask, dh)
	if mw != 0x9ab4 {
		t.Fatalf("maskWord = %04x, want 9ab4", mw)
	}
	W1 := binary.BigEndian.AppendUint16(nil, n1^mw)
	check("W1", W1, "9bf3")
	const katBucket = 5900000
	check("T", refTag(keyHead, S, R, W1, katBucket), "ab703ca35203d3cfcc8199c62b811ec8")
	check("fingerprint", refFingerprint(psk), "9ec92444")

	// The package holds the same values, and its mask and tag agree with them.
	keys := derivePSKKeys(psk)
	check("package headKey", keys.headKey, "2afac5177f332c6dc4cb82dcc2ddcded2da58013a6dbba056bf4342d8571fda9")
	check("package maskKey", keys.maskKey, "78eb39892114136d900a6ea461136d68d70f0d830720a8fa7befc7026f37981d")
	check("package fingerprint", keys.fingerprint, "9ec92444")
	if got := lengthMask(keys.maskKey, dh); got != mw {
		t.Fatalf("package mask = %04x, want %04x", got, mw)
	}
	if got := headTag(keys.headKey, S, R, W1, katBucket); !bytes.Equal(got, refTag(keyHead, S, R, W1, katBucket)) {
		t.Fatalf("package tag = %x", got)
	}
	if got := int(binary.BigEndian.Uint16(W1) ^ lengthMask(keys.maskKey, dh)); got != n1 {
		t.Fatalf("the receiver recovers %d, want %d", got, n1)
	}
}

// TestPSKKeysPrecomputed checks that a Server and a Client hold the section 5 values
// and not the PSK.
func TestPSKKeysPrecomputed(t *testing.T) {
	s, err := NewServer(coreContext(t), serverConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(coreContext(t), clientConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, side := range []struct {
		name string
		keys pskKeys
	}{{"server", s.keys.cur}, {"client", c.keys}} {
		if !bytes.Equal(side.keys.headKey, refHeadKey(testPSK)) {
			t.Errorf("%s headKey is not keyHead of section 5", side.name)
		}
		if !bytes.Equal(side.keys.maskKey, refMaskKey(testPSK)) {
			t.Errorf("%s maskKey is not keyMask of section 5", side.name)
		}
		if !bytes.Equal(side.keys.fingerprint, refFingerprint(testPSK)) {
			t.Errorf("%s fingerprint is not the section 5 fingerprint", side.name)
		}
	}
	if holdsSlice(reflect.ValueOf(s).Elem(), testPSK) {
		t.Fatal("Server keeps the PSK")
	}
	if holdsSlice(reflect.ValueOf(c).Elem(), testPSK) {
		t.Fatal("Client keeps the PSK")
	}
}

// TestHeadReplayStallsResidual pins residual R11/R2 for a head that was never accepted:
// it is not in the seen memory, so a captured head sent alone is held until the remainder
// would end, and the server relays it at the deadline. A head that was accepted is
// answered at byte 50 instead (TestSeenHeadRelayedAtByte50).
func TestHeadReplayStallsResidual(t *testing.T) {
	saved := preAuthTimeout
	preAuthTimeout = 200 * time.Millisecond
	t.Cleanup(func() { preAuthTimeout = saved })

	serverKey, clientKey := newKey(t), newKey(t)
	msg1, _ := captureHandshake(t, clientKey, serverKey, defaultPadPolicy())
	allowAll := func([]byte) bool { return true }
	he, _ := decide(t, serverKey, allowAll, NewReplayFilter(), func(c net.Conn, _ <-chan struct{}) {
		_, _ = c.Write(msg1[:hsHeadLen])
	})
	if he.Reason != "deadline" || !bytes.Equal(he.Consumed, msg1[:hsHeadLen]) {
		t.Fatalf("reason %q with %d bytes consumed, want deadline with the head", he.Reason, len(he.Consumed))
	}
}

// TestTagBitFlipsEveryPosition flips each bit of the head of a valid msg1. A flip in
// W1, T or R_e bytes 4 to 31 gives the tag reason at byte 50. A flip in R_e bytes 0 to
// 3 gives a prefix reason when the flipped bytes match a probe table entry, and the
// tag reason otherwise.
func TestTagBitFlipsEveryPosition(t *testing.T) {
	saved := preAuthTimeout
	preAuthTimeout = 2 * time.Second
	t.Cleanup(func() { preAuthTimeout = saved })

	serverKey, clientKey := newKey(t), newKey(t)
	msg1, _ := captureHandshake(t, clientKey, serverKey, defaultPadPolicy())
	head := msg1[:hsHeadLen]
	allowAll := func([]byte) bool { return true }
	for bit := range hsHeadLen * 8 {
		probe := flipBit(head, bit)
		wantReason, wantLen := "tag", hsHeadLen
		switch {
		case hasPrefix2(probe):
			wantReason, wantLen = "prefix", 2
		case hasPrefix4(probe):
			wantReason, wantLen = "prefix", 4
		}
		he, sc := decide(t, serverKey, allowAll, NewReplayFilter(), sendThenSentinel(probe[:wantLen]))
		if he.Reason != wantReason || !bytes.Equal(he.Consumed, probe[:wantLen]) {
			t.Fatalf("bit %d: reason %q consumed %x, want %q with %d bytes", bit, he.Reason, he.Consumed, wantReason, wantLen)
		}
		if wantReason == "tag" && !errors.Is(he, ErrTag) {
			t.Fatalf("bit %d: error %v, want ErrTag", bit, he.Err)
		}
		expectSentinel(t, sc)
	}
}

// TestW1BitFlipsNoLengthOracle flips each of the 16 bits of W1. Each flip gives the
// tag reason at byte 50, so no flip of the length word shows the server's reaction.
func TestW1BitFlipsNoLengthOracle(t *testing.T) {
	saved := preAuthTimeout
	preAuthTimeout = 2 * time.Second
	t.Cleanup(func() { preAuthTimeout = saved })

	serverKey, clientKey := newKey(t), newKey(t)
	msg1, _ := captureHandshake(t, clientKey, serverKey, defaultPadPolicy())
	allowAll := func([]byte) bool { return true }
	for bit := hsKeyLen * 8; bit < (hsKeyLen+2)*8; bit++ {
		probe := flipBit(msg1[:hsHeadLen], bit)
		he, sc := decide(t, serverKey, allowAll, NewReplayFilter(), sendThenSentinel(probe))
		if he.Reason != "tag" || len(he.Consumed) != hsHeadLen {
			t.Fatalf("W1 bit %d: reason %q with %d bytes, want tag with %d", bit, he.Reason, len(he.Consumed), hsHeadLen)
		}
		expectSentinel(t, sc)
	}
}

// TestTagOnlyBitFlipAtBit255 checks that bit 255 of R_e is covered by the tag. v2
// ignored that bit, and v3 rejects a flipped one at byte 50.
func TestTagOnlyBitFlipAtBit255(t *testing.T) {
	saved := preAuthTimeout
	preAuthTimeout = 2 * time.Second
	t.Cleanup(func() { preAuthTimeout = saved })

	serverKey, clientKey := newKey(t), newKey(t)
	msg1, _ := captureHandshake(t, clientKey, serverKey, defaultPadPolicy())
	probe := flipBit(msg1[:hsHeadLen], 255)
	he, sc := decide(t, serverKey, func([]byte) bool { return true }, NewReplayFilter(), sendThenSentinel(probe))
	if he.Reason != "tag" || len(he.Consumed) != hsHeadLen {
		t.Fatalf("bit 255 flipped: reason %q with %d bytes, want tag with %d", he.Reason, len(he.Consumed), hsHeadLen)
	}
	expectSentinel(t, sc)
}

// TestSHolderWithoutPSKNoStall plays an attacker who holds the server's public key
// and not the PSK. It builds R_e with its own key, an in-range length under the
// unkeyed mask of v2, and a random tag. Every head gets the tag reason at byte 50,
// at once, and none makes the server wait for a remainder.
func TestSHolderWithoutPSKNoStall(t *testing.T) {
	saved := preAuthTimeout
	preAuthTimeout = 2 * time.Second
	t.Cleanup(func() { preAuthTimeout = saved })

	serverKey := newKey(t)
	k, _, R, err := selectEphemeral(wireEphemeral)
	if err != nil {
		t.Fatal(err)
	}
	dh, err := curve25519.X25519(k, serverKey.Public)
	if err != nil {
		t.Fatal(err)
	}
	unkeyed := hmac.New(sha256.New, dh)
	unkeyed.Write([]byte("raywire/4 w1"))
	unkeyedMask := binary.BigEndian.Uint16(unkeyed.Sum(nil))

	allowAll := func([]byte) bool { return true }
	for i := range 1000 {
		n1 := 72 + i%513
		W1 := binary.BigEndian.AppendUint16(nil, uint16(n1)^unkeyedMask)
		probe := append(append(append([]byte(nil), R...), W1...), randomBytes(t, headTagLen)...)

		start := time.Now()
		he, sc := decide(t, serverKey, allowAll, NewReplayFilter(), sendThenSentinel(probe))
		if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
			t.Fatalf("attempt %d: decision after %v, want under 100 ms", i, elapsed)
		}
		if he.Reason != "tag" || len(he.Consumed) != hsHeadLen {
			t.Fatalf("attempt %d: reason %q with %d bytes, want tag with %d", i, he.Reason, len(he.Consumed), hsHeadLen)
		}
		expectSentinel(t, sc)
	}
}

// TestPSKHolderForgedLength shows that the remainder stall is reachable only with the
// PSK. A head built with the PSK and n1 = 72 is held until the deadline. The same head
// under another PSK gets the tag reason at byte 50.
func TestPSKHolderForgedLength(t *testing.T) {
	saved := preAuthTimeout
	preAuthTimeout = 200 * time.Millisecond
	t.Cleanup(func() { preAuthTimeout = saved })

	serverKey := newKey(t)
	allowAll := func([]byte) bool { return true }
	_, _, R, err := selectEphemeral(wireEphemeral)
	if err != nil {
		t.Fatal(err)
	}

	head := headWithLength(t, serverKey, testPSK, R, 72)
	he, _ := decide(t, serverKey, allowAll, NewReplayFilter(), func(c net.Conn, _ <-chan struct{}) {
		_, _ = c.Write(head)
	})
	if he.Reason != "deadline" || !bytes.Equal(he.Consumed, head) {
		t.Fatalf("PSK holder: reason %q with %d bytes, want deadline with %d", he.Reason, len(he.Consumed), len(head))
	}

	wrong := headWithLength(t, serverKey, bytes.Repeat([]byte{0x44}, pskLen), R, 72)
	he, sc := decide(t, serverKey, allowAll, NewReplayFilter(), sendThenSentinel(wrong))
	if he.Reason != "tag" || len(he.Consumed) != hsHeadLen {
		t.Fatalf("wrong PSK: reason %q with %d bytes, want tag with %d", he.Reason, len(he.Consumed), hsHeadLen)
	}
	expectSentinel(t, sc)
}

// TestPSKHolderOracleIsPerRE pins residual R3 for one R_e. With a PSK holder's view of
// one R_e, the reply depends only on whether BE16(W1) XOR maskWord lies in [72, 584]:
// an in-range value stalls to the deadline, and any other gives the length reason. The
// number of probes is not asserted.
func TestPSKHolderOracleIsPerRE(t *testing.T) {
	saved := preAuthTimeout
	preAuthTimeout = 60 * time.Millisecond
	t.Cleanup(func() { preAuthTimeout = saved })

	serverKey := newKey(t)
	allowAll := func([]byte) bool { return true }
	_, _, R, err := selectEphemeral(wireEphemeral)
	if err != nil {
		t.Fatal(err)
	}
	mask := refMaskWord(refMaskKey(testPSK), refDH(t, serverKey.Private, R))

	for _, n1 := range []int{0, 71, 585, 0xffff, 72, 200, 584, 300} {
		W1 := binary.BigEndian.AppendUint16(nil, uint16(n1)^mask)
		probe := rawHead(testPSK, serverKey.Public, R, W1)
		wantReason := "length"
		if n1 >= 72 && n1 <= 584 {
			wantReason = "deadline"
		}
		he, _ := decide(t, serverKey, allowAll, NewReplayFilter(), func(c net.Conn, _ <-chan struct{}) {
			_, _ = c.Write(probe)
		})
		if he.Reason != wantReason || !bytes.Equal(he.Consumed, probe) {
			t.Fatalf("n1 %d: reason %q with %d bytes, want %q with %d", n1, he.Reason, len(he.Consumed), wantReason, len(probe))
		}
	}
}

// TestNoX25519BeforeTag runs random heads and a valid head with a wrong tag through
// the server. None of them reaches the DH.
func TestNoX25519BeforeTag(t *testing.T) {
	calls := 0
	saved := dhCalls
	dhCalls = func() { calls++ }
	t.Cleanup(func() { dhCalls = saved })

	serverKey := newKey(t)
	allowAll := func([]byte) bool { return true }
	for range 10000 {
		_, _ = ServerHandshake(newMemConn(randomHead(t, hsHeadLen)), serverKey, allowAll, NewReplayFilter(), nil, testHeadKeys(), defaultPadPolicy())
	}
	if calls != 0 {
		t.Fatalf("%d DH computations for random heads, want none", calls)
	}

	_, _, R, err := selectEphemeral(wireEphemeral)
	if err != nil {
		t.Fatal(err)
	}
	head := headWithLength(t, serverKey, testPSK, R, 100)
	head[hsHeadLen-1] ^= 1
	_, _ = ServerHandshake(newMemConn(head), serverKey, allowAll, NewReplayFilter(), nil, testHeadKeys(), defaultPadPolicy())
	if calls != 0 {
		t.Fatalf("%d DH computations after a head with a wrong tag, want none", calls)
	}
}

// TestNoElligatorBeforeTag runs the same heads as TestNoX25519BeforeTag and counts the
// Elligator decodes.
func TestNoElligatorBeforeTag(t *testing.T) {
	calls := 0
	saved := elligatorCalls
	elligatorCalls = func() { calls++ }
	t.Cleanup(func() { elligatorCalls = saved })

	serverKey := newKey(t)
	allowAll := func([]byte) bool { return true }
	for range 10000 {
		_, _ = ServerHandshake(newMemConn(randomHead(t, hsHeadLen)), serverKey, allowAll, NewReplayFilter(), nil, testHeadKeys(), defaultPadPolicy())
	}
	if calls != 0 {
		t.Fatalf("%d Elligator decodes for random heads, want none", calls)
	}

	_, _, R, err := selectEphemeral(wireEphemeral)
	if err != nil {
		t.Fatal(err)
	}
	head := headWithLength(t, serverKey, testPSK, R, 100)
	head[hsKeyLen] ^= 1
	_, _ = ServerHandshake(newMemConn(head), serverKey, allowAll, NewReplayFilter(), nil, testHeadKeys(), defaultPadPolicy())
	if calls != 0 {
		t.Fatalf("%d Elligator decodes after a head with a wrong tag, want none", calls)
	}
}

// TestTagFailuresLeaveReplayFilterEmpty checks that no failed head writes to the
// replay filter, so that junk cannot fill it or change a client's count.
func TestTagFailuresLeaveReplayFilterEmpty(t *testing.T) {
	serverKey := newKey(t)
	filter := NewReplayFilter()
	allowAll := func([]byte) bool { return true }
	for range 10000 {
		_, err := ServerHandshake(newMemConn(randomHead(t, hsHeadLen)), serverKey, allowAll, filter, nil, testHeadKeys(), defaultPadPolicy())
		var he *HandshakeError
		if !errors.As(err, &he) || (he.Reason != "tag" && he.Reason != "prefix") {
			t.Fatalf("random head: error %v, want a tag or prefix decision", err)
		}
	}
	if n := len(filter.entries); n != 0 {
		t.Fatalf("replay filter holds %d entries after failed heads", n)
	}
	if n := len(filter.perClient); n != 0 {
		t.Fatalf("replay filter counts %d clients after failed heads", n)
	}
}

// TestUnauthorizedLeavesReplayFilterEmpty checks that a first message from a key the
// server does not accept writes nothing to the replay filter (9.6). The message is valid
// in every other respect, so only authorize refuses it. A PSK holder can send many such
// messages with fresh static keys, and each one would take an entry before the refusal.
// The control runs the same message with an accepting authorize, which must take one entry,
// so the filter is what the refusal leaves unchanged.
func TestUnauthorizedLeavesReplayFilterEmpty(t *testing.T) {
	serverKey, clientKey := newKey(t), newKey(t)
	msg1, _ := captureHandshake(t, clientKey, serverKey, defaultPadPolicy())

	filter := NewReplayFilter()
	he, sc := decide(t, serverKey, func([]byte) bool { return false }, filter, sendThenSentinel(msg1))
	if he.Reason != "unauthorized" || !errors.Is(he, ErrUnauthorized) {
		t.Fatalf("reason %q err %v, want unauthorized", he.Reason, he.Err)
	}
	expectSentinel(t, sc)
	if n := len(filter.entries); n != 0 {
		t.Fatalf("replay filter holds %d entries after an unauthorized key, want 0", n)
	}
	if n := len(filter.perClient); n != 0 {
		t.Fatalf("replay filter counts %d clients after an unauthorized key, want 0", n)
	}

	if _, err := ServerHandshake(newMemConn(msg1), serverKey, func([]byte) bool { return true }, filter, nil, testHeadKeys(), defaultPadPolicy()); err != nil {
		t.Fatalf("control with an accepted key: %v", err)
	}
	if n := len(filter.entries); n != 1 {
		t.Fatalf("control left %d entries, want 1", n)
	}
}

// TestNoKeyWorkBeforeTagAST checks, from the source, that serverHandshake does no key work
// before the tag check. The counters dhCalls, elligatorCalls and canonCalls see only the
// calls that they wrap, so an X25519 added above the tag check would pass the counter tests.
// Spec 9.6 and 15.3 allow a head that fails the tag one HMAC and one read. Every call before
// the tag check must therefore be on the list of cheap calls below.
func TestNoKeyWorkBeforeTagAST(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "handshake.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var fn *ast.FuncDecl
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == "serverHandshake" {
			fn = fd
		}
	}
	if fn == nil {
		t.Fatal("serverHandshake is not in handshake.go")
	}

	// The tag check is the first call to matchHeadTag in the function. matchHeadTag
	// holds the hmac.Equal calls, and its own body is checked below.
	tagPos := token.NoPos
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if ok && calleeName(call) == "matchHeadTag" && (tagPos == token.NoPos || call.Pos() < tagPos) {
			tagPos = call.Pos()
		}
		return true
	})
	if tagPos == token.NoPos {
		t.Fatal("no tag check (matchHeadTag) in serverHandshake")
	}
	var match *ast.FuncDecl
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == "matchHeadTag" {
			match = fd
		}
	}
	if match == nil {
		t.Fatal("matchHeadTag is not in handshake.go")
	}
	sawEqual := false
	ast.Inspect(match.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch name := calleeName(call); name {
		case "Equal":
			sawEqual = true
		case "headTag", "headBucket":
		default:
			t.Errorf("matchHeadTag calls %s at %v, but it may only compute and compare tags", name, fset.Position(call.Pos()))
		}
		return true
	})
	if !sawEqual {
		t.Fatal("matchHeadTag compares no tag")
	}

	// cheap lists the calls that may run before the tag check. None of them does a DH,
	// an Elligator decode or a Noise step.
	cheap := map[string]bool{
		"NewHandshakeState": true, // builds the Noise state, no key work
		"Now":               true, // clock
		"handshakeClock":    true, // clock, read for the tag bucket
		"Add":               true, // deadline arithmetic
		"SetDeadline":       true, // conn.SetDeadline, set and cleared around the handshake
		"read":              true, // preAuthReader: reads only
		"fail":              true, // preAuthReader: builds the decision
		"Contains":          true, // the probe table
		"headTag":           true, // one HMAC
		"string":            true, // conversion
		"[]byte":            true, // conversion
		"make":              true, // buffer
		"len":               true,
		"append":            true,
	}
	sawKeyWorkAfterTag := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := calleeName(call)
		if call.Pos() >= tagPos {
			if name == "X25519" || name == "elligatorDecode" {
				sawKeyWorkAfterTag = true
			}
			return true
		}
		if !cheap[name] {
			t.Errorf("call %s at %v runs before the tag check; spec 9.6 allows one HMAC and one read there",
				name, fset.Position(call.Pos()))
		}
		return true
	})
	if !sawKeyWorkAfterTag {
		t.Fatal("no X25519 or Elligator decode after the tag check, so the test looks at the wrong code")
	}
}

// calleeName returns the name of the function a call invokes: the identifier, or the
// selector's last name. A conversion to a slice type is named "[]byte". It returns ""
// for any other call, which the callers treat as not allowed.
func calleeName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	case *ast.ArrayType:
		return "[]byte"
	}
	return ""
}

// TestPreAuthSlotReleasedAtTagFailure checks that a head with a bad tag frees its
// pre-auth slot at byte 50, before the relay that the failure starts. The slot is
// seen held while the head is incomplete. The count is then read inside the decoy,
// which the relay reaches only after the decision, and it must be zero there. The
// decoy keeps the relay open until the count is read, so the relay's end cannot
// release the slot first. Nothing here depends on timing.
func TestPreAuthSlotReleasedAtTagFailure(t *testing.T) {
	setPreAuthTimeout(t, 3*time.Second)
	srv := newProbeServer(t, xnet.Destination{})
	slotAtDecoy := make(chan int, 1)
	holdRelay := make(chan struct{})
	srv.fallback = startDecoy(t, func(c net.Conn) {
		got := make([]byte, hsHeadLen)
		if _, err := io.ReadFull(c, got); err != nil {
			slotAtDecoy <- -1
			return
		}
		slotAtDecoy <- srv.adm.pendingCount()
		// Bounded, so that a failed test does not leave this goroutine waiting forever.
		select {
		case <-holdRelay:
		case <-time.After(10 * time.Second):
		}
	})

	server, prober := tcpPair(t)
	done := make(chan error, 1)
	go func() {
		_, err := srv.handlePreAuth(t.Context(), server, srv.pad)
		done <- err
	}()

	// The slot is taken at accept and held until the 50th byte decides. Waiting
	// for it to be held first shows the slot exists before it is checked.
	head := randomHead(t, hsHeadLen)
	if _, err := prober.Write(head[:hsHeadLen-1]); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for srv.adm.pendingCount() != 1 {
		if time.Now().After(deadline) {
			t.Fatal("no pre-auth slot was taken for the incomplete head")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := prober.Write(head[hsHeadLen-1:]); err != nil {
		t.Fatal(err)
	}

	select {
	case n := <-slotAtDecoy:
		if n != 0 {
			t.Fatalf("%d pre-auth slots held when the relay reached the decoy, want 0", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the decoy got no head")
	}
	close(holdRelay)
	_ = prober.Close()
	select {
	case err := <-done:
		if reasonOf(err) != "tag" {
			t.Fatalf("decision = %v, want reason tag", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pre-auth stage did not return")
	}
}

// FuzzHeadTag feeds arbitrary 50-byte heads to the responder. Only the prefix and tag
// reasons may appear, and a head that does not start with a probe table entry must
// get the tag reason at byte 50.
func FuzzHeadTag(f *testing.F) {
	serverKey := fuzzKey(f, 0x32)
	f.Add(make([]byte, hsHeadLen))
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	f.Add(bytes.Repeat([]byte{0x5a}, hsHeadLen))
	f.Add(append([]byte{0x16, 0x03}, make([]byte, hsHeadLen-2)...))

	f.Fuzz(func(t *testing.T, input []byte) {
		head := make([]byte, hsHeadLen)
		copy(head, input)
		_, err := ServerHandshake(newMemConn(head), serverKey, func([]byte) bool { return true }, NewReplayFilter(), nil, testHeadKeys(), defaultPadPolicy())
		var he *HandshakeError
		if !errors.As(err, &he) {
			t.Fatalf("error %v, want a HandshakeError", err)
		}
		switch {
		case hasPrefix2(head):
			if he.Reason != "prefix" || len(he.Consumed) != 2 {
				t.Fatalf("head with a 2-byte prefix: %q after %d bytes", he.Reason, len(he.Consumed))
			}
		case hasPrefix4(head):
			if he.Reason != "prefix" || len(he.Consumed) != 4 {
				t.Fatalf("head with a 4-byte prefix: %q after %d bytes", he.Reason, len(he.Consumed))
			}
		default:
			if he.Reason != "tag" || len(he.Consumed) != hsHeadLen {
				t.Fatalf("head with no prefix: %q after %d bytes, want tag after %d", he.Reason, len(he.Consumed), hsHeadLen)
			}
		}
	})
}
