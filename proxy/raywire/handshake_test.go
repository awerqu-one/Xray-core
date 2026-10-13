package raywire

import (
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/flynn/noise"
	"golang.org/x/crypto/curve25519"
	mrand "math/rand/v2"
)

var update = flag.Bool("update", false, "rewrite testdata/handshake_v4.golden from the current output")

// runHandshake runs both sides of the handshake over the two ends of a pipe, with the
// PSK-derived keys of testPSK on both sides. The client pins serverPublic, which is the
// public half of serverKey unless the test pins another key on purpose.
func runHandshake(t *testing.T, cc, sc net.Conn, clientKey noise.DHKey, serverPublic []byte, serverKey noise.DHKey, cpol, spol padPolicy) (client, server *Conn, cerr, serr error) {
	t.Helper()
	return runHandshakeWith(t, cc, sc, clientKey, serverPublic, serverKey, testKeys(), testHeadKeys(), cpol, spol)
}

// runHandshakeWith is runHandshake with the PSK-derived keys of each side given.
func runHandshakeWith(t *testing.T, cc, sc net.Conn, clientKey noise.DHKey, serverPublic []byte, serverKey noise.DHKey, ckeys pskKeys, skeys headKeys, cpol, spol padPolicy) (client, server *Conn, cerr, serr error) {
	t.Helper()

	accept := func(pub []byte) bool { return bytes.Equal(pub, clientKey.Public) }
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		server, serr = ServerHandshake(sc, serverKey, accept, NewReplayFilter(), nil, skeys, spol)
		if serr != nil {
			sc.Close()
		}
	}()
	client, cerr = ClientHandshake(cc, clientKey, serverPublic, ckeys, cpol)
	if cerr != nil {
		cc.Close()
	}
	wg.Wait()
	return client, server, cerr, serr
}

// captureHandshake runs one handshake and returns the bytes that each side wrote.
func captureHandshake(t *testing.T, clientKey, serverKey noise.DHKey, pol padPolicy) (msg1, msg2 []byte) {
	t.Helper()

	cc, sc := net.Pipe()
	crec, srec := &recordConn{Conn: cc}, &recordConn{Conn: sc}
	client, server, cerr, serr := runHandshake(t, crec, srec, clientKey, serverKey.Public, serverKey, pol, pol)
	if cerr != nil || serr != nil {
		t.Fatalf("handshake: client=%v server=%v", cerr, serr)
	}
	client.Close()
	server.Close()
	return crec.written(), srec.written()
}

// fixRandomness replaces the handshake's randomness and clock until the test ends.
// Each side draws only after the other has written, so the draws are in the same
// order on every run.
func fixRandomness(t *testing.T) {
	t.Helper()

	savedEph, savedPad, savedClock := ephRand, padRand, handshakeClock
	t.Cleanup(func() { ephRand, padRand, handshakeClock = savedEph, savedPad, savedClock })
	ephRand = mrand.NewChaCha8([32]byte{1})
	padRand = mrand.NewChaCha8([32]byte{2})
	handshakeClock = func() time.Time { return testNow }
}

// fixedKeys returns two static key pairs with fixed private halves.
func fixedKeys(t *testing.T) (client, server noise.DHKey) {
	t.Helper()

	var err error
	if client, err = keyFromPrivate(bytes.Repeat([]byte{0x11}, 32)); err != nil {
		t.Fatal(err)
	}
	if server, err = keyFromPrivate(bytes.Repeat([]byte{0x22}, 32)); err != nil {
		t.Fatal(err)
	}
	return client, server
}

func TestHandshakeRoundTripPadded(t *testing.T) {
	for _, p := range []int{0, 1, 255, 512} {
		t.Run(fmt.Sprintf("pad%d", p), func(t *testing.T) {
			clientKey, serverKey := newKey(t), newKey(t)
			pol := padPolicy{Handshake: p}
			cc, sc := net.Pipe()
			client, server, cerr, serr := runHandshake(t, cc, sc, clientKey, serverKey.Public, serverKey, pol, pol)
			if cerr != nil || serr != nil {
				t.Fatalf("handshake: client=%v server=%v", cerr, serr)
			}
			defer client.Close()
			defer server.Close()

			// Each side sends one message through the frame layer.
			errCh := make(chan error, 1)
			go func() {
				_, err := client.Write([]byte("request"))
				errCh <- err
			}()
			got := make([]byte, len("request"))
			if _, err := io.ReadFull(server, got); err != nil {
				t.Fatalf("server read: %v", err)
			}
			if err := <-errCh; err != nil {
				t.Fatalf("client write: %v", err)
			}
			if string(got) != "request" {
				t.Fatalf("server got %q, want %q", got, "request")
			}

			go func() {
				_, err := server.Write([]byte("response"))
				errCh <- err
			}()
			reply := make([]byte, len("response"))
			if _, err := io.ReadFull(client, reply); err != nil {
				t.Fatalf("client read: %v", err)
			}
			if err := <-errCh; err != nil {
				t.Fatalf("server write: %v", err)
			}
			if string(reply) != "response" {
				t.Fatalf("client got %q, want %q", reply, "response")
			}
		})
	}
}

// TestHandshakeMessageLengths checks that msg1 is 122 + P1 bytes and msg2 is 50 + P2
// bytes, for pads of 0, 1, 255 and 512. The remainder length is decoded with the DH and
// the mask computed here.
func TestHandshakeMessageLengths(t *testing.T) {
	for _, p := range []int{0, 1, 255, 512} {
		clientKey, serverKey := newKey(t), newKey(t)
		for range 4 {
			msg1, msg2 := captureHandshake(t, clientKey, serverKey, padPolicy{Handshake: p})

			p1, p2 := len(msg1)-122, len(msg2)-50
			if p1 < 0 || p1 > p || p2 < 0 || p2 > p {
				t.Fatalf("P=%d: msg1 is %d bytes and msg2 is %d bytes", p, len(msg1), len(msg2))
			}
			if p == 0 && len(msg1) != 122 {
				t.Fatalf("P=0: msg1 is %d bytes, want 122", len(msg1))
			}
			if n1 := checkHeadFormulas(t, msg1, serverKey, testPSK); n1 != 72+p1 {
				t.Fatalf("P=%d: length word decodes to %d, want %d", p, n1, 72+p1)
			}
		}
	}
}

// TestEphemeralResamplesProbePrefix drives the selection with scripted keys. The
// first two wire forms start with a probe prefix, so the third must be chosen.
func TestEphemeralResamplesProbePrefix(t *testing.T) {
	prefixed := func(prefix string) []byte {
		R := bytes.Repeat([]byte{0x40}, hsKeyLen)
		copy(R, prefix)
		return R
	}
	wire := [][]byte{prefixed("\x16\x03"), prefixed("POST"), prefixed("\x01\x02")}
	calls := 0
	next := func() ([]byte, []byte, []byte, error) {
		calls++
		return []byte{byte(calls)}, []byte{byte(calls)}, wire[calls-1], nil
	}

	k, _, R, err := selectEphemeral(next)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatalf("selection drew %d keys, want 3", calls)
	}
	if !bytes.Equal(k, []byte{3}) || !bytes.Equal(R, wire[2]) {
		t.Fatalf("selected key %x with wire form %x, want the third draw", k, R)
	}
}

// TestEphemeralDrawsAvoidProbePrefixes runs the real key selection that every
// client handshake uses. The rule is also covered by the scripted test above. A
// prefix occurs with probability 1.5e-5 per draw, so this check is a sanity
// check on the wire form, not the main test.
func TestEphemeralDrawsAvoidProbePrefixes(t *testing.T) {
	for range 1000 {
		k, u, R, err := selectEphemeral(wireEphemeral)
		if err != nil {
			t.Fatal(err)
		}
		if hasPrefix2(R) || hasPrefix4(R) {
			t.Fatalf("wire form %x starts with a probe prefix", R)
		}
		// The wire form carries u + T, and the canonical point is the chosen u.
		if !bytes.Equal(canonicalDecode(R), u) {
			t.Fatalf("wire form %x does not decode to the chosen point %x", R, u)
		}
		if !bytes.Equal(curveBasePoint(k), u) {
			t.Fatalf("private key %x does not give the chosen point %x", k, u)
		}
	}
}

// curveBasePoint returns the X25519 public key for the private key k.
func curveBasePoint(k []byte) []byte {
	u, err := curve25519.X25519(k, curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	return u
}

func TestProbePrefixMatch(t *testing.T) {
	for _, e := range prefixTable4 {
		if !hasPrefix4([]byte(e + "x")) {
			t.Errorf("table entry %q not matched", e)
		}
	}
	if !hasPrefix2([]byte{0x16, 0x03, 0x01}) {
		t.Error("TLS record start not matched")
	}
	// Short inputs and near misses must not match either table.
	for _, b := range [][]byte{{0x16}, {0x16, 0x02, 0x01}, []byte("GET"), []byte("GETX")} {
		if hasPrefix2(b) || hasPrefix4(b) {
			t.Errorf("%q matched a probe table", b)
		}
	}
}

func TestScriptedRandDrawsOnce(t *testing.T) {
	var r scriptedRand
	if _, err := r.Read(make([]byte, 32)); err == nil {
		t.Fatal("an unarmed draw succeeded")
	}

	key := bytes.Repeat([]byte{7}, 32)
	r.arm(key)
	got := make([]byte, 32)
	if _, err := io.ReadFull(&r, got); err != nil || !bytes.Equal(got, key) {
		t.Fatalf("armed draw = %x, %v; want %x", got, err, key)
	}
	if _, err := r.Read(got); err == nil {
		t.Fatal("a second draw succeeded")
	}
}

// TestHandshakeGoldenVector pins the bytes of one handshake with fixed keys, fixed
// randomness and a fixed clock. The file is regenerated with -update.
func TestHandshakeGoldenVector(t *testing.T) {
	fixRandomness(t)
	clientKey, serverKey := fixedKeys(t)
	msg1, msg2 := captureHandshake(t, clientKey, serverKey, defaultPadPolicy())
	got := fmt.Sprintf("msg1 %x\nmsg2 %x\n", msg1, msg2)

	const path = "testdata/handshake_v4.golden"
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden vector: %v (run the test with -update to create it)", err)
	}
	if string(want) != got {
		t.Fatalf("handshake bytes differ from %s\n got: %s\nwant: %s", path, got, want)
	}
}

// TestGoldenVectorIsSpecFormula checks the golden msg1 against section 5, so that the
// golden file cannot pin bytes that the spec does not give.
func TestGoldenVectorIsSpecFormula(t *testing.T) {
	fixRandomness(t)
	raw, err := os.ReadFile("testdata/handshake_v4.golden")
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(raw))
	if len(fields) != 4 || fields[0] != "msg1" {
		t.Fatalf("golden file has %d fields, want msg1 and msg2 in hex", len(fields))
	}
	msg1 := mustHex(t, fields[1])
	_, serverKey := fixedKeys(t)
	if n1 := checkHeadFormulas(t, msg1, serverKey, testPSK); n1 < 72 {
		t.Fatalf("golden remainder is %d bytes", n1)
	}
}

// mustHex decodes a hex string or fails the test.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestWrongServerKeyFailsOnClient checks the client side. The server rejects a head
// that is keyed for another server at byte 50, so the budget only bounds the test. The
// decision must be the tag, at the 50 bytes of the head: the tag binds the head to the
// server's public key, so no other reason is right for this head.
func TestWrongServerKeyFailsOnClient(t *testing.T) {
	saved := preAuthTimeout
	preAuthTimeout = 200 * time.Millisecond
	t.Cleanup(func() { preAuthTimeout = saved })

	clientKey, serverKey, otherKey := newKey(t), newKey(t), newKey(t)
	cc, sc := net.Pipe()
	_, _, cerr, serr := runHandshake(t, cc, sc, clientKey, otherKey.Public, serverKey,
		defaultPadPolicy(), defaultPadPolicy())
	if cerr == nil {
		t.Fatal("client accepted a server that does not hold the pinned key")
	}
	var he *HandshakeError
	if !errors.As(serr, &he) {
		t.Fatalf("server error = %v, want a *HandshakeError", serr)
	}
	if he.Reason != "tag" || !errors.Is(he, ErrTag) || len(he.Consumed) != hsHeadLen {
		t.Fatalf("server decision %q err %v with %d bytes, want tag with %d", he.Reason, he.Err, len(he.Consumed), hsHeadLen)
	}
}

// sentinel is written by the peer right after the bytes that decide a probe. The
// server must leave it unread.
const sentinel = "after-decision"

// readSignal closes ch on the first Read. A peer waits for it before it closes,
// because net.Pipe makes SetDeadline fail once the remote end is closed.
type readSignal struct {
	net.Conn
	once sync.Once
	ch   chan struct{}
}

func (c *readSignal) Read(p []byte) (int, error) {
	c.once.Do(func() { close(c.ch) })
	return c.Conn.Read(p)
}

// decide runs ServerHandshake on one end of a pipe while peer writes to the
// other end. It checks that the failure is a HandshakeError and that the server
// wrote nothing. It returns the failure and the server end of the pipe.
func decide(t *testing.T, serverKey noise.DHKey, authorize func([]byte) bool, filter *ReplayFilter, peer func(c net.Conn, reading <-chan struct{})) (*HandshakeError, net.Conn) {
	t.Helper()

	cc, sc := net.Pipe()
	t.Cleanup(func() {
		cc.Close()
		sc.Close()
	})
	reading := make(chan struct{})
	rec := &recordConn{Conn: &readSignal{Conn: sc, ch: reading}}
	go peer(cc, reading)

	_, err := ServerHandshake(rec, serverKey, authorize, filter, nil, testHeadKeys(), defaultPadPolicy())
	var he *HandshakeError
	if !errors.As(err, &he) {
		t.Fatalf("server error = %v, want a *HandshakeError", err)
	}
	if n := len(rec.written()); n != 0 {
		t.Fatalf("server wrote %d bytes to a peer that was not authenticated", n)
	}
	return he, sc
}

// sendThenSentinel is a peer that writes probe and then the sentinel.
func sendThenSentinel(probe []byte) func(net.Conn, <-chan struct{}) {
	data := append(append([]byte(nil), probe...), sentinel...)
	return func(c net.Conn, _ <-chan struct{}) {
		_, _ = c.Write(data)
	}
}

// sendThenClose is a peer that writes probe and then closes.
func sendThenClose(probe []byte) func(net.Conn, <-chan struct{}) {
	return func(c net.Conn, _ <-chan struct{}) {
		_, _ = c.Write(probe)
		c.Close()
	}
}

// closeWhenReading is a peer that closes without writing, once the server reads.
func closeWhenReading(c net.Conn, reading <-chan struct{}) {
	<-reading
	c.Close()
}

// idle is a peer that writes nothing and stays open.
func idle(net.Conn, <-chan struct{}) {}

// expectSentinel reads the next bytes from the server end. Anything but the
// sentinel means the server read past its decision.
func expectSentinel(t *testing.T, sc net.Conn) {
	t.Helper()

	if err := sc.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(sentinel))
	if _, err := io.ReadFull(sc, got); err != nil || string(got) != sentinel {
		t.Fatalf("bytes after the decision are %q (%v), want %q", got, err, sentinel)
	}
}

// TestHandshakeDecisions checks the bytes consumed and the reason at each decision
// point of the server. A probe is followed by the sentinel wherever the server
// decides on bytes already sent, so an extra read would show up.
func TestHandshakeDecisions(t *testing.T) {
	saved := preAuthTimeout
	preAuthTimeout = 200 * time.Millisecond
	t.Cleanup(func() { preAuthTimeout = saved })

	serverKey := newKey(t)
	clientKey := newKey(t)
	allowAll := func([]byte) bool { return true }
	denyAll := func([]byte) bool { return false }

	// A real msg1 from clientKey, for the cases that need a well-formed first message.
	msg1, _ := captureHandshake(t, clientKey, serverKey, defaultPadPolicy())

	t.Run("eof at zero bytes", func(t *testing.T) {
		he, _ := decide(t, serverKey, allowAll, NewReplayFilter(), closeWhenReading)
		if he.Reason != "eof" || len(he.Consumed) != 0 {
			t.Fatalf("reason %q with %d bytes consumed, want eof with none", he.Reason, len(he.Consumed))
		}
	})

	t.Run("deadline at zero bytes", func(t *testing.T) {
		he, _ := decide(t, serverKey, allowAll, NewReplayFilter(), idle)
		if he.Reason != "deadline" || len(he.Consumed) != 0 {
			t.Fatalf("reason %q with %d bytes consumed, want deadline with none", he.Reason, len(he.Consumed))
		}
	})

	t.Run("deadline after three bytes", func(t *testing.T) {
		probe := []byte{0x00, 0x01, 0x02}
		he, _ := decide(t, serverKey, allowAll, NewReplayFilter(), func(c net.Conn, _ <-chan struct{}) { _, _ = c.Write(probe) })
		if he.Reason != "deadline" || !bytes.Equal(he.Consumed, probe) {
			t.Fatalf("reason %q consumed %x, want deadline with %x", he.Reason, he.Consumed, probe)
		}
	})

	t.Run("one byte then eof", func(t *testing.T) {
		probe := []byte{0x01}
		he, _ := decide(t, serverKey, allowAll, NewReplayFilter(), sendThenClose(probe))
		if he.Reason != "eof" || !bytes.Equal(he.Consumed, probe) {
			t.Fatalf("reason %q consumed %x, want eof with %x", he.Reason, he.Consumed, probe)
		}
	})

	// Silent bytes that match no prefix are held to the deadline, so a probe of 1 to 49
	// bytes waits for the pre-auth budget (residual R1).
	for _, k := range []int{1, 5, 33, 49} {
		t.Run(fmt.Sprintf("deadline after %d silent bytes", k), func(t *testing.T) {
			probe := bytes.Repeat([]byte{0x5a}, k)
			he, _ := decide(t, serverKey, allowAll, NewReplayFilter(), func(c net.Conn, _ <-chan struct{}) { _, _ = c.Write(probe) })
			if he.Reason != "deadline" || !bytes.Equal(he.Consumed, probe) {
				t.Fatalf("reason %q consumed %x, want deadline with %x", he.Reason, he.Consumed, probe)
			}
		})
	}

	t.Run("eof after 49 bytes", func(t *testing.T) {
		probe := bytes.Repeat([]byte{0x5a}, 49)
		he, _ := decide(t, serverKey, allowAll, NewReplayFilter(), sendThenClose(probe))
		if he.Reason != "eof" || !bytes.Equal(he.Consumed, probe) {
			t.Fatalf("reason %q with %d bytes consumed, want eof with 49", he.Reason, len(he.Consumed))
		}
	})

	t.Run("tls record start at two bytes", func(t *testing.T) {
		probe := []byte(prefixTable2)
		he, sc := decide(t, serverKey, allowAll, NewReplayFilter(), sendThenSentinel(probe))
		if he.Reason != "prefix" || !bytes.Equal(he.Consumed, probe) {
			t.Fatalf("reason %q consumed %x, want prefix with %x", he.Reason, he.Consumed, probe)
		}
		expectSentinel(t, sc)
	})

	for _, entry := range prefixTable4 {
		t.Run("table entry "+entry+" at four bytes", func(t *testing.T) {
			probe := []byte(entry)
			he, sc := decide(t, serverKey, allowAll, NewReplayFilter(), sendThenSentinel(probe))
			if he.Reason != "prefix" || !bytes.Equal(he.Consumed, probe) {
				t.Fatalf("reason %q consumed %x, want prefix with %x", he.Reason, he.Consumed, probe)
			}
			expectSentinel(t, sc)
		})
	}

	t.Run("tag wrong at 50 bytes", func(t *testing.T) {
		probe := bytes.Repeat([]byte{0x5a}, hsHeadLen)
		he, sc := decide(t, serverKey, allowAll, NewReplayFilter(), sendThenSentinel(probe))
		if he.Reason != "tag" || !errors.Is(he, ErrTag) || !bytes.Equal(he.Consumed, probe) {
			t.Fatalf("reason %q err %v consumed %d, want tag with %d", he.Reason, he.Err, len(he.Consumed), hsHeadLen)
		}
		expectSentinel(t, sc)
	})

	// A length out of range is decided only when the tag is valid, so the head is
	// built with the PSK.
	for _, n1 := range []int{0, hsMinN1 - 1, hsMaxN1 + 1, 0xffff} {
		t.Run(fmt.Sprintf("length %d out of range with a valid tag", n1), func(t *testing.T) {
			_, _, R, err := selectEphemeral(wireEphemeral)
			if err != nil {
				t.Fatal(err)
			}
			probe := headWithLength(t, serverKey, testPSK, R, n1)
			he, sc := decide(t, serverKey, allowAll, NewReplayFilter(), sendThenSentinel(probe))
			if he.Reason != "length" || !bytes.Equal(he.Consumed, probe) {
				t.Fatalf("reason %q consumed %x, want length with %x", he.Reason, he.Consumed, probe)
			}
			expectSentinel(t, sc)
		})
	}

	t.Run("length word ends early", func(t *testing.T) {
		_, _, R, err := selectEphemeral(wireEphemeral)
		if err != nil {
			t.Fatal(err)
		}
		probe := append(headWithLength(t, serverKey, testPSK, R, 100), make([]byte, 40)...)
		he, _ := decide(t, serverKey, allowAll, NewReplayFilter(), sendThenClose(probe))
		if he.Reason != "eof" || !bytes.Equal(he.Consumed, probe) || len(probe) != 90 {
			t.Fatalf("reason %q with %d bytes consumed, want eof with 90", he.Reason, len(he.Consumed))
		}
	})

	t.Run("ephemeral key is low order", func(t *testing.T) {
		// R of all zeros decodes to the point 0, which X25519 rejects. The head has a
		// valid tag, so the server reaches the DH.
		zero := make([]byte, hsKeyLen)
		probe := rawHead(testPSK, serverKey.Public, zero, []byte{0x00, 0x00})
		he, sc := decide(t, serverKey, allowAll, NewReplayFilter(), sendThenSentinel(probe))
		if he.Reason != "ephemeral" || !bytes.Equal(he.Consumed, probe) {
			t.Fatalf("reason %q consumed %x, want ephemeral with %x", he.Reason, he.Consumed, probe)
		}
		expectSentinel(t, sc)
	})

	t.Run("noise failure", func(t *testing.T) {
		probe := bytes.Clone(msg1)
		probe[60] ^= 0x01 // inside enc(S), so the static key fails to open
		he, sc := decide(t, serverKey, allowAll, NewReplayFilter(), sendThenSentinel(probe))
		if he.Reason != "noise" || !bytes.Equal(he.Consumed, probe) {
			t.Fatalf("reason %q with %d bytes consumed, want noise with %d", he.Reason, len(he.Consumed), len(probe))
		}
		expectSentinel(t, sc)
	})

	t.Run("unauthorized key", func(t *testing.T) {
		he, sc := decide(t, serverKey, denyAll, NewReplayFilter(), sendThenSentinel(msg1))
		if he.Reason != "unauthorized" || !errors.Is(he, ErrUnauthorized) || !bytes.Equal(he.Consumed, msg1) {
			t.Fatalf("reason %q err %v with %d bytes consumed, want unauthorized with %d",
				he.Reason, he.Err, len(he.Consumed), len(msg1))
		}
		expectSentinel(t, sc)
	})

	t.Run("replayed first message", func(t *testing.T) {
		filter := NewReplayFilter()
		now := time.Now()
		if !filter.Accept("client", canonicalDecode(msg1[:hsKeyLen]), now, now) {
			t.Fatal("could not seed the replay filter")
		}
		he, sc := decide(t, serverKey, allowAll, filter, sendThenSentinel(msg1))
		if he.Reason != "replay" || !errors.Is(he, ErrReplay) || !bytes.Equal(he.Consumed, msg1) {
			t.Fatalf("reason %q err %v with %d bytes consumed, want replay with %d",
				he.Reason, he.Err, len(he.Consumed), len(msg1))
		}
		expectSentinel(t, sc)
	})

	t.Run("tag bucket window", func(t *testing.T) {
		// The server's clock is testNow, the start of a bucket. A head is tagged with
		// the bucket of the client's clock, and the server accepts that bucket and one
		// on each side. A head from further away fails at byte 50, as a junk head does,
		// and so a captured head has no stall once its window has passed.
		savedClock := handshakeClock
		t.Cleanup(func() { handshakeClock = savedClock })
		for _, tc := range []struct {
			name   string
			offset time.Duration
			reason string
		}{
			// The client is refused by authorize, which comes after the tag, so the
			// reason shows that the tag verified.
			{"previous bucket", -299 * time.Second, "unauthorized"},
			{"next bucket, timestamp too far", 2*headBucketSeconds*time.Second - time.Second, "replay"},
			{"two buckets ahead", 2 * headBucketSeconds * time.Second, "tag"},
			{"two buckets behind", -301 * time.Second, "tag"},
			{"ten minutes behind", -10 * time.Minute, "tag"},
			{"a day behind", -24 * time.Hour, "tag"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				handshakeClock = func() time.Time { return testNow.Add(tc.offset) }
				head, _ := captureHandshake(t, clientKey, serverKey, defaultPadPolicy())
				handshakeClock = func() time.Time { return testNow }
				auth := allowAll
				if tc.reason == "unauthorized" {
					auth = func([]byte) bool { return false }
				}
				he, _ := decide(t, serverKey, auth, NewReplayFilter(), sendThenSentinel(head))
				got := ""
				if he != nil {
					got = he.Reason
				}
				if got != tc.reason {
					t.Fatalf("reason %q, want %q", got, tc.reason)
				}
				if tc.reason == "tag" && len(he.Consumed) != hsHeadLen {
					t.Fatalf("%d bytes consumed, want the %d of the head", len(he.Consumed), hsHeadLen)
				}
			})
		}
	})

	t.Run("skewed timestamp", func(t *testing.T) {
		// Capture with a client clock just over the allowed skew ahead, so the head
		// is in the next bucket and its tag verifies, then restore the clock for
		// the server.
		savedClock := handshakeClock
		t.Cleanup(func() { handshakeClock = savedClock })
		ahead := aheadOfSkew(time.Now())
		handshakeClock = func() time.Time { return ahead }
		skewed, _ := captureHandshake(t, clientKey, serverKey, defaultPadPolicy())
		handshakeClock = savedClock

		he, sc := decide(t, serverKey, allowAll, NewReplayFilter(), sendThenSentinel(skewed))
		if he.Reason != "replay" || !errors.Is(he, ErrReplay) || !bytes.Equal(he.Consumed, skewed) {
			t.Fatalf("reason %q err %v with %d bytes consumed, want replay with %d",
				he.Reason, he.Err, len(he.Consumed), len(skewed))
		}
		expectSentinel(t, sc)
	})
}

// TestLengthDHOnRawPoint checks the reason the server takes the length DH from
// the raw decoded point u + T. For random static keys and all eight torsion
// shifts of a subgroup point u, X25519 gives the same bytes on u + T as on u,
// and the canonical point is u.
func TestLengthDHOnRawPoint(t *testing.T) {
	src := ellSource(22)
	for range 64 {
		s := ellRead(t, src, 32)
		u, err := curve25519.X25519(ellRead(t, src, 32), curve25519.Basepoint)
		if err != nil {
			t.Fatal(err)
		}
		want, err := curve25519.X25519(s, u)
		if err != nil {
			t.Fatalf("DH with the subgroup point %x failed: %v", u, err)
		}
		for sel := range 8 {
			shifted := torsionShift(u, sel)
			if shifted == nil {
				t.Fatalf("shift %d of %x failed", sel, u)
			}
			if got := canonicalPoint(shifted); !bytes.Equal(got, u) {
				t.Fatalf("canonical(shift %d of %x) = %x", sel, u, got)
			}
			got, err := curve25519.X25519(s, shifted)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("length DH on shift %d differs from the DH on %x: %v", sel, u, err)
			}
		}
	}
}

// TestTorsionOnlyPointsFailDH checks that the two checks on the raw point agree.
// For a torsion-only input the canonical point is nil, and the length DH fails.
// The server relies on the DH to decide first, so the nil check after the length
// check never changes a decision.
func TestTorsionOnlyPointsFailDH(t *testing.T) {
	src := ellSource(23)
	for range 8 {
		s := ellRead(t, src, 32)
		for _, T := range elliTorsion {
			if T == nil {
				continue // the point at infinity has no u-coordinate
			}
			u := feToLE(T.u)
			if canonicalPoint(u) != nil {
				t.Fatalf("canonical point of torsion u %x is not nil", u)
			}
			if _, err := curve25519.X25519(s, u); err == nil {
				t.Fatalf("length DH on torsion u %x succeeded", u)
			}
		}
	}
	// The zero u-coordinate is the order-2 point, which is in the table above.
	if canonicalPoint(make([]byte, 32)) != nil {
		t.Fatal("canonical point of 0 is not nil")
	}
}

// TestTorsionEphemeralDecidesAtHead sends a head whose R_e decodes to a torsion-only
// point, with a valid tag. The server must refuse it at byte 50, as the low-order case
// always did, and read nothing more.
func TestTorsionEphemeralDecidesAtHead(t *testing.T) {
	serverKey := newKey(t)
	allowAll := func([]byte) bool { return true }
	encoded := 0
	for _, T := range elliTorsion {
		if T == nil {
			continue
		}
		r, ok := elligatorE(feToLE(T.u))
		if !ok {
			continue
		}
		encoded++
		R := wireForm(r, mrand.NewChaCha8([32]byte{9}))
		if R == nil {
			t.Fatal("wireForm failed")
		}
		// W1 is never used, because the DH fails first. Any value works under the tag.
		probe := rawHead(testPSK, serverKey.Public, R, []byte{0x12, 0x34})
		he, sc := decide(t, serverKey, allowAll, NewReplayFilter(), sendThenSentinel(probe))
		if he.Reason != "ephemeral" || !bytes.Equal(he.Consumed, probe) {
			t.Fatalf("torsion R %x: reason %q consumed %d bytes, want ephemeral with %d", R, he.Reason, len(he.Consumed), len(probe))
		}
		expectSentinel(t, sc)
	}
	// u = 0 is always encodable, since F(0) = 0, so the loop checks at least one probe.
	if encoded == 0 {
		t.Fatal("no torsion point was encodable")
	}
	t.Logf("%d of the 7 finite torsion table entries are encodable", encoded)
}

// serveMsg1 runs ServerHandshake over a pipe, with msg1 as the client's first
// message and filter as the server's replay filter. The peer drains whatever the
// server writes, so a successful handshake does not block. It returns the
// server's error.
func serveMsg1(t *testing.T, serverKey noise.DHKey, filter *ReplayFilter, msg1 []byte) error {
	t.Helper()

	cc, sc := net.Pipe()
	defer cc.Close()
	go func() {
		_, _ = cc.Write(msg1)
		_, _ = io.Copy(io.Discard, cc)
	}()
	accept := func([]byte) bool { return true }
	conn, err := ServerHandshake(sc, serverKey, accept, filter, nil, testHeadKeys(), defaultPadPolicy())
	if conn != nil {
		conn.Close()
	}
	sc.Close()
	return err
}

// retagged returns msg1 with its first 32 bytes replaced by wire and the head tag
// recomputed under testPSK. The length word is the same, because every wire form of
// one point gives the same DH. Only a holder of the PSK can build it.
func retagged(t *testing.T, msg1 []byte, serverKey noise.DHKey, wire []byte) []byte {
	t.Helper()
	W1 := msg1[hsKeyLen : hsKeyLen+2]
	out := append([]byte(nil), wire...)
	out = append(out, W1...)
	out = append(out, refTag(refHeadKey(testPSK), serverKey.Public, wire, W1, testBucket())...)
	return append(out, msg1[hsHeadLen:]...)
}

// TestReplayKeyIsCanonical re-sends an accepted msg1 with its first 32 bytes
// re-encoded. Bit 255 flipped and r replaced by p - r both decode to the same
// point, so each variant is a valid handshake on a fresh server and a replay on
// the server that accepted the original. The variants carry a tag recomputed under the
// PSK, so the holder of the PSK builds them. This pins the canonical replay key.
func TestReplayKeyIsCanonical(t *testing.T) {
	// The wire forms must not start with a probe prefix, so the randomness is
	// fixed. Each variant then has a known first byte pattern.
	fixRandomness(t)
	serverKey, clientKey := newKey(t), newKey(t)
	msg1, _ := captureHandshake(t, clientKey, serverKey, defaultPadPolicy())

	filter := NewReplayFilter()
	if err := serveMsg1(t, serverKey, filter, msg1); err != nil {
		t.Fatalf("original msg1 refused: %v", err)
	}

	flipped := bytes.Clone(msg1[:hsKeyLen])
	flipped[31] ^= 0x80

	// r is the wire value with bit 255 cleared, and p - r is its negation. F(p - r)
	// = F(r), so the wire form of -r decodes to the same point as the original.
	body := bytes.Clone(msg1[:hsKeyLen])
	bit := body[31] & 0x80
	body[31] &= 0x7f
	r := new(big.Int).Mod(feFromLE(body), elliP)
	neg := feToLE(new(big.Int).Sub(elliP, r))
	neg[31] |= bit

	for _, v := range []struct {
		name  string
		probe []byte
	}{
		{"bit 255 flipped", retagged(t, msg1, serverKey, flipped)},
		{"p - r", retagged(t, msg1, serverKey, neg)},
	} {
		if bytes.Equal(v.probe, msg1) {
			t.Fatalf("%s variant is the original", v.name)
		}
		if err := serveMsg1(t, serverKey, NewReplayFilter(), v.probe); err != nil {
			t.Fatalf("%s: a fresh server refused the variant: %v", v.name, err)
		}
		err := serveMsg1(t, serverKey, filter, v.probe)
		var he *HandshakeError
		if !errors.As(err, &he) || he.Reason != "replay" || !bytes.Equal(he.Consumed, v.probe) {
			t.Fatalf("%s: server error %v, want a replay refusal of the variant", v.name, err)
		}
	}
}

// TestRetaggedVariantIsNotOriginal checks the premise of TestReplayKeyIsCanonical:
// flipping bit 255 without recomputing the tag gives the tag reason, which is what v3
// requires of any change to R_e.
func TestRetaggedVariantIsNotOriginal(t *testing.T) {
	fixRandomness(t)
	serverKey, clientKey := newKey(t), newKey(t)
	msg1, _ := captureHandshake(t, clientKey, serverKey, defaultPadPolicy())
	raw := flipBit(msg1, 255)
	if err := serveMsg1(t, serverKey, NewReplayFilter(), raw); err == nil {
		t.Fatal("a raw bit-255 flip was accepted")
	} else if reasonOf(err) != "tag" {
		t.Fatalf("raw bit-255 flip: %v, want reason tag", err)
	}
}

// TestSentinelAfterEveryDecision checks, for each reason that the peer's own bytes can
// produce, that the server stops at its decision and never reads the sentinel that
// follows. The reasons eof, deadline and read decide on bytes that are missing, so they
// take no sentinel. The reason payload cannot be reached (TestPayloadBelowMinimumIsLength).
func TestSentinelAfterEveryDecision(t *testing.T) {
	saved := preAuthTimeout
	preAuthTimeout = 200 * time.Millisecond
	t.Cleanup(func() { preAuthTimeout = saved })

	serverKey, clientKey := newKey(t), newKey(t)
	allowAll := func([]byte) bool { return true }
	denyAll := func([]byte) bool { return false }
	msg1, _ := captureHandshake(t, clientKey, serverKey, defaultPadPolicy())
	_, _, R, err := selectEphemeral(wireEphemeral)
	if err != nil {
		t.Fatal(err)
	}
	flipped := bytes.Clone(msg1)
	flipped[60] ^= 0x01

	seeded := NewReplayFilter()
	now := time.Now()
	if !seeded.Accept("client", canonicalDecode(msg1[:hsKeyLen]), now, now) {
		t.Fatal("could not seed the replay filter")
	}

	for _, c := range []struct {
		reason    string
		probe     []byte
		authorize func([]byte) bool
		filter    *ReplayFilter
	}{
		{"prefix", []byte(prefixTable2), allowAll, NewReplayFilter()},
		{"prefix", []byte("GET "), allowAll, NewReplayFilter()},
		{"tag", bytes.Repeat([]byte{0x5a}, hsHeadLen), allowAll, NewReplayFilter()},
		{"ephemeral", rawHead(testPSK, serverKey.Public, make([]byte, hsKeyLen), []byte{0, 0}), allowAll, NewReplayFilter()},
		{"length", headWithLength(t, serverKey, testPSK, R, 0), allowAll, NewReplayFilter()},
		{"noise", flipped, allowAll, NewReplayFilter()},
		{"unauthorized", msg1, denyAll, NewReplayFilter()},
		{"replay", msg1, allowAll, seeded},
	} {
		he, sc := decide(t, serverKey, c.authorize, c.filter, sendThenSentinel(c.probe))
		if he.Reason != c.reason || !bytes.Equal(he.Consumed, c.probe) {
			t.Fatalf("%s: reason %q with %d bytes consumed, want %q with %d",
				c.reason, he.Reason, len(he.Consumed), c.reason, len(c.probe))
		}
		expectSentinel(t, sc)
	}
}
