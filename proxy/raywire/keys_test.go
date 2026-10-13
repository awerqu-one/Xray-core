package raywire

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// testPrevPSK is the previousPsk of the rotation tests. testPSK plays the new PSK, and
// testOtherPSK is a third PSK that no test server holds.
var (
	testPrevPSK  = bytes.Repeat([]byte{0x44}, pskLen)
	testOtherPSK = bytes.Repeat([]byte{0x55}, pskLen)
)

// newHeadKeysFor returns the head keys of an inbound with psk, previousPsk and expiry
// until, built the way NewServer builds them.
func newHeadKeysFor(t *testing.T, psk, previous []byte, until time.Time) headKeys {
	t.Helper()
	hk, err := newHeadKeys(psk, previous, until)
	if err != nil {
		t.Fatal(err)
	}
	return hk
}

// recordMsg1Under is recordMsg1 for a client that holds the keys of one PSK.
func recordMsg1Under(t *testing.T, clientKey noise.DHKey, serverPublic []byte, at time.Time, keys pskKeys) []byte {
	t.Helper()
	cc, sc := net.Pipe()
	defer cc.Close()
	defer sc.Close()

	saved := handshakeClock
	handshakeClock = func() time.Time { return at }
	defer func() { handshakeClock = saved }()

	rec := &msg1Recorder{Conn: cc}
	_, err := ClientHandshake(rec, clientKey, serverPublic, keys, defaultPadPolicy())
	if !errors.Is(err, errMsg1Recorded) {
		t.Fatalf("client handshake error = %v, want the recorded first message", err)
	}
	return rec.msg
}

// serveWithKeys runs serverHandshake with the head keys of a server on one pipe, where the
// peer writes probe and then reads what the server writes. The clients are the authorized
// static keys. It returns what serverHandshake returned.
func serveWithKeys(t *testing.T, serverKey noise.DHKey, keys headKeys, probe []byte, clients ...noise.DHKey) (*Conn, error) {
	t.Helper()
	cc, sc := net.Pipe()
	go func() {
		_, _ = cc.Write(probe)
		_, _ = io.Copy(io.Discard, cc)
	}()
	conn, err := serverHandshake(sc, serverKey, allowKeys(clients...), NewReplayFilter(), nil, keys, defaultPadPolicy())
	sc.Close()
	cc.Close()
	return conn, err
}

// warnCapture keeps the messages that a deployed log level of Warning keeps: the handler
// reports that level, so Info lines are dropped before they reach it.
type warnCapture struct {
	*logCapture
}

func (c warnCapture) Severity() log.Severity { return log.Severity_Warning }

// captureWarnings records the log messages of Warning and above until the test ends.
func captureWarnings(t *testing.T) *logCapture {
	t.Helper()
	c := &logCapture{}
	log.RegisterHandler(warnCapture{logCapture: c})
	t.Cleanup(func() { log.RegisterHandler(discardLog{}) })
	return c
}

// messageOf returns the message of an error without the component prefix that Xray's
// errors package puts in front of it.
func messageOf(err error) string {
	if err == nil {
		return ""
	}
	return strings.TrimPrefix(err.Error(), "proxy/raywire: ")
}

// lineWith returns the logged lines that contain s.
func lineWith(logs *logCapture, s string) []string {
	var out []string
	for _, line := range logs.lines() {
		if strings.Contains(line, s) {
			out = append(out, line)
		}
	}
	return out
}

// fingerprintHex returns the 8-hex fingerprint of a PSK, as the server logs it.
func fingerprintHex(psk []byte) string {
	return hex.EncodeToString(derivePSKKeys(psk).fingerprint)
}

// minFragment is the shortest run of key bytes that a log line must not carry. Six bytes is
// 48 bits, well above the 4-byte fingerprint that the server logs on purpose.
const minFragment = 6

// pskEncodings returns the forms of a PSK and of its derived keys that must never be logged:
// each whole secret, and every run of at least minFragment bytes of it, in four encodings.
// A partial leak of a key is caught as well as a full one.
func pskEncodings(psk []byte) []string {
	k := derivePSKKeys(psk)
	var out []string
	for _, secret := range [][]byte{psk, k.headKey, k.maskKey} {
		for i := 0; i+minFragment <= len(secret); i++ {
			for j := i + minFragment; j <= len(secret); j++ {
				b := secret[i:j]
				out = append(out,
					string(b),
					hex.EncodeToString(b),
					base64.RawURLEncoding.EncodeToString(b),
					base64.URLEncoding.EncodeToString(b),
					base64.StdEncoding.EncodeToString(b),
				)
			}
		}
	}
	return out
}

// TestPreviousPSKAcceptsBoth is T-H2-1. Heads under psk and under previousPsk both succeed
// while the overlap lasts, and the account of a previousPsk head is marked as such.
func TestPreviousPSKAcceptsBoth(t *testing.T) {
	until := time.Now().Add(48 * time.Hour)
	hk := newHeadKeysFor(t, testPSK, testPrevPSK, until)
	serverKey, clientP, clientQ := newKey(t), newKey(t), newKey(t)
	now := time.Now()

	connP, err := serveWithKeys(t, serverKey, hk, recordMsg1Under(t, clientP, serverKey.Public, now, derivePSKKeys(testPSK)), clientP, clientQ)
	if err != nil {
		t.Fatalf("head under psk refused: %v", err)
	}
	defer connP.Close()
	if connP.viaPrevious {
		t.Fatal("a head under psk is marked as accepted under previousPsk")
	}

	connQ, err := serveWithKeys(t, serverKey, hk, recordMsg1Under(t, clientQ, serverKey.Public, now, derivePSKKeys(testPrevPSK)), clientP, clientQ)
	if err != nil {
		t.Fatalf("head under previousPsk refused: %v", err)
	}
	defer connQ.Close()
	if !connQ.viaPrevious {
		t.Fatal("a head under previousPsk is not marked as accepted under previousPsk")
	}
}

// TestPreviousPSKRejectsThird is T-H2-2. A head under a third PSK gets the tag reason at
// byte 50, as a wrong PSK does.
func TestPreviousPSKRejectsThird(t *testing.T) {
	hk := newHeadKeysFor(t, testPSK, testPrevPSK, time.Now().Add(time.Hour))
	serverKey, client := newKey(t), newKey(t)
	msg := recordMsg1Under(t, client, serverKey.Public, time.Now(), derivePSKKeys(testOtherPSK))

	_, err := serveWithKeys(t, serverKey, hk, msg, client)
	var he *HandshakeError
	if !errors.As(err, &he) || he.Reason != "tag" || !errors.Is(err, ErrTag) {
		t.Fatalf("decision = %v, want reason tag", err)
	}
	if len(he.Consumed) != hsHeadLen {
		t.Fatalf("decided after %d bytes, want %d", len(he.Consumed), hsHeadLen)
	}
}

// TestPreviousPSKNotConfigured is T-H2-3. Without previousPsk, a head under the old PSK
// gets the tag reason, as it does in v3.
func TestPreviousPSKNotConfigured(t *testing.T) {
	hk := newHeadKeysFor(t, testPSK, nil, time.Time{})
	serverKey, client := newKey(t), newKey(t)
	msg := recordMsg1Under(t, client, serverKey.Public, time.Now(), derivePSKKeys(testPrevPSK))

	_, err := serveWithKeys(t, serverKey, hk, msg, client)
	if reason := reasonOf(err); reason != "tag" {
		t.Fatalf("decision = %v, want reason tag", err)
	}
}

// TestPreviousPSKMaskFromVerifyingPSK is T-H2-4. The length mask comes from the PSK that
// verified the tag. A head under previousPsk completes, and a head whose tag verifies under
// psk with a mask from previousPsk is decoded with psk's mask.
func TestPreviousPSKMaskFromVerifyingPSK(t *testing.T) {
	setPreAuthTimeout(t, 300*time.Millisecond)
	until := time.Now().Add(48 * time.Hour)
	hk := newHeadKeysFor(t, testPSK, testPrevPSK, until)
	serverKey, client := newKey(t), newKey(t)

	conn, err := serveWithKeys(t, serverKey, hk, recordMsg1Under(t, client, serverKey.Public, time.Now(), derivePSKKeys(testPrevPSK)), client)
	if err != nil {
		t.Fatalf("msg1 built under previousPsk refused: %v", err)
	}
	conn.Close()

	// The tag is under psk. W1 is masked with previousPsk's mask key. The length that
	// psk's mask gives is out of range, so psk's decoding refuses the head at byte 50.
	// A server that decoded with previousPsk's mask would read an in-range length and wait.
	_, _, R, err := selectEphemeral(wireEphemeral)
	if err != nil {
		t.Fatal(err)
	}
	dh := refDH(t, serverKey.Private, R)
	d := refMaskWord(refMaskKey(testPSK), dh) ^ refMaskWord(refMaskKey(testPrevPSK), dh)
	n1 := 0
	for c := hsMinN1; c <= hsMaxN1 && n1 == 0; c++ {
		if x := c ^ int(d); x < hsMinN1 || x > hsMaxN1 {
			n1 = c
		}
	}
	if n1 == 0 {
		t.Fatal("no in-range length gives an out-of-range decoding under psk")
	}
	W1 := binary.BigEndian.AppendUint16(nil, uint16(n1)^refMaskWord(refMaskKey(testPrevPSK), dh))
	head := rawHead(testPSK, serverKey.Public, R, W1)

	_, err = serveWithKeys(t, serverKey, hk, head, client)
	var he *HandshakeError
	if !errors.As(err, &he) || he.Reason != "length" || len(he.Consumed) != hsHeadLen {
		t.Fatalf("head with a mismatched mask: decision = %v, want reason length after %d bytes", err, hsHeadLen)
	}
}

// TestPreviousPSKSameWork is T-H2-5. Each head runs two head tags, with or without
// previousPsk, and whichever PSK verifies it, or none.
func TestPreviousPSKSameWork(t *testing.T) {
	until := time.Now().Add(48 * time.Hour)
	withPrev := newHeadKeysFor(t, testPSK, testPrevPSK, until)
	withoutPrev := newHeadKeysFor(t, testPSK, nil, time.Time{})
	serverKey, client := newKey(t), newKey(t)
	now := time.Now()

	cases := []struct {
		name  string
		keys  headKeys
		probe []byte
	}{
		{"no previousPsk, head under psk", withoutPrev, recordMsg1Under(t, client, serverKey.Public, now, derivePSKKeys(testPSK))},
		{"previousPsk set, head under psk", withPrev, recordMsg1Under(t, client, serverKey.Public, now, derivePSKKeys(testPSK))},
		{"previousPsk set, head under previousPsk", withPrev, recordMsg1Under(t, client, serverKey.Public, now, derivePSKKeys(testPrevPSK))},
		{"previousPsk set, head under neither", withPrev, recordMsg1Under(t, client, serverKey.Public, now, derivePSKKeys(testOtherPSK))},
		{"no previousPsk, random head", withoutPrev, randomHead(t, hsHeadLen)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := countSteps(t)
			conn, _ := serveWithKeys(t, serverKey, tc.keys, tc.probe, client)
			if conn != nil {
				conn.Close()
			}
			if c.tag != 2 {
				t.Fatalf("%d head tags for one head, want 2", c.tag)
			}
		})
	}
}

// TestPreviousPSKCounterOnSuccessOnly is T-H2-6. A previousPsk head that fails authorize is
// not counted. One that succeeds is counted once, and its account is in the window's lines.
func TestPreviousPSKCounterOnSuccessOnly(t *testing.T) {
	tlsdrainSetWindow(t, time.Second)
	logs := captureLogs(t)
	decoy := startBannerDecoy(t)
	clientP, clientQ, stranger := newKey(t), newKey(t), newKey(t)
	srv := newProbeServer(t, xnet.DestinationFromAddr(decoy), clientQ)
	srv.keys = newHeadKeysFor(t, testPSK, testPrevPSK, time.Now().Add(48*time.Hour))
	srv.clients[string(clientQ.Public)] = &Account{PublicKey: clientQ.Public, Email: "bob"}

	refused := recordMsg1Under(t, stranger, srv.privateKey.Public, time.Now(), derivePSKKeys(testPrevPSK))
	o := probeViaServer(t, srv, refused)
	if reason := reasonOf(o.serverErr); reason != "unauthorized" {
		t.Fatalf("stranger under previousPsk = %v, want reason unauthorized", o.serverErr)
	}
	srv.headFails.mu.Lock()
	counted := srv.headFails.prev
	srv.headFails.mu.Unlock()
	if counted != 0 {
		t.Fatalf("a refused previousPsk head was counted %d times", counted)
	}

	accepted := recordMsg1Under(t, clientQ, srv.privateKey.Public, time.Now(), derivePSKKeys(testPrevPSK))
	acceptFirst(t, srv, accepted)
	srv.headFails.mu.Lock()
	counted = srv.headFails.prev
	srv.headFails.mu.Unlock()
	if counted != 1 {
		t.Fatalf("an accepted previousPsk head was counted %d times, want 1", counted)
	}
	// A success under psk is not a previousPsk accept, and it is not counted.
	srv.clients[string(clientP.Public)] = &Account{PublicKey: clientP.Public, Email: "alice"}
	acceptFirst(t, srv, recordMsg1Under(t, clientP, srv.privateKey.Public, time.Now(), derivePSKKeys(testPSK)))
	srv.headFails.mu.Lock()
	counted = srv.headFails.prev
	srv.headFails.mu.Unlock()
	if counted != 1 {
		t.Fatalf("a success under psk moved the previousPsk count to %d, want 1", counted)
	}

	if !tlsdrainWaitFor(3*time.Second, func() bool { return len(lineWith(logs, "account bob connected under previousPsk")) == 1 }) {
		t.Fatalf("no per-account line for bob; lines %q", logs.lines())
	}
	if n := len(lineWith(logs, "account key ")); n != 0 {
		t.Fatalf("%d per-account lines for an account that was refused", n)
	}

}

// TestPreviousPSKStartLog is T-H2-7. The start line names the previousPsk fingerprint and
// the inbound fingerprint, and it carries no secret.
func TestPreviousPSKStartLog(t *testing.T) {
	logs := captureWarnings(t)
	cfg := serverConfig(t)
	cfg.Psk = testPSK
	cfg.PreviousPsk = testPrevPSK
	cfg.PreviousPskUntil = time.Now().Add(48 * time.Hour).Unix()
	srv, err := NewServer(coreContext(t), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })

	start := lineWith(logs, "previousPsk set")
	if len(start) != 1 {
		t.Fatalf("%d start lines, want 1: %q", len(start), logs.lines())
	}
	if !strings.Contains(start[0], "fingerprint "+fingerprintHex(testPrevPSK)) {
		t.Fatalf("start line %q does not name the previousPsk fingerprint", start[0])
	}
	if !strings.Contains(start[0], "(inbound psk fingerprint "+fingerprintHex(testPSK)+")") {
		t.Fatalf("start line %q does not name the inbound fingerprint", start[0])
	}
	for _, line := range logs.lines() {
		for _, secret := range append(pskEncodings(testPSK), pskEncodings(testPrevPSK)...) {
			if strings.Contains(line, secret) {
				t.Fatalf("a log line carries key material: %q", line)
			}
		}
	}
}

// TestPreviousPSKValidation is T-H2-8 for the typed path. Each rule of the typed table
// gives its message, and an unset previousPsk is accepted with no error.
func TestPreviousPSKValidation(t *testing.T) {
	now := time.Now()
	zero := make([]byte, pskLen)
	cases := []struct {
		name    string
		prev    []byte
		until   int64
		wantErr string // empty when NewServer must accept
	}{
		{"length 31", bytes.Repeat([]byte{0x44}, 31), now.Add(time.Hour).Unix(), "raywire: previousPsk must be 32 bytes"},
		{"all zero", zero, now.Add(time.Hour).Unix(), "raywire: previousPsk must not be all zero"},
		{"equal to psk", testPSK, now.Add(time.Hour).Unix(), "raywire: previousPsk must differ from psk"},
		{"until zero with previousPsk", testPrevPSK, 0, "raywire: previousPskUntil must be set with previousPsk"},
		{"until set without previousPsk", nil, now.Add(time.Hour).Unix(), "raywire: previousPskUntil is set without previousPsk"},
		{"until 15 days ahead", testPrevPSK, now.Add(15 * 24 * time.Hour).Unix(), "raywire: previousPskUntil is more than 14 days ahead"},
		{"unset, nil", nil, 0, ""},
		{"unset, empty", []byte{}, 0, ""},
		{"set, one day", testPrevPSK, now.Add(24 * time.Hour).Unix(), ""},
		{"set, exactly 14 days", testPrevPSK, now.Add(MaxPreviousPskOverlap).Unix(), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := serverConfig(t)
			cfg.Psk = testPSK
			cfg.PreviousPsk = tc.prev
			cfg.PreviousPskUntil = tc.until
			srv, err := NewServer(coreContext(t), cfg)
			if srv != nil {
				t.Cleanup(func() { srv.Close() })
			}
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("NewServer refused a valid configuration: %v", err)
				}
				return
			}
			if messageOf(err) != tc.wantErr {
				t.Fatalf("NewServer error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

// TestRotationProcedure is T-H2-9, with the steps of the runbook (section 4.6). Start with
// the new PSK and previousPsk set to the old one: both clients succeed. Restart without
// previousPsk: the old client is relayed to the decoy at byte 50 and the new one succeeds.
// The rollback is the same test with the two values swapped.
func TestRotationProcedure(t *testing.T) {
	serverKey, oldClient, newClient := newKey(t), newKey(t), newKey(t)
	decoy := startBannerDecoy(t)
	now := time.Now()
	oldMsg := recordMsg1Under(t, oldClient, serverKey.Public, now, derivePSKKeys(testPrevPSK))
	newMsg := recordMsg1Under(t, newClient, serverKey.Public, now, derivePSKKeys(testPSK))

	t.Run("overlap", func(t *testing.T) {
		hk := newHeadKeysFor(t, testPSK, testPrevPSK, now.Add(48*time.Hour))
		for _, m := range [][]byte{oldMsg, newMsg} {
			conn, err := serveWithKeys(t, serverKey, hk, m, oldClient, newClient)
			if err != nil {
				t.Fatalf("client refused during the overlap: %v", err)
			}
			conn.Close()
		}
	})

	t.Run("restart without previousPsk", func(t *testing.T) {
		srv := newProbeServer(t, xnet.DestinationFromAddr(decoy), oldClient, newClient)
		srv.keys = newHeadKeysFor(t, testPSK, nil, time.Time{})
		o := probeViaServer(t, srv, oldMsg)
		if reason := reasonOf(o.serverErr); reason != "tag" {
			t.Fatalf("old client after the restart = %v, want reason tag", o.serverErr)
		}
		if want := probeDirect(t, decoy, oldMsg); !bytes.Equal(o.got, want) {
			t.Fatalf("old client read %q through raywire, %q direct", o.got, want)
		}
		conn, err := serveWithKeys(t, serverKey, srv.keys, newMsg, oldClient, newClient)
		if err != nil {
			t.Fatalf("new client after the restart refused: %v", err)
		}
		conn.Close()
	})

	t.Run("rollback swaps the values", func(t *testing.T) {
		hk := newHeadKeysFor(t, testPrevPSK, testPSK, now.Add(48*time.Hour))
		for _, m := range [][]byte{oldMsg, newMsg} {
			conn, err := serveWithKeys(t, serverKey, hk, m, oldClient, newClient)
			if err != nil {
				t.Fatalf("client refused after the rollback: %v", err)
			}
			conn.Close()
		}
	})
}

// TestPreviousPSKProtoRoundTrip is T-H2-10. The two new proto fields keep their numbers,
// and they survive a marshal and an unmarshal.
func TestPreviousPSKProtoRoundTrip(t *testing.T) {
	fields := (&ServerConfig{}).ProtoReflect().Descriptor().Fields()
	for name, num := range map[string]protoreflect.FieldNumber{"previous_psk": 7, "previous_psk_until": 8} {
		f := fields.ByName(protoreflect.Name(name))
		if f == nil || f.Number() != num {
			t.Fatalf("field %s is missing or not number %d", name, num)
		}
	}

	in := &ServerConfig{PreviousPsk: testPrevPSK, PreviousPskUntil: 1_800_000_000}
	raw, err := proto.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out ServerConfig
	if err := proto.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.PreviousPsk, testPrevPSK) || out.PreviousPskUntil != 1_800_000_000 {
		t.Fatalf("round trip gave previous_psk %x and until %d", out.PreviousPsk, out.PreviousPskUntil)
	}
}

// TestPreviousPSKExpiry is T-H2-11 at the head level. A head under previousPsk succeeds one
// nanosecond before the expiry, and gets the tag reason at the expiry.
func TestPreviousPSKExpiry(t *testing.T) {
	fixRandomness(t)
	until := testNow.Add(time.Hour)
	hk := newHeadKeysFor(t, testPSK, testPrevPSK, until)
	serverKey, client := newKey(t), newKey(t)

	handshakeClock = func() time.Time { return until.Add(-time.Nanosecond) }
	msg := recordMsg1Under(t, client, serverKey.Public, handshakeClock(), derivePSKKeys(testPrevPSK))
	conn, err := serveWithKeys(t, serverKey, hk, msg, client)
	if err != nil {
		t.Fatalf("head under previousPsk one nanosecond before its expiry refused: %v", err)
	}
	conn.Close()

	handshakeClock = func() time.Time { return until }
	msg = recordMsg1Under(t, client, serverKey.Public, handshakeClock(), derivePSKKeys(testPrevPSK))
	_, err = serveWithKeys(t, serverKey, hk, msg, client)
	if reason := reasonOf(err); reason != "tag" {
		t.Fatalf("head under expired previousPsk = %v, want reason tag", err)
	}
}

// TestPreviousPSKExpiryLogsOnce is T-H2-11, the timer part. The server logs its expiry
// once, when the timer fires, and the head-level expiry takes effect at the same time.
func TestPreviousPSKExpiryLogsOnce(t *testing.T) {
	logs := captureWarnings(t)
	cfg := serverConfig(t)
	cfg.Psk = testPSK
	cfg.PreviousPsk = testPrevPSK
	// The field is whole seconds, so the expiry is one to two seconds away.
	cfg.PreviousPskUntil = time.Now().Add(2 * time.Second).Unix()
	srv, err := NewServer(coreContext(t), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })

	if !tlsdrainWaitFor(6*time.Second, func() bool { return len(lineWith(logs, "previousPsk expired at")) >= 1 }) {
		t.Fatalf("no expiry line; lines %q", logs.lines())
	}
	time.Sleep(300 * time.Millisecond)
	if n := len(lineWith(logs, "previousPsk expired at")); n != 1 {
		t.Fatalf("%d expiry lines, want 1", n)
	}
}

// TestPreviousPSKExpiredAtStart is T-H2-12. A previousPskUntil in the past starts the server
// with previousPsk ignored, logs it, and refuses a head under it with the tag reason.
func TestPreviousPSKExpiredAtStart(t *testing.T) {
	logs := captureWarnings(t)
	cfg := serverConfig(t)
	cfg.Psk = testPSK
	cfg.PreviousPsk = testPrevPSK
	cfg.PreviousPskUntil = time.Now().Add(-time.Hour).Unix()
	srv, err := NewServer(coreContext(t), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })

	if n := len(lineWith(logs, "previousPsk expired at")); n != 1 {
		t.Fatalf("%d expired lines at start, want 1: %q", n, logs.lines())
	}
	if n := len(lineWith(logs, "is ignored")); n != 1 {
		t.Fatalf("the start line does not say that previousPsk is ignored: %q", logs.lines())
	}
	client := newKey(t)
	msg := recordMsg1Under(t, client, srv.privateKey.Public, time.Now(), derivePSKKeys(testPrevPSK))
	_, err = serveWithKeys(t, srv.privateKey, srv.keys, msg, client)
	if reason := reasonOf(err); reason != "tag" {
		t.Fatalf("head under an expired previousPsk = %v, want reason tag", err)
	}
}

// TestNewHeadKeysDerivesRawPSK is T-H2-13. previousPsk is derived from its raw value, the
// derived keys differ from psk's, a set value equal to psk is refused, and an unset one
// keeps a dummy that gates nothing.
func TestNewHeadKeysDerivesRawPSK(t *testing.T) {
	until := time.Now().Add(time.Hour)
	hk, err := newHeadKeys(testPSK, testPrevPSK, until)
	if err != nil {
		t.Fatal(err)
	}
	if !hk.hasPrev || !hk.prevUntil.Equal(until) {
		t.Fatalf("hasPrev %v, prevUntil %v; want true and %v", hk.hasPrev, hk.prevUntil, until)
	}
	if !bytes.Equal(hk.prev.headKey, derivePSKKeys(testPrevPSK).headKey) {
		t.Fatal("previousPsk head key is not derived from the raw previousPsk")
	}
	if bytes.Equal(hk.prev.headKey, hk.cur.headKey) {
		t.Fatal("previousPsk and psk have the same head key")
	}

	if _, err := newHeadKeys(testPSK, testPSK, until); messageOf(err) != "raywire: previousPsk must differ from psk" {
		t.Fatalf("previousPsk equal to psk: error %v", err)
	}

	unset, err := newHeadKeys(testPSK, nil, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if unset.hasPrev || !unset.prevUntil.IsZero() {
		t.Fatalf("unset previousPsk: hasPrev %v, prevUntil %v", unset.hasPrev, unset.prevUntil)
	}
	again, err := newHeadKeys(testPSK, nil, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(unset.prev.headKey, again.prev.headKey) {
		t.Fatal("the dummy previousPsk key is not random")
	}
}

// TestPreviousPSKStrictLogLevel is T-H2-14. At a Warning level, the summary of accepted
// previousPsk handshakes is logged, and a summary with failures only is not.
func TestPreviousPSKStrictLogLevel(t *testing.T) {
	tlsdrainSetWindow(t, time.Second)
	logs := captureWarnings(t)
	decoy := startBannerDecoy(t)
	clientQ := newKey(t)
	srv := newProbeServer(t, xnet.DestinationFromAddr(decoy), clientQ)
	srv.keys = newHeadKeysFor(t, testPSK, testPrevPSK, time.Now().Add(48*time.Hour))

	// The failure and the accepted handshake fall in one window, so one summary holds both.
	tlsdrainFail(t, srv)
	acceptFirst(t, srv, recordMsg1Under(t, clientQ, srv.privateKey.Public, time.Now(), derivePSKKeys(testPrevPSK)))
	if !tlsdrainWaitFor(3*time.Second, func() bool {
		return len(lineWith(logs, "1 handshakes accepted under previousPsk")) == 1
	}) {
		t.Fatalf("no Warning summary for an accepted previousPsk handshake; lines %q", logs.lines())
	}
	if n := len(lineWith(logs, "first messages failed the head check")); n != 1 {
		t.Fatalf("%d summary lines with the failure count, want 1", n)
	}

	// A window with failures only is an Info summary, which this level drops.
	tlsdrainFail(t, srv)
	time.Sleep(3 * headFailWindow)
	if n := len(lineWith(logs, "first messages failed the head check")); n != 1 {
		t.Fatalf("an Info-only failure summary reached a Warning handler (%d lines)", n)
	}
}

// TestPreviousPSKSummaryWithoutFailuresIsWarning is the accept-only case of T-H2-14. A window
// with accepted previousPsk handshakes and no failure has a Warning summary, with no failure
// clause, and the deployed level keeps it. TestPreviousPSKStrictLogLevel covers the window
// that also has failures.
func TestPreviousPSKSummaryWithoutFailuresIsWarning(t *testing.T) {
	tlsdrainSetWindow(t, time.Second)
	logs := captureWarnings(t)
	// NewServer sets the inbound fingerprint that the summary line names.
	cfg := serverConfig(t)
	cfg.Psk = testPSK
	cfg.PreviousPsk = testPrevPSK
	cfg.PreviousPskUntil = time.Now().Add(48 * time.Hour).Unix()
	srv, err := NewServer(coreContext(t), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	clientQ := newKey(t)
	srv.clients[string(clientQ.Public)] = &Account{PublicKey: clientQ.Public, Email: "bob"}

	acceptFirst(t, srv, recordMsg1Under(t, clientQ, srv.privateKey.Public, time.Now(), derivePSKKeys(testPrevPSK)))
	want := "raywire: 1 handshakes accepted under previousPsk in the last minute (inbound psk fingerprint " + fingerprintHex(testPSK) + ")"
	if !tlsdrainWaitFor(3*time.Second, func() bool { return len(lineWith(logs, want)) == 1 }) {
		t.Fatalf("no Warning summary for accepts without failures; lines %q", logs.lines())
	}
	if n := len(lineWith(logs, "first messages failed")); n != 0 {
		t.Fatalf("%d failure clauses in a window with no failure", n)
	}
}

// TestV3ServerConfigUnchanged is T-H2-15. A v3 configuration, with neither previousPsk
// field, starts with the v3 line and nothing about previousPsk.
func TestV3ServerConfigUnchanged(t *testing.T) {
	logs := captureLogs(t)
	srv, err := NewServer(coreContext(t), serverConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })

	want := "raywire: version raywire/3, psk fingerprint " + fingerprintHex(testPSK)
	if n := len(lineWith(logs, want)); n != 1 {
		t.Fatalf("%d v3 start lines, want 1: %q", n, logs.lines())
	}
	for _, line := range logs.lines() {
		if strings.Contains(line, "previousPsk") {
			t.Fatalf("a v3 configuration logs a previousPsk line: %q", line)
		}
	}
	if srv.keys.hasPrev || !srv.keys.prevUntil.IsZero() {
		t.Fatal("a v3 configuration has previousPsk state")
	}
}

// TestPreviousPSKLineTokens is T-H2-16. Every rotation line carries the one token
// previousPsk and the inbound fingerprint, so two inbounds can be told apart.
func TestPreviousPSKLineTokens(t *testing.T) {
	tlsdrainSetWindow(t, 200*time.Millisecond)
	logs := captureWarnings(t)
	cfg := serverConfig(t)
	cfg.Psk = testPSK
	cfg.PreviousPsk = testPrevPSK
	cfg.PreviousPskUntil = time.Now().Add(48 * time.Hour).Unix()
	srv, err := NewServer(coreContext(t), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })

	client := newKey(t)
	srv.clients[string(client.Public)] = &Account{PublicKey: client.Public, Email: "carol"}
	acceptFirst(t, srv, recordMsg1Under(t, client, srv.privateKey.Public, time.Now(), derivePSKKeys(testPrevPSK)))
	if !tlsdrainWaitFor(3*time.Second, func() bool { return len(lineWith(logs, "account carol")) == 1 }) {
		t.Fatalf("no per-account line; lines %q", logs.lines())
	}

	inbound := "(inbound psk fingerprint " + fingerprintHex(testPSK) + ")"
	for _, line := range logs.lines() {
		if !strings.Contains(line, "previousPsk") {
			continue
		}
		if !strings.Contains(line, inbound) {
			t.Fatalf("rotation line %q lacks the inbound fingerprint", line)
		}
	}
}
