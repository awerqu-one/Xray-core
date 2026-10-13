package raywire

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"google.golang.org/protobuf/proto"
)

// TestNewServerRefusesBadPSK checks the typed path of the PSK rules for an inbound.
func TestNewServerRefusesBadPSK(t *testing.T) {
	ctx := coreContext(t)
	for _, tc := range []struct {
		name    string
		psk     []byte
		wantErr string
	}{
		{"missing", nil, "raywire: psk must be 32 bytes"},
		{"31 bytes", make([]byte, 31), "raywire: psk must be 32 bytes"},
		{"33 bytes", make([]byte, 33), "raywire: psk must be 32 bytes"},
		{"all zero", make([]byte, 32), "raywire: psk must not be all zero"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := serverConfig(t)
			config.Psk = tc.psk
			_, err := NewServer(ctx, config)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("NewServer error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
	if _, err := NewServer(ctx, serverConfig(t)); err != nil {
		t.Fatalf("NewServer with a valid psk: %v", err)
	}
}

// TestNewClientRefusesBadPSK checks the typed path of the PSK rules for an outbound.
func TestNewClientRefusesBadPSK(t *testing.T) {
	ctx := coreContext(t)
	for _, tc := range []struct {
		name    string
		psk     []byte
		wantErr string
	}{
		{"missing", nil, "raywire: psk must be 32 bytes"},
		{"31 bytes", make([]byte, 31), "raywire: psk must be 32 bytes"},
		{"33 bytes", make([]byte, 33), "raywire: psk must be 32 bytes"},
		{"all zero", make([]byte, 32), "raywire: psk must not be all zero"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := clientConfig(t)
			config.Psk = tc.psk
			_, err := NewClient(ctx, config)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("NewClient error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

// TestPSKProtoRoundTrip checks that psk is field 6 of both configurations and that it
// survives a marshal and an unmarshal.
func TestPSKProtoRoundTrip(t *testing.T) {
	server := &ServerConfig{Psk: testPSK}
	client := &ClientConfig{Psk: testPSK}
	for _, m := range []proto.Message{server, client} {
		fd := m.ProtoReflect().Descriptor().Fields().ByName("psk")
		if fd == nil || fd.Number() != 6 {
			t.Fatalf("%T: psk field is %v, want field number 6", m, fd)
		}
	}

	b, err := proto.Marshal(server)
	if err != nil {
		t.Fatal(err)
	}
	var server2 ServerConfig
	if err := proto.Unmarshal(b, &server2); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(server2.Psk, testPSK) {
		t.Fatalf("server psk after a round trip = %x", server2.Psk)
	}

	b, err = proto.Marshal(client)
	if err != nil {
		t.Fatal(err)
	}
	var client2 ClientConfig
	if err := proto.Unmarshal(b, &client2); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(client2.Psk, testPSK) {
		t.Fatalf("client psk after a round trip = %x", client2.Psk)
	}
}

// TestPayloadBelowMinimumIsLength pins a boundary of the length rule. A remainder
// under 72 bytes is refused as a length, so a payload shorter than the 8-byte timestamp
// cannot reach the payload reason: every accepted remainder carries at least 8 bytes.
func TestPayloadBelowMinimumIsLength(t *testing.T) {
	serverKey, clientKey := newKey(t), newKey(t)
	msg := craftMsg1(t, clientKey, serverKey.Public, prologue, testPSK, make([]byte, timestampSize-1))
	if len(msg) != hsHeadLen+hsMinN1-1 {
		t.Fatalf("msg1 is %d bytes, want %d", len(msg), hsHeadLen+hsMinN1-1)
	}
	allowAll := func([]byte) bool { return true }
	he, sc := decide(t, serverKey, allowAll, NewReplayFilter(), sendThenSentinel(msg[:hsHeadLen]))
	if he.Reason != "length" || len(he.Consumed) != hsHeadLen {
		t.Fatalf("reason %q with %d bytes, want length with %d", he.Reason, len(he.Consumed), hsHeadLen)
	}
	expectSentinel(t, sc)
}

// TestWrongPSKRelaysAtByte50 checks a client that holds another PSK. The server decides
// on the tag at byte 50, and the client gets no msg2.
func TestWrongPSKRelaysAtByte50(t *testing.T) {
	clientKey, serverKey := newKey(t), newKey(t)
	wrong := derivePSKKeys(bytes.Repeat([]byte{0x44}, pskLen))
	cc, sc := net.Pipe()
	_, _, cerr, serr := runHandshakeWith(t, cc, sc, clientKey, serverKey.Public, serverKey, wrong, testHeadKeys(),
		defaultPadPolicy(), defaultPadPolicy())
	if cerr == nil {
		t.Fatal("client finished the handshake with another PSK")
	}
	var he *HandshakeError
	if !errors.As(serr, &he) {
		t.Fatalf("server error = %v, want a *HandshakeError", serr)
	}
	if he.Reason != "tag" || !errors.Is(he, ErrTag) || len(he.Consumed) != hsHeadLen {
		t.Fatalf("reason %q err %v with %d bytes, want tag with %d", he.Reason, he.Err, len(he.Consumed), hsHeadLen)
	}
}

// TestV2ClientAgainstV3Server sends a raywire/2 first message to the v3 server. The
// head is 34 bytes of v2 and then the start of the remainder, so the tag at byte 50
// fails and the server decides at 50 bytes.
func TestV2ClientAgainstV3Server(t *testing.T) {
	serverKey, clientKey := newKey(t), newKey(t)
	payload := make([]byte, timestampSize)
	binary.BigEndian.PutUint64(payload, uint64(testNow.UnixNano()))
	v2 := craftV2Msg1(t, clientKey, serverKey.Public, payload)
	if len(v2) != 106 {
		t.Fatalf("v2 msg1 is %d bytes, want 106", len(v2))
	}
	allowAll := func([]byte) bool { return true }
	he, sc := decide(t, serverKey, allowAll, NewReplayFilter(), sendThenSentinel(v2[:hsHeadLen]))
	if he.Reason != "tag" || len(he.Consumed) != hsHeadLen {
		t.Fatalf("reason %q with %d bytes, want tag with %d", he.Reason, len(he.Consumed), hsHeadLen)
	}
	expectSentinel(t, sc)
}

// TestV2ClientReadsDecoyNotMsg2 checks the client half of the v2 rollout (14.5, 15.6). A v2
// client sends its first message and then reads the server's reply where it expects msg2.
// Through the real pre-auth path, that reply must be the decoy's output, here the banner
// the decoy opens with, and never a raywire reply. Decoy bytes carry no key that the v2
// client can check, so it fails. The v2 client code is gone from the repo, so the test checks
// the bytes that such a client would read, not the client itself.
func TestV2ClientReadsDecoyNotMsg2(t *testing.T) {
	serverKey, clientKey := newKey(t), newKey(t)
	payload := make([]byte, timestampSize)
	binary.BigEndian.PutUint64(payload, uint64(testNow.UnixNano()))
	v2 := craftV2Msg1(t, clientKey, serverKey.Public, payload)

	srv := newProbeServer(t, xnet.DestinationFromAddr(startBannerDecoy(t)))
	srv.privateKey = serverKey
	o := probeViaServer(t, srv, v2[:hsHeadLen])
	if reason := reasonOf(o.serverErr); reason != "tag" {
		t.Fatalf("decision = %v, want reason tag", o.serverErr)
	}
	if !bytes.HasPrefix(o.got, []byte(bannerText)) {
		t.Fatalf("the v2 client reads %q where it expects msg2, want the decoy's banner", o.got)
	}
}

// TestPrologueMismatchIsNoise sends a first message whose tag is valid under the PSK,
// but whose Noise prologue is raywire/2. The tag passes, so the server reaches Noise,
// and Noise refuses the message.
func TestPrologueMismatchIsNoise(t *testing.T) {
	serverKey, clientKey := newKey(t), newKey(t)
	payload := make([]byte, timestampSize)
	binary.BigEndian.PutUint64(payload, uint64(testNow.UnixNano()))
	msg := craftMsg1(t, clientKey, serverKey.Public, "raywire/2", testPSK, payload)

	allowAll := func([]byte) bool { return true }
	he, sc := decide(t, serverKey, allowAll, NewReplayFilter(), sendThenSentinel(msg))
	if he.Reason != "noise" || !bytes.Equal(he.Consumed, msg) {
		t.Fatalf("reason %q with %d bytes, want noise with %d", he.Reason, len(he.Consumed), len(msg))
	}
	expectSentinel(t, sc)
}

// TestClientRoundTripWithPSK completes a handshake between a v3 client and a v3 server
// that hold the same PSK, and sends data across it.
func TestClientRoundTripWithPSK(t *testing.T) {
	clientKey, serverKey := newKey(t), newKey(t)
	cc, sc := net.Pipe()
	client, server, cerr, serr := runHandshake(t, cc, sc, clientKey, serverKey.Public, serverKey,
		defaultPadPolicy(), defaultPadPolicy())
	if cerr != nil || serr != nil {
		t.Fatalf("handshake: client=%v server=%v", cerr, serr)
	}
	defer client.Close()
	defer server.Close()

	errCh := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte("ping"))
		errCh <- err
	}()
	got := make([]byte, 4)
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("server read: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("client write: %v", err)
	}
	if string(got) != "ping" {
		t.Fatalf("server got %q, want ping", got)
	}
}

// TestPSKMismatchNotLogged checks that no log line, at any level, carries the PSK in
// any encoding. The startup line may carry the fingerprint, which is the one value
// derived from the PSK that is allowed in logs (4.5, 14.6).
func TestPSKMismatchNotLogged(t *testing.T) {
	logs := captureLogs(t)
	clientKey := newKey(t)
	cfg := serverConfig(t)
	cfg.Fallback = ""
	cfg.AllowSilentClose = true
	cfg.Clients = []*Account{{PublicKey: clientKey.Public}}
	srv, err := NewServer(coreContext(t), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })

	// A client with another PSK. The server refuses it, and logs the reason at debug.
	server, client := tcpPair(t)
	clientDone := make(chan error, 1)
	go func() {
		wrong := derivePSKKeys(bytes.Repeat([]byte{0x44}, pskLen))
		_, err := ClientHandshake(client, clientKey, srv.privateKey.Public, wrong, defaultPadPolicy())
		clientDone <- err
	}()
	if err := srv.Process(context.Background(), xnet.Network_TCP, server, fakeDispatcher{}); err != nil {
		t.Fatalf("Process returned %v for a refused first message, want nil", err)
	}
	select {
	case <-clientDone:
	case <-time.After(5 * time.Second):
		t.Fatal("client did not return")
	}

	secrets := []string{
		string(testPSK),
		hex.EncodeToString(testPSK),
		base64.RawURLEncoding.EncodeToString(testPSK),
		base64.URLEncoding.EncodeToString(testPSK),
		base64.StdEncoding.EncodeToString(testPSK),
	}
	// The derived keys are secrets too. The head key makes valid head tags and the mask
	// key unmasks the length, so neither may appear in full or as an 8-byte prefix. Only
	// the 4-byte fingerprint may be logged (keys.go).
	keys := testKeys()
	for _, k := range [][]byte{keys.headKey, keys.maskKey} {
		for _, b := range [][]byte{k, k[:8]} {
			secrets = append(secrets,
				string(b),
				hex.EncodeToString(b),
				base64.RawURLEncoding.EncodeToString(b),
				base64.StdEncoding.EncodeToString(b),
			)
		}
	}
	lines := logs.lines()
	var sawTag, sawFingerprint bool
	for _, line := range lines {
		for _, s := range secrets {
			if strings.Contains(line, s) {
				t.Fatalf("a log line carries the PSK: %q", line)
			}
		}
		if strings.Contains(line, "tag") {
			sawTag = true
		}
		if strings.Contains(line, "psk fingerprint "+hex.EncodeToString(refFingerprint(testPSK))) {
			sawFingerprint = true
		}
	}
	if !sawTag {
		t.Fatal("the refused first message was not logged, so the check proves nothing")
	}
	if !sawFingerprint {
		t.Fatal("the startup line does not carry the PSK fingerprint")
	}
}

// TestInfoSummaryCountsTagFailures checks the once-a-minute line that counts the failed
// first messages with reasons tag, length and noise (14.6). The window is shortened for
// the test. A window with failures logs one line that counts all three reasons once the
// window ends, even when no later failure arrives. The next isolated failure gets its own
// line, and a window without failures logs nothing.
func TestInfoSummaryCountsTagFailures(t *testing.T) {
	oldWindow := headFailWindow
	headFailWindow = 500 * time.Millisecond
	t.Cleanup(func() { headFailWindow = oldWindow })

	logs := captureLogs(t)
	serverKey := newKey(t)
	srv := newProbeServer(t, xnet.Destination{}) // no decoy: the failures are closed
	srv.privateKey = serverKey
	t.Cleanup(func() { srv.Close() })

	// fail sends one probe and checks that the decision has the wanted reason.
	fail := func(probe []byte, want string) {
		t.Helper()
		o := probeViaServer(t, srv, probe)
		if reason := reasonOf(o.serverErr); reason != want {
			t.Fatalf("decision = %v, want reason %s", o.serverErr, want)
		}
	}
	summaries := func() []string {
		var out []string
		for _, line := range logs.lines() {
			if strings.Contains(line, "first messages failed the head check") {
				out = append(out, line)
			}
		}
		return out
	}
	waitSummaries := func(n int) []string {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for len(summaries()) < n {
			if time.Now().After(deadline) {
				t.Fatalf("%d summary lines, want %d: %q", len(summaries()), n, summaries())
			}
			time.Sleep(5 * time.Millisecond)
		}
		return summaries()
	}

	// Two of each reason, all within one window.
	payload := make([]byte, timestampSize)
	binary.BigEndian.PutUint64(payload, uint64(testNow.UnixNano()))
	noiseMsg := craftMsg1(t, newKey(t), serverKey.Public, "raywire/2", testPSK, payload)
	_, _, R, err := selectEphemeral(wireEphemeral)
	if err != nil {
		t.Fatal(err)
	}
	lengthHead := headWithLength(t, serverKey, testPSK, R, hsMinN1-1)
	for range 2 {
		fail(randomHead(t, hsHeadLen), "tag")
		fail(lengthHead, "length")
		fail(noiseMsg, "noise")
	}
	lines := waitSummaries(1)
	if len(lines) != 1 || !strings.Contains(lines[0], "raywire: 6 first messages") {
		t.Fatalf("summary lines %q, want one line that counts 6 (2 tag, 2 length, 2 noise)", lines)
	}

	// One isolated failure, with no later failure to close its window.
	fail(randomHead(t, hsHeadLen), "tag")
	lines = waitSummaries(2)
	if !strings.Contains(lines[1], "raywire: 1 first messages") {
		t.Fatalf("second summary line %q, want a line that counts 1", lines[1])
	}

	// A quiet window logs nothing.
	time.Sleep(3 * headFailWindow)
	if n := len(summaries()); n != 2 {
		t.Fatalf("%d summary lines after a quiet window, want 2", n)
	}
}
