package raywire

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/flynn/noise"
)

// handshake runs Client and Server over an in-memory pipe. A failure on one
// side closes the pipe, so the other side fails instead of waiting for its
// deadline.
func handshake(
	t *testing.T,
	clientKey noise.DHKey,
	serverPublic []byte,
	serverKey noise.DHKey,
	authorize func([]byte) bool,
) (client, server *Conn, clientErr, serverErr error) {
	t.Helper()

	cc, sc := net.Pipe()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		server, serverErr = ServerHandshake(sc, serverKey, authorize, NewReplayFilter(), nil, testHeadKeys(), defaultPadPolicy())
		if serverErr != nil {
			sc.Close()
		}
	}()

	client, clientErr = ClientHandshake(cc, clientKey, serverPublic, testKeys(), defaultPadPolicy())
	if clientErr != nil {
		cc.Close()
	}
	wg.Wait()
	return client, server, clientErr, serverErr
}

func newKey(t *testing.T) noise.DHKey {
	t.Helper()
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestRoundTrip(t *testing.T) {
	clientKey, serverKey := newKey(t), newKey(t)
	accept := func(pub []byte) bool { return bytes.Equal(pub, clientKey.Public) }

	client, server, cerr, serr := handshake(t, clientKey, serverKey.Public, serverKey, accept)
	if cerr != nil || serr != nil {
		t.Fatalf("handshake: client=%v server=%v", cerr, serr)
	}
	defer client.Close()
	defer server.Close()

	// Larger than one frame, so Write has to split it.
	payload := make([]byte, 3*maxPlaintext+123)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	errCh := make(chan error, 1)
	go func() {
		_, err := client.Write(payload)
		errCh <- err
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("server read: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("client write: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("client-to-server payload mismatch")
	}

	// The other direction checks that the two CipherStates are not swapped.
	go func() {
		_, err := server.Write([]byte("pong"))
		errCh <- err
	}()
	reply := make([]byte, 4)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("server write: %v", err)
	}
	if string(reply) != "pong" {
		t.Fatalf("server-to-client payload = %q, want %q", reply, "pong")
	}
}

func TestWrongServerKeyFails(t *testing.T) {
	clientKey, serverKey, otherKey := newKey(t), newKey(t), newKey(t)

	// The client pins a key the server does not hold.
	_, _, cerr, serr := handshake(t, clientKey, otherKey.Public, serverKey,
		func([]byte) bool { return true })
	if cerr == nil {
		t.Fatal("client accepted a server that does not hold the pinned key")
	}
	if serr == nil {
		t.Fatal("server accepted a handshake addressed to another key")
	}
}

func TestUnauthorizedClientRejected(t *testing.T) {
	clientKey, serverKey := newKey(t), newKey(t)

	_, _, cerr, serr := handshake(t, clientKey, serverKey.Public, serverKey,
		func([]byte) bool { return false })
	if !errors.Is(serr, ErrUnauthorized) {
		t.Fatalf("server error = %v, want ErrUnauthorized", serr)
	}
	if cerr == nil {
		t.Fatal("client finished the handshake although the server rejected it")
	}
}

func TestTamperedFrameRejected(t *testing.T) {
	clientKey, serverKey := newKey(t), newKey(t)

	client, server, cerr, serr := handshake(t, clientKey, serverKey.Public, serverKey,
		func([]byte) bool { return true })
	if cerr != nil || serr != nil {
		t.Fatalf("handshake: client=%v server=%v", cerr, serr)
	}
	defer client.Close()
	defer server.Close()

	// A header that was never sealed under the session keys. The reader fails
	// after the header, so only the header is sent.
	junk := bytes.Repeat([]byte{0xAB}, frameHdrCipher)
	go func() {
		_, _ = client.Conn.Write(junk)
	}()

	buf := make([]byte, 16)
	_, err := server.Read(buf)
	if err == nil {
		t.Fatal("server accepted a frame that failed authentication")
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("server read error = %v, want an authentication failure", err)
	}
}

// recordConn keeps a copy of every byte written to it. It records before the
// write, so a write that never returns still shows up.
type recordConn struct {
	net.Conn
	mu  sync.Mutex
	buf []byte
}

func (c *recordConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.buf = append(c.buf, p...)
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func (c *recordConn) written() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf...)
}

func TestReplayedHandshakeRejected(t *testing.T) {
	clientKey, serverKey := newKey(t), newKey(t)
	accept := func(pub []byte) bool { return bytes.Equal(pub, clientKey.Public) }
	filter := NewReplayFilter()

	// A real handshake, with the client's first message recorded on the way out.
	cc, sc := net.Pipe()
	defer cc.Close()
	defer sc.Close()
	rec := &recordConn{Conn: cc}

	var serverErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, serverErr = ServerHandshake(sc, serverKey, accept, filter, nil, testHeadKeys(), defaultPadPolicy())
	}()
	if _, err := ClientHandshake(rec, clientKey, serverKey.Public, testKeys(), defaultPadPolicy()); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	wg.Wait()
	if serverErr != nil {
		t.Fatalf("server handshake: %v", serverErr)
	}
	recorded := rec.written()
	if len(recorded) == 0 {
		t.Fatal("no first message was recorded")
	}

	// Send the recorded bytes to a second responder that shares the filter.
	// They are authentic and in time, so only the filter can reject them.
	ra, rb := net.Pipe()
	defer ra.Close()
	defer rb.Close()
	replayed := &recordConn{Conn: rb}

	// Drain the responder's side, so a reply that is written shows up in the
	// count below instead of blocking.
	go func() { _, _ = io.Copy(io.Discard, ra) }()
	go func() { _, _ = ra.Write(recorded) }()

	_, err := ServerHandshake(replayed, serverKey, accept, filter, nil, testHeadKeys(), defaultPadPolicy())
	var he *HandshakeError
	if !errors.As(err, &he) || he.Reason != "replay" || !errors.Is(err, ErrReplay) {
		t.Fatalf("replayed handshake error = %v, want a HandshakeError with reason replay", err)
	}
	if !bytes.Equal(he.Consumed, recorded) {
		t.Fatalf("replayed handshake consumed %d bytes, want the %d recorded", len(he.Consumed), len(recorded))
	}
	if n := len(replayed.written()); n != 0 {
		t.Fatalf("server wrote %d bytes in reply to a replayed handshake", n)
	}
}
