package raywire

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// scriptedWrite records ciphertext and fails one Write with a timeout.
// The embedded Conn supplies the net.Conn methods this test does not use.
type scriptedWrite struct {
	net.Conn
	out     bytes.Buffer
	n       int
	failAt  int
	partial int // bytes to accept on the failing write; 0 accepts none
}

func (c *scriptedWrite) Write(p []byte) (int, error) {
	c.n++
	if c.n == c.failAt {
		if c.partial <= 0 {
			return 0, os.ErrDeadlineExceeded
		}
		k := min(len(p), c.partial)
		c.out.Write(p[:k])
		return k, os.ErrDeadlineExceeded
	}
	c.out.Write(p)
	return len(p), nil
}

func TestWriteTimeoutRollsNonceBack(t *testing.T) {
	client, server := connPair(t)
	sink := &scriptedWrite{Conn: client.Conn, failAt: 2}
	client.Conn = sink

	payload := make([]byte, client.pad.maxPayload()+10)
	for i := range payload {
		payload[i] = byte(i)
	}
	n, err := client.Write(payload)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Write = %d, %v; want a timeout", n, err)
	}
	if n != client.pad.maxPayload() {
		t.Fatalf("Write count = %d, want the first frame only (%d)", n, client.pad.maxPayload())
	}
	if client.firstFrameHS {
		t.Fatal("first frame was sent, firstFrameHS still set")
	}

	if _, err := client.Write(payload[n:]); err != nil {
		t.Fatalf("retry Write: %v", err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	serveWire(server, sink.out.Bytes())
	got, err := io.ReadAll(server)
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("server got %d bytes, want %d", len(got), len(payload))
	}
}

func TestZeroWriteKeepsHandshakePad(t *testing.T) {
	client, _ := connPair(t)
	sink := &scriptedWrite{Conn: client.Conn, failAt: 1}
	client.Conn = sink
	if !client.firstFrameHS {
		t.Fatal("client first frame flag is clear")
	}
	n, err := client.Write([]byte("hello"))
	if n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Write = %d, %v; want 0, timeout", n, err)
	}
	if !client.firstFrameHS {
		t.Fatal("zero-byte Write cleared the handshake pad")
	}
	if client.wclosed {
		t.Fatal("zero-byte Write latched the write side")
	}
}

func TestPartialFrameWriteDoesNotSendAnother(t *testing.T) {
	client, _ := connPair(t)
	sink := &scriptedWrite{Conn: client.Conn, failAt: 1, partial: 10}
	client.Conn = sink
	n, err := client.Write([]byte("hello"))
	if n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Write = %d, %v; want 0, timeout", n, err)
	}
	before := sink.out.Len()
	n, err = client.Write([]byte("hello"))
	if n != 0 || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("retry Write = %d, %v; want 0, closed", n, err)
	}
	if sink.out.Len() != before {
		t.Fatalf("retry wrote %d more bytes", sink.out.Len()-before)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite after a partial frame = %v, want nil", err)
	}
	if sink.out.Len() != before {
		t.Fatal("CloseWrite sent a frame after a partial write")
	}
}

func TestCloseWriteTimeoutCanBeRetried(t *testing.T) {
	client, server := connPair(t)
	if err := client.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	err := client.CloseWrite()
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("CloseWrite = %v, want a timeout", err)
	}
	if client.wclosed {
		t.Fatal("CloseWrite latched after sending nothing")
	}
	if _, werr := client.Write([]byte("late")); !errors.Is(werr, os.ErrDeadlineExceeded) {
		t.Fatalf("Write after failed CloseWrite = %v, want the same deadline", werr)
	}
	if err := client.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}

	got := make(chan error, 1)
	go func() {
		b, rerr := io.ReadAll(server)
		if rerr != nil {
			got <- rerr
			return
		}
		if string(b) != "late" {
			got <- errors.New("payload " + string(b))
			return
		}
		got <- nil
	}()
	if _, err := client.Write([]byte("late")); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatalf("second CloseWrite = %v", err)
	}
	if err := <-got; err != nil {
		t.Fatal(err)
	}
}
