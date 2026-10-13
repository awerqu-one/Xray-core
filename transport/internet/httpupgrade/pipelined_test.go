package httpupgrade_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	stdnet "net"
	"strconv"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	. "github.com/xtls/xray-core/transport/internet/httpupgrade"
	"github.com/xtls/xray-core/transport/internet/stat"
)

const pipelineTestTimeout = 5 * time.Second

// pattern returns n deterministic bytes, so a dropped or shifted byte shows up in a comparison.
func pattern(n int, seed byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7) ^ seed
	}
	return b
}

// noPanic turns a panic in f into a test failure instead of aborting the whole test binary.
func noPanic(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic: %v", r)
		}
	}()
	f()
}

// fakeUpgradeServer accepts one client, answers its request with 101 and then reply,
// both in a single write, the way a server that talks right after the upgrade does.
func fakeUpgradeServer(t *testing.T, reply []byte) stdnet.Listener {
	t.Helper()
	ln, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(pipelineTestTimeout))
		br := bufio.NewReader(c)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		resp := "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
		if _, err := c.Write(append([]byte(resp), reply...)); err != nil {
			return
		}
		io.Copy(io.Discard, c) // keep the connection open until the client closes it
	}()
	return ln
}

// Defect 1: the 101 reply and the payload that follows it arrive in one segment.
// Dial used to panic when it drained the read-ahead bytes into an empty buffer.
func TestDialKeepsPayloadSentRightAfter101(t *testing.T) {
	reply := []byte("server payload sent right after the 101 reply, same segment")

	t.Run("dial consumes reply", func(t *testing.T) {
		ln := fakeUpgradeServer(t, reply)
		port := net.Port(ln.Addr().(*stdnet.TCPAddr).Port)
		noPanic(t, func() {
			conn, err := Dial(context.Background(), net.TCPDestination(net.LocalHostIP, port), &internet.MemoryStreamConfig{
				ProtocolName:     "httpupgrade",
				ProtocolSettings: &Config{Path: "httpupgrade"},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetReadDeadline(time.Now().Add(pipelineTestTimeout))
			got := make([]byte, len(reply))
			if _, err := io.ReadFull(conn, got); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, reply) {
				t.Fatalf("got %q, want %q", got, reply)
			}
		})
	})

	t.Run("reply consumed by first read", func(t *testing.T) {
		ln := fakeUpgradeServer(t, reply)
		port := net.Port(ln.Addr().(*stdnet.TCPAddr).Port)
		noPanic(t, func() {
			conn, err := Dial(context.Background(), net.TCPDestination(net.LocalHostIP, port), &internet.MemoryStreamConfig{
				ProtocolName:     "httpupgrade",
				ProtocolSettings: &Config{Path: "httpupgrade", Ed: 1},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetReadDeadline(time.Now().Add(pipelineTestTimeout))
			// small reads: each Read must return at most len(buf) bytes and keep the rest for later
			buf := make([]byte, 3)
			var got []byte
			for len(got) < len(reply) {
				n, err := conn.Read(buf)
				if n > len(buf) {
					t.Fatalf("Read returned %d bytes into a %d-byte buffer", n, len(buf))
				}
				if err != nil {
					t.Fatal(err)
				}
				if n == 0 {
					t.Fatal("Read returned no data and no error")
				}
				got = append(got, buf[:n]...)
			}
			if !bytes.Equal(got, reply) {
				t.Fatalf("got %q, want %q", got, reply)
			}
		})
	})
}

// Defect 2: the client sends payload in the same segment as the upgrade request.
// The server must hand those bytes to the upgraded connection before the socket.
func TestHubKeepsBytesPipelinedWithUpgradeRequest(t *testing.T) {
	port := tcp.PickPort()
	accepted := make(chan stat.Connection, 1)
	listen, err := ListenHTTPUpgrade(context.Background(), net.LocalHostIP, port, &internet.MemoryStreamConfig{
		ProtocolName:     "httpupgrade",
		ProtocolSettings: &Config{Path: "httpupgrade"},
	}, func(conn stat.Connection) {
		accepted <- conn
	})
	common.Must(err)
	defer listen.Close()

	raw, err := stdnet.Dial("tcp", stdnet.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()

	early := []byte("client payload pipelined right after the upgrade request")
	request := "GET /httpupgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
	// one write, so the payload is already read together with the request headers
	if _, err := raw.Write(append([]byte(request), early...)); err != nil {
		t.Fatal(err)
	}

	var conn stat.Connection
	select {
	case conn = <-accepted:
	case <-time.After(pipelineTestTimeout):
		t.Fatal("upgrade was not accepted")
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(pipelineTestTimeout))

	got := make([]byte, len(early))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("pipelined bytes lost: %v", err)
	}
	if !bytes.Equal(got, early) {
		t.Fatalf("got %q, want %q", got, early)
	}

	// bytes sent later must come straight from the socket, without a size cap
	late := pattern(64<<10, 0x5a)
	writeErr := make(chan error, 1)
	go func() {
		_, err := raw.Write(late)
		writeErr <- err
	}()
	got = make([]byte, len(late))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("bytes after the upgrade: %v", err)
	}
	if !bytes.Equal(got, late) {
		t.Fatal("bytes after the upgrade differ")
	}
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}
}

// Both defects in the shape raywire uses: each side sends its handshake at once,
// the server answers right after the 101, and bulk data follows in both directions.
func TestRaywireLikePayloadFlowsBothWays(t *testing.T) {
	port := tcp.PickPort()
	clientHello := pattern(48, 0x11)
	serverMsg := append(pattern(48, 0x22), pattern(64<<10, 0x44)...)
	clientBulk := pattern(64<<10, 0x33)
	serverErr := make(chan error, 1)

	listen, err := ListenHTTPUpgrade(context.Background(), net.LocalHostIP, port, &internet.MemoryStreamConfig{
		ProtocolName:     "httpupgrade",
		ProtocolSettings: &Config{Path: "httpupgrade"},
	}, func(conn stat.Connection) {
		go func() {
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(pipelineTestTimeout))
			if _, err := conn.Write(serverMsg); err != nil {
				serverErr <- err
				return
			}
			hello := make([]byte, len(clientHello))
			if _, err := io.ReadFull(conn, hello); err != nil {
				serverErr <- err
				return
			}
			if !bytes.Equal(hello, clientHello) {
				serverErr <- fmt.Errorf("client hello: got %x", hello)
				return
			}
			bulk := make([]byte, len(clientBulk))
			if _, err := io.ReadFull(conn, bulk); err != nil {
				serverErr <- err
				return
			}
			if !bytes.Equal(bulk, clientBulk) {
				serverErr <- fmt.Errorf("client bulk differs")
				return
			}
			serverErr <- nil
		}()
	})
	common.Must(err)
	defer listen.Close()

	conn, err := Dial(context.Background(), net.TCPDestination(net.LocalHostIP, port), &internet.MemoryStreamConfig{
		ProtocolName:     "httpupgrade",
		ProtocolSettings: &Config{Path: "httpupgrade"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(pipelineTestTimeout))

	if _, err := conn.Write(clientHello); err != nil {
		t.Fatal(err)
	}
	writeErr := make(chan error, 1)
	go func() {
		_, err := conn.Write(clientBulk)
		writeErr <- err
	}()

	got := make([]byte, len(serverMsg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("server payload: %v", err)
	}
	if !bytes.Equal(got, serverMsg) {
		t.Fatal("server payload differs")
	}
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}
