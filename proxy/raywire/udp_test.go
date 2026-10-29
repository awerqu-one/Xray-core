package raywire

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	gonet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
)

// datagram is one packet with its address, as it comes out of the stream.
type datagram struct {
	dest    net.Destination
	payload []byte
}

// udpDest returns a UDP destination. address may be an IP or a domain name.
func udpDest(address string, port net.Port) net.Destination {
	return net.UDPDestination(net.ParseAddress(address), port)
}

// sendDatagram writes d through w. The buffer wraps d.payload without a copy.
func sendDatagram(w buf.Writer, d datagram) error {
	b := buf.FromBytes(d.payload)
	b.UDP = &d.dest
	return w.WriteMultiBuffer(buf.MultiBuffer{b})
}

// sendAll writes the datagrams in order and stops at the first error.
func sendAll(w buf.Writer, ds []datagram) error {
	for _, d := range ds {
		if err := sendDatagram(w, d); err != nil {
			return err
		}
	}
	return nil
}

// readDatagram reads one datagram and copies it out, since the buffer is
// released here. Each datagram must come back as exactly one buffer with its
// destination set.
func readDatagram(t *testing.T, r buf.Reader) datagram {
	t.Helper()

	mb, err := r.ReadMultiBuffer()
	if err != nil {
		t.Fatalf("read datagram: %v", err)
	}
	defer buf.ReleaseMulti(mb)
	if len(mb) != 1 {
		t.Fatalf("read %d buffers, want one datagram", len(mb))
	}
	if mb[0].UDP == nil {
		t.Fatal("datagram has no destination")
	}
	return datagram{dest: *mb[0].UDP, payload: append([]byte(nil), mb[0].Bytes()...)}
}

// checkDatagram fails the test unless got has the destination and payload of want.
func checkDatagram(t *testing.T, got, want datagram) {
	t.Helper()

	if got.dest.Network != net.Network_UDP || got.dest.NetAddr() != want.dest.NetAddr() {
		t.Fatalf("destination = %s (network %v), want %s", got.dest.NetAddr(), got.dest.Network, want.dest.NetAddr())
	}
	if !bytes.Equal(got.payload, want.payload) {
		t.Fatalf("payload to %s is %d bytes, want %d bytes with the same content",
			got.dest.NetAddr(), len(got.payload), len(want.payload))
	}
}

func TestDatagramRoundTrip(t *testing.T) {
	client, server := connPair(t)

	// Client to server, one destination per kind of address.
	toServer := []datagram{
		{udpDest("192.0.2.1", 53), []byte("ipv4 query")},
		{udpDest("2001:db8::1", 443), []byte("ipv6 packet")},
		{udpDest("example.com", 853), []byte("domain packet")},
	}
	// Server to client, each from the address it came from.
	toClient := []datagram{
		{udpDest("example.com", 853), []byte("domain reply")},
		{udpDest("2001:db8::1", 443), []byte("ipv6 reply")},
		{udpDest("192.0.2.1", 53), []byte("ipv4 reply")},
	}

	// Both directions run at once. net.Pipe is synchronous, so each write
	// finishes only when the other side reads it.
	errs := make(chan error, 2)
	go func() { errs <- sendAll(newPacketWriter(client, net.Destination{}), toServer) }()
	go func() { errs <- sendAll(newPacketWriter(server, net.Destination{}), toClient) }()

	fromClient := newPacketReader(server)
	for _, want := range toServer {
		checkDatagram(t, readDatagram(t, fromClient), want)
	}
	fromServer := newPacketReader(client)
	for _, want := range toClient {
		checkDatagram(t, readDatagram(t, fromServer), want)
	}
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("send: %v", err)
		}
	}
}

func TestDatagramWireFormat(t *testing.T) {
	client, server := connPair(t)

	// The bytes must match the layout in udp.go, whatever the reader accepts.
	const addr = "192.0.2.1"
	want := []byte{networkUDP, 0x00, 0x35, byte(len(addr))}
	want = append(want, addr...)
	want = append(want, 0x00, 0x02, 'h', 'i')

	errCh := make(chan error, 1)
	go func() {
		errCh <- sendDatagram(newPacketWriter(client, net.Destination{}), datagram{udpDest(addr, 53), []byte("hi")})
	}()

	got := make([]byte, len(want))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("read stream: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("stream bytes = %x, want %x", got, want)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("send: %v", err)
	}
}

func TestEmptyDatagram(t *testing.T) {
	client, server := connPair(t)

	// A zero-length datagram must arrive as its own packet, so the datagram
	// after it is still read as a separate one.
	dest := udpDest("192.0.2.1", 53)
	sent := []datagram{{dest, nil}, {dest, []byte("after")}}

	errCh := make(chan error, 1)
	go func() { errCh <- sendAll(newPacketWriter(client, net.Destination{}), sent) }()

	r := newPacketReader(server)
	for _, want := range sent {
		checkDatagram(t, readDatagram(t, r), want)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("send: %v", err)
	}
}

// TestEmptyDatagramSurvivesCopy is the path client.go and server.go use.
// buf.Copy must hand the length-0 datagram to the pipe, not drop it.
func TestEmptyDatagramSurvivesCopy(t *testing.T) {
	client, server := connPair(t)
	closeIfStuck(t, server)

	dest := udpDest("192.0.2.1", 53)
	sent := []datagram{{dest, nil}, {dest, []byte("after")}}

	errCh := make(chan error, 1)
	go func() {
		err := sendAll(newPacketWriter(client, net.Destination{}), sent)
		if err == nil {
			err = client.CloseWrite()
		}
		errCh <- err
	}()

	pr, pw := pipe.New(pipe.WithoutSizeLimit())
	copyErr := make(chan error, 1)
	go func() {
		err := buf.Copy(newPacketReader(server), pw)
		pw.Close()
		copyErr <- err
	}()

	got := collectDatagrams(t, pr, len(sent))
	for i := range sent {
		checkDatagram(t, got[i], sent[i])
	}
	if err := <-copyErr; err != nil {
		t.Fatalf("copy: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("send: %v", err)
	}
}

func TestUnreadableAddressDropped(t *testing.T) {
	client, server := connPair(t)
	closeIfStuck(t, server)

	good := datagram{udpDest("192.0.2.1", 53), []byte("ok")}
	after := datagram{udpDest("192.0.2.1", 53), []byte("after")}
	// These strings survive encodeHeader and used to be rejected by the reader
	// before the payload length was read, which ended the stream.
	bad := []net.Destination{
		net.UDPDestination(net.DomainAddress(" "), 53),
		net.UDPDestination(net.DomainAddress("\t"), 53),
		net.UDPDestination(net.DomainAddress("[]"), 53),
		net.UDPDestination(net.DomainAddress("[ ]"), 53),
	}

	errCh := make(chan error, 1)
	go func() {
		w := newPacketWriter(client, net.Destination{})
		if err := sendDatagram(w, good); err != nil {
			errCh <- err
			return
		}
		for _, dest := range bad {
			if err := sendDatagram(w, datagram{dest, []byte("nope")}); err != nil {
				errCh <- err
				return
			}
		}
		errCh <- sendDatagram(w, after)
	}()

	r := newPacketReader(server)
	checkDatagram(t, readDatagram(t, r), good)
	checkDatagram(t, readDatagram(t, r), after)
	if err := <-errCh; err != nil {
		t.Fatalf("send: %v", err)
	}
}

func TestSpacedBracketIPv6(t *testing.T) {
	client, server := connPair(t)
	closeIfStuck(t, server)

	const addr = " [2001:db8::1]"
	pkt := []byte{networkUDP, 0x00, 0x35, byte(len(addr))}
	pkt = append(pkt, addr...)
	pkt = append(pkt, 0x00, 0x01, 'q')

	errCh := make(chan error, 1)
	go func() {
		_, err := client.Write(pkt)
		errCh <- err
	}()

	got := readDatagram(t, newPacketReader(server))
	if got.dest.Address == nil || !got.dest.Address.Family().IsIPv6() {
		t.Fatalf("address family = %v, dest = %s; want IPv6", got.dest.Address, got.dest)
	}
	if got.dest.Address.IP().String() != "2001:db8::1" || got.dest.Port != 53 {
		t.Fatalf("dest = %s, want udp:[2001:db8::1]:53", got.dest)
	}
	if !bytes.Equal(got.payload, []byte("q")) {
		t.Fatalf("payload = %q", got.payload)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("write: %v", err)
	}

	// The writer emits the canonical IP, not the spaced domain text.
	client2, server2 := connPair(t)
	closeIfStuck(t, server2)
	raw := net.UDPDestination(net.DomainAddress(addr), 53)
	errCh = make(chan error, 1)
	go func() {
		errCh <- sendDatagram(newPacketWriter(client2, net.Destination{}), datagram{raw, []byte("q")})
	}()
	got = readDatagram(t, newPacketReader(server2))
	if got.dest.Address == nil || !got.dest.Address.Family().IsIPv6() || got.dest.Address.IP().String() != "2001:db8::1" {
		t.Fatalf("written dest = %s, want IPv6 2001:db8::1", got.dest)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("send: %v", err)
	}
}

func TestMaxSizeDatagram(t *testing.T) {
	client, server := connPair(t)

	payload := make([]byte, maxDatagramPayload)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	want := datagram{udpDest("example.com", 4789), payload}

	errCh := make(chan error, 1)
	go func() { errCh <- sendDatagram(newPacketWriter(client, net.Destination{}), want) }()

	checkDatagram(t, readDatagram(t, newPacketReader(server)), want)
	if err := <-errCh; err != nil {
		t.Fatalf("send: %v", err)
	}
}

func TestOversizedDatagramRefused(t *testing.T) {
	client, server := connPair(t)
	w := newPacketWriter(client, net.Destination{})

	// Nothing may reach the stream for a refused datagram. The reader is not
	// running yet, so a stray write would block this test.
	oversized := datagram{udpDest("192.0.2.1", 53), make([]byte, maxDatagramPayload+1)}
	if err := sendDatagram(w, oversized); !errors.Is(err, errDatagramTooLarge) {
		t.Fatalf("oversized write error = %v, want errDatagramTooLarge", err)
	}

	next := datagram{udpDest("192.0.2.1", 53), []byte("next")}
	errCh := make(chan error, 1)
	go func() { errCh <- sendDatagram(w, next) }()

	checkDatagram(t, readDatagram(t, newPacketReader(server)), next)
	if err := <-errCh; err != nil {
		t.Fatalf("send next: %v", err)
	}
}

// sendBare writes payload as one buffer with no destination.
func sendBare(w buf.Writer, payload []byte) error {
	return w.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(payload)})
}

// closeIfStuck closes c after a few seconds. A test that waits for a datagram
// that never arrives then fails at once instead of hanging the package.
func closeIfStuck(t *testing.T, c *Conn) {
	t.Helper()

	timer := time.AfterFunc(5*time.Second, func() { c.Conn.Close() })
	t.Cleanup(func() { timer.Stop() })
}

func TestNilDestinationUsesDefault(t *testing.T) {
	client, server := connPair(t)
	closeIfStuck(t, server)
	def := udpDest("192.0.2.1", 53)
	w := newPacketWriter(client, def)

	// Each buffer without a destination is one datagram to the default.
	payloads := [][]byte{[]byte("reply one"), []byte("reply two")}
	errCh := make(chan error, 1)
	go func() {
		for _, p := range payloads {
			if err := sendBare(w, p); err != nil {
				errCh <- err
				return
			}
		}
		errCh <- nil
	}()

	r := newPacketReader(server)
	for _, p := range payloads {
		checkDatagram(t, readDatagram(t, r), datagram{def, p})
	}
	if err := <-errCh; err != nil {
		t.Fatalf("send: %v", err)
	}
}

func TestNilDestinationDomainDefault(t *testing.T) {
	client, server := connPair(t)
	closeIfStuck(t, server)
	def := udpDest("example.com", 853)

	errCh := make(chan error, 1)
	go func() { errCh <- sendBare(newPacketWriter(client, def), []byte("domain reply")) }()

	checkDatagram(t, readDatagram(t, newPacketReader(server)), datagram{def, []byte("domain reply")})
	if err := <-errCh; err != nil {
		t.Fatalf("send: %v", err)
	}
}

func TestOwnDestinationWinsOverDefault(t *testing.T) {
	client, server := connPair(t)
	closeIfStuck(t, server)
	def := udpDest("example.com", 853)
	own := udpDest("192.0.2.1", 53)
	w := newPacketWriter(client, def)

	// One write holds a buffer without a destination, one with its own, and
	// one more without. Each one goes to its own destination, or to the
	// default when it has none, and in order.
	withOwn := buf.FromBytes([]byte("own reply"))
	withOwn.UDP = &own
	mb := buf.MultiBuffer{buf.FromBytes([]byte("default one")), withOwn, buf.FromBytes([]byte("default two"))}

	errCh := make(chan error, 1)
	go func() { errCh <- w.WriteMultiBuffer(mb) }()

	r := newPacketReader(server)
	for _, want := range []datagram{
		{def, []byte("default one")},
		{own, []byte("own reply")},
		{def, []byte("default two")},
	} {
		checkDatagram(t, readDatagram(t, r), want)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("send: %v", err)
	}
}

func TestNilDestinationWithoutDefault(t *testing.T) {
	client, _ := connPair(t)
	w := newPacketWriter(client, net.Destination{})

	// With no default, a buffer without a destination has no address to send to.
	if err := sendBare(w, []byte("x")); !errors.Is(err, errDatagramNoDest) {
		t.Fatalf("write without destination error = %v, want errDatagramNoDest", err)
	}
}

func TestInvalidDestinationRefused(t *testing.T) {
	// An explicit destination that cannot be encoded is refused. The default is
	// not used in its place.
	t.Run("own port zero", func(t *testing.T) {
		client, server := connPair(t)
		w := newPacketWriter(client, udpDest("192.0.2.1", 53))
		if err := sendDatagram(w, datagram{udpDest("192.0.2.1", 0), []byte("x")}); err == nil {
			t.Fatal("write to port 0 succeeded")
		}
		assertNothingWritten(t, w, server)
	})
	t.Run("own address missing", func(t *testing.T) {
		client, server := connPair(t)
		w := newPacketWriter(client, udpDest("192.0.2.1", 53))
		noAddr := datagram{net.Destination{Network: net.Network_UDP, Port: 53}, []byte("x")}
		if err := sendDatagram(w, noAddr); err == nil {
			t.Fatal("write with no address succeeded")
		}
		assertNothingWritten(t, w, server)
	})
	t.Run("default port zero", func(t *testing.T) {
		client, _ := connPair(t)
		w := newPacketWriter(client, udpDest("192.0.2.1", 0))
		if err := sendBare(w, []byte("x")); err == nil {
			t.Fatal("write to a default on port 0 succeeded")
		}
	})
	t.Run("own network not UDP", func(t *testing.T) {
		client, server := connPair(t)
		w := newPacketWriter(client, udpDest("192.0.2.1", 53))
		tcpDest := net.TCPDestination(net.IPAddress([]byte{192, 0, 2, 1}), 53)
		if err := sendDatagram(w, datagram{tcpDest, []byte("x")}); !errors.Is(err, errDatagramNetwork) {
			t.Fatalf("write to a TCP destination error = %v, want errDatagramNetwork", err)
		}
		assertNothingWritten(t, w, server)
	})
	t.Run("default network not UDP", func(t *testing.T) {
		client, _ := connPair(t)
		tcpDef := net.TCPDestination(net.IPAddress([]byte{192, 0, 2, 1}), 53)
		w := newPacketWriter(client, tcpDef)
		if err := sendBare(w, []byte("x")); !errors.Is(err, errDatagramNetwork) {
			t.Fatalf("write to a TCP default error = %v, want errDatagramNetwork", err)
		}
	})
}

// assertNothingWritten checks that a refused write put no bytes on the stream.
// The next datagram must be the first one the reader sees.
func assertNothingWritten(t *testing.T, w buf.Writer, server *Conn) {
	t.Helper()

	closeIfStuck(t, server)
	next := datagram{udpDest("192.0.2.1", 53), []byte("next")}
	errCh := make(chan error, 1)
	go func() { errCh <- sendDatagram(w, next) }()

	checkDatagram(t, readDatagram(t, newPacketReader(server)), next)
	if err := <-errCh; err != nil {
		t.Fatalf("send next: %v", err)
	}
}

func TestDatagramNetworkMustBeUDP(t *testing.T) {
	client, server := connPair(t)

	// The first four bytes of a TCP header. The reader rejects the network byte
	// before it reads anything more.
	block := []byte{networkTCP, 0x00, 0x35, 9}
	errCh := make(chan error, 1)
	go func() {
		_, err := client.Write(block)
		errCh <- err
	}()

	_, err := newPacketReader(server).ReadMultiBuffer()
	if !errors.Is(err, errDatagramNetwork) {
		t.Fatalf("read error = %v, want errDatagramNetwork", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestTruncatedDatagram(t *testing.T) {
	// The header and length of a 10-byte payload, then 5 bytes of it.
	partial := []byte{networkUDP, 0x00, 0x35, 9}
	partial = append(partial, "192.0.2.1"...)
	partial = append(partial, 0x00, 0x0a, 'h', 'e', 'l', 'l', 'o')

	tests := []struct {
		name string
		// end runs after the partial datagram is written, and ends the stream.
		end func(c *Conn) error
	}{
		{
			name: "stream ends",
			end:  func(c *Conn) error { return c.CloseWrite() },
		},
		{
			name: "connection closes",
			end:  func(c *Conn) error { return c.Conn.Close() },
		},
		{
			// The header alone fails authentication, so no body is sent after it.
			name: "frame fails authentication",
			end: func(c *Conn) error {
				_, err := c.Conn.Write(bytes.Repeat([]byte{0xAB}, frameHdrCipher))
				return err
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, server := connPair(t)

			errCh := make(chan error, 1)
			go func() {
				_, err := client.Write(partial)
				if err == nil {
					err = tt.end(client)
				}
				errCh <- err
			}()

			r := newPacketReader(server)
			_, err := r.ReadMultiBuffer()
			if err != io.ErrUnexpectedEOF {
				t.Fatalf("read error = %v, want io.ErrUnexpectedEOF", err)
			}

			// The stream is no longer at a datagram boundary, so the error sticks.
			if _, again := r.ReadMultiBuffer(); again != err {
				t.Fatalf("second read error = %v, want %v", again, err)
			}
			if err := <-errCh; err != nil {
				t.Fatalf("send: %v", err)
			}
		})
	}
}

func TestCleanEnd(t *testing.T) {
	dest := udpDest("192.0.2.1", 53)
	sent := []datagram{{dest, []byte("one")}, {dest, []byte("two")}}

	t.Run("end of stream after datagrams", func(t *testing.T) {
		client, server := connPair(t)

		errCh := make(chan error, 1)
		go func() {
			err := sendAll(newPacketWriter(client, net.Destination{}), sent)
			if err == nil {
				err = client.CloseWrite()
			}
			errCh <- err
		}()

		r := newPacketReader(server)
		for _, want := range sent {
			checkDatagram(t, readDatagram(t, r), want)
		}
		if _, err := r.ReadMultiBuffer(); err != io.EOF {
			t.Fatalf("read after the last datagram = %v, want io.EOF", err)
		}
		if err := <-errCh; err != nil {
			t.Fatalf("send: %v", err)
		}
	})

	t.Run("end of stream without datagrams", func(t *testing.T) {
		client, server := connPair(t)

		errCh := make(chan error, 1)
		go func() { errCh <- client.CloseWrite() }()

		if _, err := newPacketReader(server).ReadMultiBuffer(); err != io.EOF {
			t.Fatalf("first read = %v, want io.EOF", err)
		}
		if err := <-errCh; err != nil {
			t.Fatalf("close write: %v", err)
		}
	})

	t.Run("connection closes without end of stream", func(t *testing.T) {
		client, server := connPair(t)

		errCh := make(chan error, 1)
		go func() {
			err := sendDatagram(newPacketWriter(client, net.Destination{}), sent[0])
			if err == nil {
				err = client.Conn.Close()
			}
			errCh <- err
		}()

		r := newPacketReader(server)
		checkDatagram(t, readDatagram(t, r), sent[0])
		// The peer never said the stream was done, so this is not a clean end.
		if _, err := r.ReadMultiBuffer(); err != io.ErrUnexpectedEOF {
			t.Fatalf("read after the last datagram = %v, want io.ErrUnexpectedEOF", err)
		}
		if err := <-errCh; err != nil {
			t.Fatalf("send: %v", err)
		}
	})
}

// concurrentPayload returns datagram i of writer. The first two bytes name the
// writer and the index, and the rest follows a pattern that depends on both. A
// payload mixed with another one fails the check on read.
func concurrentPayload(writer, i int) []byte {
	n := 2 + (i*7919+writer*104729)%(maxDatagramPayload-1)
	p := make([]byte, n)
	p[0], p[1] = byte(writer), byte(i)
	for k := 2; k < n; k++ {
		p[k] = byte(writer + i + k)
	}
	return p
}

func TestConcurrentDatagramsDoNotInterleave(t *testing.T) {
	client, server := connPair(t)

	const perWriter = 40
	dests := [2]net.Destination{udpDest("192.0.2.1", 1000), udpDest("192.0.2.1", 1001)}

	// Both writers share one Conn. Their datagrams are large enough to span
	// frames, so a Conn without a write lock would mix frames from the two.
	errCh := make(chan error, len(dests))
	for writer := range dests {
		go func(writer int) {
			w := newPacketWriter(client, net.Destination{})
			for i := 0; i < perWriter; i++ {
				d := datagram{dests[writer], concurrentPayload(writer, i)}
				if err := sendDatagram(w, d); err != nil {
					errCh <- err
					return
				}
			}
			errCh <- nil
		}(writer)
	}

	r := newPacketReader(server)
	nextIndex := make([]int, len(dests))
	for n := 0; n < len(dests)*perWriter; n++ {
		got := readDatagram(t, r)
		if len(got.payload) < 2 || int(got.payload[0]) >= len(dests) {
			t.Fatalf("datagram %d has a bad header", n)
		}
		writer, i := int(got.payload[0]), int(got.payload[1])
		if i != nextIndex[writer] {
			t.Fatalf("writer %d sent datagram %d, want %d", writer, i, nextIndex[writer])
		}
		nextIndex[writer]++
		checkDatagram(t, got, datagram{dests[writer], concurrentPayload(writer, i)})
	}
	for range dests {
		if err := <-errCh; err != nil {
			t.Fatalf("send: %v", err)
		}
	}
}

// collectDatagrams reads from r until it has n datagrams. Each one is copied
// out, since the buffers are released here.
func collectDatagrams(t *testing.T, r buf.Reader, n int) []datagram {
	t.Helper()

	var out []datagram
	for len(out) < n {
		mb, err := r.ReadMultiBuffer()
		if err != nil {
			t.Fatalf("read datagram %d: %v", len(out), err)
		}
		for _, b := range mb {
			if b.UDP == nil {
				t.Fatal("datagram has no destination")
			}
			out = append(out, datagram{dest: *b.UDP, payload: append([]byte(nil), b.Bytes()...)})
		}
		buf.ReleaseMulti(mb)
	}
	if len(out) != n {
		t.Fatalf("read %d datagrams, want %d", len(out), n)
	}
	return out
}

// fakePolicy is the policy.Manager that Process reads its timeouts from. The
// timeouts are long, so none of them fires during a test.
type fakePolicy struct{}

func (fakePolicy) Type() interface{}        { return policy.ManagerType() }
func (fakePolicy) Start() error             { return nil }
func (fakePolicy) Close() error             { return nil }
func (fakePolicy) ForSystem() policy.System { return policy.System{} }

func (fakePolicy) ForLevel(uint32) policy.Session {
	d := time.Minute
	return policy.Session{Timeouts: policy.Timeout{
		Handshake:      d,
		ConnectionIdle: d,
		UplinkOnly:     d,
		DownlinkOnly:   d,
	}}
}

// fakeDispatcher gives the server one link, which stands for the destination.
type fakeDispatcher struct{ link *transport.Link }

func (d fakeDispatcher) Type() interface{} { return routing.DispatcherType() }
func (d fakeDispatcher) Start() error      { return nil }
func (d fakeDispatcher) Close() error      { return nil }

func (d fakeDispatcher) Dispatch(context.Context, net.Destination) (*transport.Link, error) {
	return d.link, nil
}

func (d fakeDispatcher) DispatchLink(context.Context, net.Destination, *transport.Link) error {
	return errors.New("DispatchLink is not used by these tests")
}

// fakeDialer hands the client one end of an in-memory pipe.
type fakeDialer struct{ conn gonet.Conn }

func (d fakeDialer) Dial(context.Context, net.Destination) (stat.Connection, error) {
	return d.conn, nil
}

func (d fakeDialer) DestIpAddress() gonet.IP { return nil }

func (d fakeDialer) SetOutboundGateway(context.Context, *session.Outbound) {}

// udpSession is a client outbound and a server inbound joined by an in-memory
// handshake. The test drives both ends of the upload and download, and the
// destination's input and output.
type udpSession struct {
	upW        *pipe.Writer // the client's upload
	downR      *pipe.Reader // the client's download
	destInR    *pipe.Reader // the destination's input, as the server sends it
	destOutW   *pipe.Writer // the destination's output, as the server receives it
	clientDone chan error
	serverDone chan error
}

// startUDPSession starts a UDP session whose request header names target. The
// target is also the client's outbound destination.
func startUDPSession(t *testing.T, target net.Destination) *udpSession {
	t.Helper()

	clientKey, serverKey := newKey(t), newKey(t)
	cc, sc := gonet.Pipe()
	t.Cleanup(func() { sc.Close() })

	upR, upW := pipe.New(pipe.WithoutSizeLimit())
	downR, downW := pipe.New(pipe.WithoutSizeLimit())
	destInR, destInW := pipe.New(pipe.WithoutSizeLimit())
	destOutR, destOutW := pipe.New(pipe.WithoutSizeLimit())

	// Both ends hold the keys of the test PSK, as a real pair does. Zero keys
	// would make the tags match on both sides, and a regression in the keys would
	// pass unseen.
	client := &Client{
		server:        net.TCPDestination(net.DomainAddress("raywire.test"), 443),
		key:           clientKey,
		serverPublic:  serverKey.Public,
		keys:          testKeys(),
		pad:           defaultPadPolicy(),
		policyManager: fakePolicy{},
	}
	server := &Server{
		privateKey:    serverKey,
		keys:          testHeadKeys(),
		clients:       map[string]*Account{string(clientKey.Public): {PublicKey: clientKey.Public}},
		pad:           defaultPadPolicy(),
		policyManager: fakePolicy{},
		replay:        NewReplayFilter(),
	}
	t.Cleanup(func() { server.Close() })

	// A session that does not start must fail the test and not hang the package. Five
	// seconds after the start, every pipe is closed, so a read that waits for the session
	// returns an error. A passing session ends in milliseconds and stops the timer.
	watchdog := time.AfterFunc(5*time.Second, func() {
		upW.Close()
		downW.Close()
		destInW.Close()
		destOutW.Close()
	})
	t.Cleanup(func() { watchdog.Stop() })

	ctx := session.ContextWithOutbounds(context.Background(),
		[]*session.Outbound{{Target: target}})
	s := &udpSession{
		upW:        upW,
		downR:      downR,
		destInR:    destInR,
		destOutW:   destOutW,
		clientDone: make(chan error, 1),
		serverDone: make(chan error, 1),
	}
	go func() {
		s.clientDone <- client.Process(ctx, &transport.Link{Reader: upR, Writer: downW}, fakeDialer{cc})
	}()
	go func() {
		s.serverDone <- server.Process(context.Background(), net.Network_TCP, sc,
			fakeDispatcher{&transport.Link{Reader: destOutR, Writer: destInW}})
	}()
	return s
}

// endUDPSession ends the upload, then the destination's output. Both Process
// calls must return without an error, and the download must end cleanly.
func endUDPSession(t *testing.T, s *udpSession) {
	t.Helper()

	// The upload ends first. The destination's input then ends, and so does the
	// client's download once the destination's output ends.
	if err := s.upW.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.destInR.ReadMultiBuffer(); err != io.EOF {
		t.Fatalf("destination read after upload end = %v, want io.EOF", err)
	}
	if err := s.destOutW.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.downR.ReadMultiBuffer(); err != io.EOF {
		t.Fatalf("client read after destination end = %v, want io.EOF", err)
	}
	if err := <-s.clientDone; err != nil {
		t.Fatalf("client Process: %v", err)
	}
	if err := <-s.serverDone; err != nil {
		t.Fatalf("server Process: %v", err)
	}
}

// TestUDPSessionThroughProcess runs the client outbound and the server inbound
// over an in-memory handshake. Datagrams must reach the destination with their
// addresses, and the reply must come back with its source address. Ending both
// directions must end both Process calls without an error.
func TestUDPSessionThroughProcess(t *testing.T) {
	s := startUDPSession(t, udpDest("192.0.2.1", 53))

	upload := []datagram{
		{udpDest("192.0.2.1", 53), []byte("query")},
		{udpDest("example.com", 853), []byte("domain query")},
	}
	if err := sendAll(s.upW, upload); err != nil {
		t.Fatalf("upload: %v", err)
	}
	got := collectDatagrams(t, s.destInR, len(upload))
	for i := range upload {
		checkDatagram(t, got[i], upload[i])
	}

	// A reply carries the address it came from.
	reply := datagram{udpDest("example.com", 853), []byte("domain answer")}
	if err := sendDatagram(s.destOutW, reply); err != nil {
		t.Fatalf("reply: %v", err)
	}
	checkDatagram(t, collectDatagrams(t, s.downR, 1)[0], reply)

	endUDPSession(t, s)
}

// TestNilDestinationThroughProcess checks buffers with no destination on both
// sides of a UDP session. An upload with none goes to the session's target. A
// reply with none comes from the session's target, and it must not end the
// session. A reply with its own address still works afterwards.
func TestNilDestinationThroughProcess(t *testing.T) {
	target := udpDest("192.0.2.1", 53)
	s := startUDPSession(t, target)

	// If a buffer is refused, the session ends and nothing else arrives. The
	// watchdog then ends the wait, so the test fails instead of hanging.
	watchdog := time.AfterFunc(10*time.Second, s.downR.Interrupt)
	defer watchdog.Stop()

	if err := sendBare(s.upW, []byte("bare query")); err != nil {
		t.Fatalf("upload: %v", err)
	}
	checkDatagram(t, collectDatagrams(t, s.destInR, 1)[0], datagram{target, []byte("bare query")})

	replies := []string{"first answer", "second answer"}
	for _, p := range replies {
		if err := sendBare(s.destOutW, []byte(p)); err != nil {
			t.Fatalf("reply %q: %v", p, err)
		}
	}
	got := collectDatagrams(t, s.downR, len(replies))
	for i, p := range replies {
		checkDatagram(t, got[i], datagram{target, []byte(p)})
	}

	reply := datagram{udpDest("example.com", 853), []byte("domain answer")}
	if err := sendDatagram(s.destOutW, reply); err != nil {
		t.Fatalf("reply: %v", err)
	}
	checkDatagram(t, collectDatagrams(t, s.downR, 1)[0], reply)

	endUDPSession(t, s)
}
