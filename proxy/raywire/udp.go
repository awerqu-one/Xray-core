package raywire

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

// maxDatagramPayload is the largest payload one datagram can carry. Its length
// is a 2-byte field.
const maxDatagramPayload = 0xFFFF

var (
	errDatagramTooLarge = errors.New("raywire: datagram payload is larger than 65535 bytes")
	errDatagramNoDest   = errors.New("raywire: datagram has no destination")
	errDatagramNetwork  = errors.New("raywire: datagram destination is not UDP")
	errDatagramPort     = errors.New("raywire: datagram destination port is zero")
	errDatagramAddress  = errors.New("raywire: datagram destination address is empty")
)

// A UDP session carries datagrams over the Conn in both directions. Each one is
// a destination block, the same bytes as the request header with network UDP,
// then a 2-byte big-endian payload length, then the payload:
//
//	[1 byte network=2][2 bytes port][1 byte address length][address][2 bytes payload length][payload]
//
// The client sends the destination to reach. The server sends the source the
// reply came from, so the client sees full-cone replies.

// packetWriter writes each buffer as one datagram. The buffer's UDP field is
// the address the datagram carries. A buffer without one is sent to def, the
// session's destination, as Xray does for such buffers in other outbounds.
// A destination that is present but not a valid UDP destination is refused.
type packetWriter struct {
	c   *Conn
	def net.Destination
}

// newPacketWriter returns a buf.Writer that sends datagrams over c. def is the
// destination for a buffer that has no UDP field. A buffer's own destination
// always wins over def. Without a def, a buffer with no destination is refused.
func newPacketWriter(c *Conn, def net.Destination) buf.Writer {
	return &packetWriter{c: c, def: def}
}

// WriteMultiBuffer implements buf.Writer. It takes ownership of mb. It stops at
// the first datagram it cannot send, and datagrams before that one are sent.
func (w *packetWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)

	for _, b := range mb {
		if err := w.writeDatagram(b); err != nil {
			return err
		}
	}
	return nil
}

// writeDatagram sends b as one datagram. The whole datagram is one Conn.Write,
// and Conn.Write holds the write lock for the whole call. So datagrams from
// concurrent writers never interleave, and a datagram is never split by a
// frame from another writer.
func (w *packetWriter) writeDatagram(b *buf.Buffer) error {
	dest := w.def
	if b.UDP != nil {
		dest = *b.UDP
	} else if dest.Address == nil {
		return errDatagramNoDest
	}
	if dest.Network != net.Network_UDP {
		return errDatagramNetwork
	}
	payload := b.Bytes()
	if len(payload) > maxDatagramPayload {
		return errDatagramTooLarge
	}
	block, err := encodeHeader(dest)
	if err != nil {
		return err
	}

	out := make([]byte, 0, len(block)+2+len(payload))
	out = append(out, block...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(payload)))
	out = append(out, payload...)
	_, err = w.c.Write(out)
	return err
}

// packetReader reads datagrams from a Conn. Each datagram is one buffer whose
// UDP field is the address the datagram carries.
type packetReader struct {
	c *Conn

	// err is sticky. After a failed datagram the stream is not at a datagram
	// boundary, so later reads must not try to parse it.
	err error
}

// newPacketReader returns a buf.Reader that reads datagrams from c.
func newPacketReader(c *Conn) buf.Reader {
	return &packetReader{c: c}
}

// ReadMultiBuffer implements buf.Reader. It returns io.EOF after a clean end
// between datagrams. A stream that ends inside a datagram gives
// io.ErrUnexpectedEOF.
func (r *packetReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if r.err != nil {
		return nil, r.err
	}
	mb, err := r.readDatagram()
	if err != nil {
		r.err = err
		return nil, err
	}
	return mb, nil
}

// readDatagram reads the next datagram. Only the first byte can report a clean
// end. A read error after it means the stream ended or failed inside the
// datagram, so it is reported as io.ErrUnexpectedEOF whatever the Conn's cause.
// A malformed header field is reported as its own error. Either way the stream
// is no longer at a datagram boundary, so the cause would not change what the
// caller can do.
func (r *packetReader) readDatagram() (buf.MultiBuffer, error) {
	// decodeHeader is not used. It does not separate a stream error from a
	// malformed block, and a stream error inside a datagram must become
	// io.ErrUnexpectedEOF.
	var head [headerFixedLen]byte
	if _, err := io.ReadFull(r.c, head[:1]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(r.c, head[1:]); err != nil {
		return nil, io.ErrUnexpectedEOF
	}
	if head[0] != networkUDP {
		return nil, errDatagramNetwork
	}
	port := net.Port(binary.BigEndian.Uint16(head[1:3]))
	if port == 0 {
		return nil, errDatagramPort
	}
	if head[3] == 0 {
		return nil, errDatagramAddress
	}
	address := make([]byte, head[3])
	if _, err := io.ReadFull(r.c, address); err != nil {
		return nil, io.ErrUnexpectedEOF
	}
	// As in decodeHeader, an address of only spaces is empty once trimmed, and the
	// datagram would have no destination to reply from.
	addr := net.ParseAddress(string(address))
	if addr.String() == "" {
		return nil, errDatagramAddress
	}

	var lengthBuf [2]byte
	if _, err := io.ReadFull(r.c, lengthBuf[:]); err != nil {
		return nil, io.ErrUnexpectedEOF
	}
	size := int(binary.BigEndian.Uint16(lengthBuf[:]))

	dest := net.UDPDestination(addr, port)
	b := newDatagramBuffer(size)
	b.UDP = &dest
	if _, err := b.ReadFullFrom(r.c, int32(size)); err != nil {
		b.Release()
		return nil, io.ErrUnexpectedEOF
	}
	return buf.MultiBuffer{b}, nil
}

// newDatagramBuffer returns an empty buffer that can hold a payload of size
// bytes. A payload larger than buf.Size gets a buffer of its own size, not a
// chain of buffers. The datagram stays one buffer, so downstream code writes it
// as one packet. Splitting it would turn each piece into a separate packet.
func newDatagramBuffer(size int) *buf.Buffer {
	if size <= buf.Size {
		return buf.New()
	}
	return buf.NewWithSize(int32(size))
}
