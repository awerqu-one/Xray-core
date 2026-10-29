package raywire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/flynn/noise"
)

const (
	// tagSize is the ChaCha20-Poly1305 authentication tag length.
	tagSize = 16

	// frameHdrCipher is the encrypted frame header: the body length and its tag.
	// It is the only part of a frame that is read before authentication.
	frameHdrCipher = 2 + tagSize

	// maxFrameBody is the largest body plaintext. The header holds its length in
	// 2 bytes, so the body itself has no further limit.
	maxFrameBody = 0xFFFF

	// maxPlaintext is the largest payload of one data frame. The body prefix,
	// the type and the length, takes frameHeaderSize bytes of the body.
	maxPlaintext = maxFrameBody - frameHeaderSize
)

// Frame types, the first byte of every body plaintext.
const (
	// frameData carries payload bytes.
	frameData byte = 0x00

	// frameEnd marks the end of the sender's stream. It carries no payload.
	frameEnd byte = 0x01
)

var (
	errFrameTooLarge = errors.New("raywire: frame too large")
	errFrameTooShort = errors.New("raywire: frame body is shorter than its prefix")
	errFramePastBody = errors.New("raywire: frame payload runs past the body")
	errEndHasPayload = errors.New("raywire: end-of-stream frame has a payload")
	errFrameAuth     = errors.New("raywire: frame authentication failed")
)

// Conn is an encrypted, authenticated stream. A Write becomes one or more data
// frames, and CloseWrite sends an end-of-stream frame. Read returns plaintext
// in order and io.EOF after the peer's end-of-stream frame. A stream that ends
// without one gives io.ErrUnexpectedEOF. A frame that fails authentication
// makes Read return an error, and the stream should be closed.
type Conn struct {
	net.Conn

	send, recv *noise.CipherState

	// pad sets the random length of each frame this side sends.
	pad padPolicy
	// firstFrameHS is true until the first frame is sent. The client's first
	// frame is the request header, and it takes the handshake pad range.
	firstFrameHS bool

	rmu  sync.Mutex
	rbuf []byte // payload not yet returned by Read
	rerr error  // sticky: io.EOF after end-of-stream, otherwise the first failure
	// rhdr holds the encrypted header of the frame being read. It is a field, so
	// reading a header allocates nothing.
	rhdr [frameHdrCipher]byte

	wmu     sync.Mutex
	wclosed bool // end-of-stream fully sent, or a frame was only partly written
	// wsent is true when the last writeFrameV2 accepted every ciphertext byte.
	// Those bytes must not be sealed again.
	wsent bool

	// peer is the server's account for the client that authenticated. It is nil on
	// the client side.
	peer *Account
	// viaPrevious is true when the handshake's head verified under previousPsk. It is
	// set on the server side only, and it is counted for the rotation summary.
	viaPrevious bool
}

// newConn wraps conn after a handshake. pol sets the random pad on this side's
// frames. firstFrameHS is true on the client.
func newConn(conn net.Conn, send, recv *noise.CipherState, pol padPolicy, firstFrameHS bool) *Conn {
	return &Conn{Conn: conn, send: send, recv: recv, pad: pol, firstFrameHS: firstFrameHS}
}

// Write splits p into data frames of at most maxPayload bytes and sends each
// one. After CloseWrite it returns io.ErrClosedPipe. A frame that is only
// partly written fails the write side, and a later Write sends nothing. A
// Write that sends no byte leaves the cipher where it was, so the same bytes
// can be written again.
func (c *Conn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	if c.wclosed {
		return 0, io.ErrClosedPipe
	}
	written := 0
	for len(p) > 0 {
		n := min(len(p), c.pad.maxPayload())
		err := c.writeFrameV2(frameData, p[:n])
		if !c.wsent {
			if err == nil {
				err = io.ErrShortWrite
			}
			return written, err
		}
		written += n
		p = p[n:]
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

// CloseWrite sends one end-of-stream frame, so the peer's Read returns io.EOF
// after the data already sent. The read side stays open, and the connection
// is not closed. Once that frame has been fully written, later calls return
// nil and send nothing. A call that sends no byte does not latch, so it can
// be retried. A partly written frame does latch: another frame would not
// authenticate.
func (c *Conn) CloseWrite() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	if c.wclosed {
		return nil
	}
	err := c.writeFrameV2(frameEnd, nil)
	if c.wsent {
		c.wclosed = true
	}
	return err
}

// writeFrameV2 seals one frame and sends it with a single Write. The body is
// padded with zeros to the length frameBp chooses, and the padding is
// authenticated with the rest of the body. The caller must hold wmu.
//
// The send cipher advances inside sealFrame, before the transport accepts the
// bytes. A write that accepts none of them restores the nonce and leaves
// firstFrameHS unchanged, so the caller can send the same frame again. A write
// that accepts a prefix latches wclosed: the peer may already hold that prefix,
// and a later frame would not authenticate.
func (c *Conn) writeFrameV2(typ byte, payload []byte) error {
	c.wsent = false
	if len(payload) > c.pad.maxPayload() {
		return errFrameTooLarge
	}
	bp := frameBp(len(payload), c.pad, c.firstFrameHS)
	pt := make([]byte, bp)
	pt[0] = typ
	binary.BigEndian.PutUint16(pt[1:frameHeaderSize], uint16(len(payload)))
	copy(pt[frameHeaderSize:], payload)

	n0 := c.send.Nonce()
	wire, err := sealFrame(c.send, pt)
	if err != nil {
		c.send.SetNonce(n0)
		return err
	}
	nw, err := c.Conn.Write(wire)
	if nw != len(wire) {
		if nw == 0 {
			c.send.SetNonce(n0)
			if err == nil {
				err = io.ErrShortWrite
			}
			return err
		}
		c.firstFrameHS = false
		c.wclosed = true
		if err == nil {
			err = io.ErrShortWrite
		}
		return err
	}
	c.firstFrameHS = false
	c.wsent = true
	return err
}

// sealFrame returns the wire form of a frame whose body plaintext is pt: the
// encrypted length of pt, then pt encrypted. The two seals use consecutive
// nonces, as the receiver expects.
func sealFrame(send *noise.CipherState, pt []byte) ([]byte, error) {
	if len(pt) > maxFrameBody {
		return nil, errFrameTooLarge
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(pt)))
	wire, err := send.Encrypt(make([]byte, 0, frameHdrCipher+len(pt)+tagSize), nil, hdr[:])
	if err != nil {
		return nil, err
	}
	return send.Encrypt(wire, nil, pt)
}

// Read returns decrypted payload in order. It returns io.EOF after the peer's
// end-of-stream frame, and io.ErrUnexpectedEOF if the stream ends before one.
// Any other error is returned again on every later call.
func (c *Conn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()

	if len(p) == 0 {
		return 0, nil
	}
	// A new frame is read only after rbuf is empty, so data sent before the
	// end-of-stream frame is returned before io.EOF.
	for len(c.rbuf) == 0 {
		if c.rerr != nil {
			return 0, c.rerr
		}
		c.rbuf, c.rerr = c.recvFrame()
	}
	n := copy(p, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}

// recvFrame reads one frame and applies the body rules. It returns the payload
// of a data frame, which may be empty, and io.EOF for an end-of-stream frame.
// The caller must hold rmu.
func (c *Conn) recvFrame() ([]byte, error) {
	pt, err := c.readFrameV2()
	if err != nil {
		return nil, err
	}
	// readFrameV2 guarantees that pt holds the 3-byte prefix.
	typ := pt[0]
	n := int(binary.BigEndian.Uint16(pt[1:frameHeaderSize]))
	if frameHeaderSize+n > len(pt) {
		return nil, errFramePastBody
	}
	switch typ {
	case frameData:
		return pt[frameHeaderSize : frameHeaderSize+n], nil
	case frameEnd:
		if n != 0 {
			return nil, errEndHasPayload
		}
		return nil, io.EOF
	default:
		return nil, fmt.Errorf("raywire: unknown frame type 0x%02x", typ)
	}
}

// readFrameV2 reads one frame and returns its authenticated body plaintext. The
// header is authenticated before the body is allocated, so a bad header costs
// frameHdrCipher bytes of reads and no body buffer. The caller must hold rmu.
func (c *Conn) readFrameV2() ([]byte, error) {
	if _, err := io.ReadFull(c.Conn, c.rhdr[:]); err != nil {
		return nil, frameReadErr(err)
	}
	hdr, err := c.recv.Decrypt(nil, nil, c.rhdr[:])
	if err != nil {
		return nil, errFrameAuth
	}
	bp := int(binary.BigEndian.Uint16(hdr))
	if bp < frameHeaderSize {
		return nil, errFrameTooShort
	}

	body := make([]byte, bp+tagSize)
	if _, err := io.ReadFull(c.Conn, body); err != nil {
		return nil, frameReadErr(err)
	}
	// Decrypting in place reuses body, so the plaintext needs no second buffer.
	pt, err := c.recv.Decrypt(body[:0], nil, body)
	if err != nil {
		return nil, errFrameAuth
	}
	return pt, nil
}

// frameReadErr maps a read that ends inside a frame, or at a frame boundary with
// no end-of-stream frame before it, to io.ErrUnexpectedEOF. Other errors pass
// through unchanged.
func frameReadErr(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}
