package raywire

import (
	"crypto/rand"
	"io"
	"math/big"

	"github.com/xtls/xray-core/common/errors"
)

const (
	// maxHandshakePad is the largest handshake pad a sender may use, and the
	// largest the receiver accepts.
	maxHandshakePad = 512

	// maxFramePad is the largest per-frame pad a sender may use.
	maxFramePad = 1024

	// minBucket and maxBucket bound the frame block size. Zero means off.
	minBucket = 16
	maxBucket = 4096

	// frameHeaderSize is the 3-byte body prefix: type and payload length.
	frameHeaderSize = 3

	// maxFramePayload is the largest payload that fits in a body plaintext.
	maxFramePayload = maxFrameBody - frameHeaderSize
)

var (
	// padRand supplies the pad lengths. Tests replace it to get fixed sizes.
	padRand io.Reader = rand.Reader
)

// padPolicy holds the sender's padding settings. A zero value means no
// padding at all. Use defaultPadPolicy for the configured defaults.
type padPolicy struct {
	// Handshake is the upper bound of the random pad on msg1 and msg2.
	Handshake int
	// Frame is the upper bound of the random pad on each frame.
	Frame int
	// Bucket is the frame block size, or zero to pad by Frame instead.
	Bucket int
}

// defaultPadPolicy is used when the configuration has no padding section.
func defaultPadPolicy() padPolicy {
	return padPolicy{Handshake: 255, Frame: 32, Bucket: 0}
}

// validate reports whether every setting is within its range.
func (p padPolicy) validate() error {
	if p.Handshake < 0 || p.Handshake > maxHandshakePad {
		return errors.New("raywire: padding handshake must be between 0 and ", maxHandshakePad)
	}
	if p.Frame < 0 || p.Frame > maxFramePad {
		return errors.New("raywire: padding frame must be between 0 and ", maxFramePad)
	}
	if p.Bucket != 0 && (p.Bucket < minBucket || p.Bucket > maxBucket) {
		return errors.New("raywire: padding bucket must be 0 or between ", minBucket, " and ", maxBucket)
	}
	return nil
}

// uniformInt returns a uniform value in [0, n]. It uses rejection sampling, so
// there is no modulo bias. A failing random source is fatal, as in crypto/rand.
func uniformInt(n int) int {
	v, err := rand.Int(padRand, big.NewInt(int64(n)+1))
	if err != nil {
		panic("raywire: padding randomness failed: " + err.Error())
	}
	return int(v.Int64())
}

// maxPayload returns the largest payload that one frame carries under this policy.
// In bucket mode the body must be a whole number of buckets that fits the 2-byte
// length, so the payload is cut to the largest such body less the frame prefix. A
// larger payload would round up past the length and be clamped to a body that is
// not a bucket multiple, which is the size that bucket mode hides.
func (p padPolicy) maxPayload() int {
	if p.Bucket > 0 {
		return maxFrameBody/p.Bucket*p.Bucket - frameHeaderSize
	}
	return maxPlaintext
}

// roundUp returns the smallest multiple of block that is at least n.
func roundUp(n, block int) int {
	return (n + block - 1) / block * block
}

// frameBp returns the body plaintext length for a frame with payload length n.
// The result is never below 3 + n. firstHS selects the handshake pad range,
// which the client uses for its first frame, the request header.
func frameBp(n int, pol padPolicy, firstHS bool) int {
	if pol.Bucket > 0 {
		return min(roundUp(frameHeaderSize+n, pol.Bucket), maxFrameBody)
	}
	pad := pol.Frame
	if firstHS {
		pad = pol.Handshake
	}
	return min(frameHeaderSize+n+uniformInt(pad), maxFrameBody)
}
