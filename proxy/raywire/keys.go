package raywire

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"time"

	"github.com/flynn/noise"
	"github.com/xtls/xray-core/common/errors"
	"golang.org/x/crypto/curve25519"
)

// keyFromPrivate derives the X25519 key pair for a 32-byte private key.
func keyFromPrivate(private []byte) (noise.DHKey, error) {
	if len(private) != 32 {
		return noise.DHKey{}, errors.New("raywire: private key must be 32 bytes")
	}
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		return noise.DHKey{}, errors.New("raywire: failed to derive public key").Base(err)
	}
	return noise.DHKey{Private: append([]byte(nil), private...), Public: public}, nil
}

// pskKeys are the values that the pre-shared key gives. A Client or Server keeps
// these and not the PSK, so the PSK is needed only to build them.
type pskKeys struct {
	// headKey keys the head tag T.
	headKey []byte
	// maskKey keys the length mask, together with the DH secret.
	maskKey []byte
	// fingerprint identifies the PSK to the operator. It is the only PSK-derived
	// value that may be logged or shown.
	fingerprint []byte
}

// headKeys holds the PSK-derived keys that the server accepts for a head. A head is
// accepted under cur, and under prev while prev is live. The mask key and the tag key
// that the server uses come from the same PSK, the one that verified the tag.
type headKeys struct {
	cur pskKeys
	// prev is derived from previousPsk when hasPrev. Otherwise it is derived from
	// 32 random bytes. The dummy costs the same work per head, and it is never
	// used for a decision, because hasPrev gates it.
	prev      pskKeys
	hasPrev   bool
	prevUntil time.Time // previousPsk is accepted while now is before prevUntil
}

// serverPreviousPskNames spell the server config fields in the messages of
// ValidatePreviousPsk.
var serverPreviousPskNames = PreviousPskNames{PSK: "psk", PreviousPSK: "previousPsk", Until: "previousPskUntil"}

// newHeadKeys derives the head keys of psk and, when previousPsk is set, of previousPsk.
// previousPsk is the raw 32-byte value, or nil or empty when it is not configured. It
// is checked by ValidatePreviousPsk before any key is derived, so that no caller can
// pass keys derived from the wrong value. previousPskUntil is the zero time when it is
// not configured.
func newHeadKeys(psk, previousPsk []byte, previousPskUntil time.Time) (headKeys, error) {
	if err := ValidatePreviousPsk(psk, previousPsk, previousPskUntil, handshakeClock(), serverPreviousPskNames); err != nil {
		return headKeys{}, err
	}
	cur := derivePSKKeys(psk)
	if len(previousPsk) == 0 {
		var r [pskLen]byte
		if _, err := io.ReadFull(rand.Reader, r[:]); err != nil {
			return headKeys{}, err
		}
		return headKeys{cur: cur, prev: derivePSKKeys(r[:])}, nil
	}
	return headKeys{cur: cur, prev: derivePSKKeys(previousPsk), hasPrev: true, prevUntil: previousPskUntil}, nil
}

// pskFromConfig checks a PSK from a typed config and returns a copy of it.
func pskFromConfig(b []byte) ([]byte, error) {
	return pskFromConfigNamed(b, "psk")
}

// pskFromConfigNamed checks a PSK value and returns a copy of it. name is the config
// field, so that the message names the field that is wrong.
func pskFromConfigNamed(b []byte, name string) ([]byte, error) {
	if len(b) != pskLen {
		return nil, errors.New("raywire: " + name + " must be 32 bytes")
	}
	allZero := true
	for _, c := range b {
		if c != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return nil, errors.New("raywire: " + name + " must not be all zero")
	}
	return append([]byte(nil), b...), nil
}

// derivePSKKeys derives the keys of the PSK. The PSK keys only the extraction,
// and each key below comes from its output, so every MAC has its own key.
func derivePSKKeys(psk []byte) pskKeys {
	prk := hmacSHA256(psk, []byte(prkLabel))
	return pskKeys{
		headKey:     hmacSHA256(prk, []byte(headKeyLabel)),
		maskKey:     hmacSHA256(prk, []byte(maskKeyLabel)),
		fingerprint: hmacSHA256(prk, []byte(fingerprintLabel))[:4],
	}
}

// hmacSHA256 returns HMAC-SHA256 of msg under key.
func hmacSHA256(key, msg []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	return mac.Sum(nil)
}
