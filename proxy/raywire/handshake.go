// Package raywire is a stream transport for the RayBridge fork. It is registered
// in Xray as the inbound and outbound protocol "raywire".
//
// This is raywire/3. A connection starts with a Noise_IK handshake (X25519,
// ChaCha20-Poly1305, BLAKE2s) under the prologue "raywire/3", so a peer on
// another version fails its first message. The client must know the server's
// static public key and the server's pre-shared key (PSK) in advance. Ephemeral
// keys travel in Elligator2 form, so the handshake bytes are uniform. msg1 is
// 122 + P1 bytes and msg2 is 50 + P2 bytes, with random pads up to 512.
//
// The first 50 bytes of msg1 are a head: the ephemeral key, a masked length word
// W1 and a 16-byte tag T. T is a MAC under a key derived from the PSK, over the
// server's public key, the ephemeral key and W1. The server reads exactly the
// head and checks T before it does any DH, interprets W1 or waits for another
// byte. A head with a bad tag is relayed to the decoy at once, as any other
// invalid first message is. The length word is masked by a key derived from the
// PSK and the DH secret. The server accepts only the client keys its authorize
// callback approves, and it rejects a handshake whose ephemeral key it has
// already accepted. The first message carries the client's clock, so client and
// server clocks must be within 5 minutes of each other.
//
// A connection that fails the handshake is relayed byte for byte to a decoy,
// and the server writes nothing of its own before success. A connection that is
// closed without a relay is drained first, so the prober sees a FIN, not a
// reset. After the handshake each frame has an AEAD-encrypted 18-byte header, so
// no plaintext length is on the wire. The body has a random pad, 0 to 32 bytes
// by default, and an opt-in bucket mode.
//
// A head that the server has accepted within the last 24 hours, or that is still
// in flight, is refused at byte 50 with the decoy's reaction, as a junk head is.
// The check is on the wire form R_e before any DH, and again on the DH output, so
// a variant of a remembered head is refused too (seen.go). The reason is "seen".
// A head is remembered only after its handshake succeeds, so a stranger cannot
// fill the memory. A restart clears it.
//
// The server accepts a head under psk, and during a rotation also under
// previousPsk until its expiry (keys.go). Both tags are always computed, so a head
// that matches neither costs the same as one that matches either.
//
// TCP and UDP are supported. UDP is carried over the stream as length-prefixed
// datagrams, so it is subject to head-of-line blocking.
//
// Per-user stats count a client's traffic under its email. They need "stats": {}
// and policy.levels.0.statsUserUplink and statsUserDownlink set to true. A client
// without an email is attached as an anonymous level-0 user (Xray's mux needs a
// non-nil user), so it has no per-user counter.
//
// Operator requirement: raywire is not a camouflage layer on its own. Deploy it
// inside TLS or REALITY, so the outer layer is the first thing a classifier
// sees. The decoy must answer as that outer layer's identity (SNI, certificate
// and protocol on the port). A mismatch is a tell. Raw TCP without an outer
// layer is a tell as well: the first packet is uniformly random, and a
// classifier that flags random first packets flags it.
//
// On a security: tls inbound over raw TCP, a plain HTTP request or another
// non-TLS first record is relayed to the decoy byte for byte, as on a raw TCP
// inbound (tlsprefix.go). A first record that looks like TLS gets the TLS layer's
// own answer and a close, with no decoy bytes, so that the decoy's second flight
// is not shown. WebSocket, HTTP upgrade, gRPC, XHTTP, MASQUE and header
// camouflage above TLS do not relay (see the operator's transport choice).
//
// Residual risks that raywire/3 does not fix:
//   - Raw-TCP entropy: every byte of the first packet is uniform, and every frame
//     is ciphertext. Only the outer layer hides this.
//   - Silent short probes: a silent probe of 1 to 49 bytes that is not a prefix
//     waits for the 10 s budget, and its relay closes 60 s after its last byte. A
//     TLS decoy shows this band. Closing it needs proactive forwarding, which is
//     out of scope. The probe needs no key.
//   - Head replay (R2): a captured head that the server never accepted, because
//     authorize refused it, its timestamp was out of range or its Noise check
//     failed, is answered with the 10 s stall, and it keeps being answered that way
//     for as long as the server runs. Its tag covers R_e and W1 and has no time.
//     A head accepted within 24 hours and still in memory is answered at byte 50.
//     The memory holds 65536 heads at most. A busy server evicts a head before its
//     24 hours when the memory is full, and a restart clears the memory.
//   - Seen-memory share (R2a): one client holds at most a quarter of the memory
//     (16384 heads). At its share, a new head of the client replaces its own oldest
//     head, so one client cannot push out another. The heads of a client below its
//     share are never evicted by another client's traffic. A client at its share can
//     lose its oldest head to another client's new head when the memory is full. A
//     full memory with no client at its share does not remember a new head, which
//     is then answered as a head that was never accepted (R2).
//   - Copy first: a copy of a head that reaches the server before the original
//     holds the head in flight for up to the 10 s budget, so the original is
//     refused with "seen". A client retries with a new ephemeral key.
//   - PSK-holder oracle (R3): a holder of the PSK learns, for a repeated ephemeral
//     key, whether each length word is in range. Only a head that is neither
//     remembered nor in flight reaches this check. A remembered head and its
//     variants are answered at byte 50 before the length word is read.
//   - Replayed msg1 CPU (R11): a head that was never accepted costs one DH and one
//     Noise run before the replay filter refuses it. A remembered head costs two
//     HMACs and a map lookup. A PSK holder can make a variant of a remembered head,
//     which costs one DH. The per-source caps bound concurrency, not this CPU.
//   - Shared PSK: every client of an inbound holds the same PSK, so a leaked client
//     configuration leaks it. A rotation keeps the old PSK accepted until
//     previousPskUntil (at most 14 days), so a leaked old PSK works until then.
//   - Decoy distance: the decoy dial adds one round trip to a probe, so keep the
//     decoy close to the server.
//   - Traffic analysis: frame and handshake sizes, timing, direction and volume
//     remain visible. Padding does not change timing.
//   - Static key exposure: the server static key is in every client config. It
//     reveals the client's identity only through the recorded msg1, as in v1.
//   - Pre-auth caps: the per-source caps bound concurrency, not rate. An IPv6 source
//     is keyed by its /64, so one /48 can still take the global pools. Host-level
//     rate limits are outside raywire.
//   - Replay cache: each client may hold at most 16384 of the 65536 entries, so
//     one authorized key cannot lock out the others. Four authorized keys that
//     each reach their quota can still fill the cache. It then fails closed,
//     which denies new handshakes from every client for up to 10 minutes.
//   - Head tag: 128 bits. An online forgery needs about 2^128 attempts.
//   - TLS-looking probes on a security: tls inbound get no decoy bytes (above).
//     Recording the bytes costs up to 16 KiB per pending TLS connection.
//   - Drain limits: queued bytes beyond 256 KiB, and bytes that arrive after the
//     drain, still reset the connection. Platforms without the Unix drain close
//     without it.
//   - Version break: every raywire/2 client fails its first message and is treated
//     as a probe. There is no compatibility mode.
//
// Measured costs are in BENCH.txt in this directory.
package raywire

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"slices"
	"time"

	"github.com/flynn/noise"
	"golang.org/x/crypto/curve25519"
)

const (
	// prologue binds the handshake to this protocol version. A peer on another
	// version derives other keys, so its first message fails.
	prologue = "raywire/3"

	// The labels below separate the PSK-derived keys and MACs. Every key except
	// the extraction key is derived from prk, which is the PSK's extraction, so
	// the PSK itself keys one HMAC only.
	prkLabel         = "raywire/3 psk"
	headKeyLabel     = "raywire/3 head key"
	maskKeyLabel     = "raywire/3 w1"
	tagLabel         = "raywire/3 head"
	fingerprintLabel = "raywire/3 fingerprint"

	handshakeTimeout = 10 * time.Second

	// timestampSize is the length of the timestamp that opens msg1: the
	// client's clock in nanoseconds, big-endian.
	timestampSize = 8

	// hsKeyLen is the length of an Elligator wire form, an X25519 scalar and a
	// public point.
	hsKeyLen = 32

	// pskLen is the length of the pre-shared key.
	pskLen = 32

	// headTagLen is the length of the head tag T, a truncated HMAC-SHA256. The
	// tag is checked before any other part of the head is used.
	headTagLen = 16

	// hsStaticLen is enc(S): the static key and its tag.
	hsStaticLen = hsKeyLen + tagSize

	// hsHeadLen is the fixed part of msg1, read before any decision after the
	// first 4 bytes: R_e, the masked length word W1 and the tag T.
	hsHeadLen = hsKeyLen + 2 + headTagLen

	// hsMinN1 is the shortest remainder of msg1: enc(S) and the timestamp with
	// its tag. hsMaxN1 adds the largest pad that the receiver accepts.
	hsMinN1 = hsStaticLen + timestampSize + tagSize
	hsMaxN1 = hsMinN1 + maxHandshakePad

	// hsMaxConsumed is the most a server reads before it decides.
	hsMaxConsumed = hsHeadLen + hsMaxN1

	// hsCountLen is enc(u16be(P2)) in msg2: the pad length and its tag.
	hsCountLen = 2 + tagSize
)

// The probe tables. The server treats a connection that starts with one of
// these as a probe and relays it to the decoy. A client never sends one as its
// first bytes. The tables are part of the wire contract.
const prefixTable2 = "\x16\x03"

var prefixTable4 = []string{
	"GET ", "POST", "HEAD", "PUT ", "OPTI", "DELE", "CONN",
	"TRAC", "PATC", "PRI ", "SSH-", "EHLO", "HELO",
}

var (
	cipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)

	// preAuthTimeout is the server's budget from accept to a successful msg1
	// and msg2. It is a variable so that tests can shorten it.
	preAuthTimeout = 10 * time.Second

	// ephRand supplies the ephemeral keys and the wire-form bits. Tests replace
	// it to fix the handshake.
	ephRand io.Reader = rand.Reader

	// handshakeClock supplies the timestamp and the server's clock for the
	// replay window. Tests replace it.
	handshakeClock = time.Now

	// dhCalls, elligatorCalls and canonCalls count the server's expensive steps.
	// They do nothing in production. Tests replace them to check that a head
	// with a bad tag reaches none of these steps.
	dhCalls        = func() {}
	elligatorCalls = func() {}
	canonCalls     = func() {}

	// headTagCalls counts each headTag, client and server, and noiseCalls counts each
	// Noise read of the server. seenHook runs after a head is admitted in flight (S6a).
	// They do nothing in production, and tests replace them. headTagCalls is called
	// inside headTag, not in serverHandshake, because TestNoKeyWorkBeforeTagAST
	// allows only listed calls before the tag check.
	headTagCalls = func() {}
	noiseCalls   = func() {}
	seenHook     = func() {}

	// ErrUnauthorized means the client authenticated with a static key that
	// the server does not accept.
	ErrUnauthorized = errors.New("raywire: client key is not authorized")

	// ErrReplay means the handshake was already accepted, or its timestamp is
	// more than maxClockSkew away from the server's clock.
	ErrReplay = errors.New("raywire: handshake is a replay or its timestamp is too far from server time")

	// ErrTag means the head tag does not verify. The sender does not hold this
	// server's PSK and public key, or the head was changed on the way.
	ErrTag = errors.New("raywire: head tag is invalid")

	errLowOrderEphemeral = errors.New("raywire: ephemeral key has no prime-order part")
)

// HandshakeError is a server-side failure before the peer is authenticated.
// Consumed holds exactly the bytes read from the connection before the
// decision, so that a relay can send them to the decoy. Reason says which
// check decided. It is for logs only and is never sent to the peer. LastRead is
// when the last byte was read, or when the first read started if none was. A
// relay's idle clock starts there.
type HandshakeError struct {
	Consumed []byte
	Reason   string
	Err      error
	LastRead time.Time
}

func (e *HandshakeError) Error() string {
	if e.Err == nil {
		return "raywire: handshake rejected: " + e.Reason
	}
	return "raywire: handshake rejected: " + e.Reason + ": " + e.Err.Error()
}

// Unwrap returns the underlying error, so that errors.Is finds ErrReplay and
// the other sentinels.
func (e *HandshakeError) Unwrap() error {
	return e.Err
}

// GenerateKey returns a new static X25519 key pair.
func GenerateKey() (noise.DHKey, error) {
	return noise.DH25519.GenerateKeypair(rand.Reader)
}

// ClientHandshake runs the initiator side of the handshake over conn. serverPublic is
// the server's static public key, keys are the PSK-derived keys of the inbound, and
// pol sets the random pad on msg1. On success the returned Conn wraps conn.
func ClientHandshake(conn net.Conn, static noise.DHKey, serverPublic []byte, keys pskKeys, pol padPolicy) (*Conn, error) {
	if err := conn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return nil, err
	}
	defer conn.SetDeadline(time.Time{})

	k, u, R, err := selectEphemeral(wireEphemeral)
	if err != nil {
		return nil, err
	}

	// flynn draws the ephemeral key from rng, and the key is armed just before
	// the one WriteMessage that draws it. Noise then mixes u, not R.
	rng := &scriptedRand{}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cipherSuite,
		Random:        rng,
		Pattern:       noise.HandshakeIK,
		Initiator:     true,
		Prologue:      []byte(prologue),
		StaticKeypair: static,
		PeerStatic:    serverPublic,
	})
	if err != nil {
		return nil, err
	}
	rng.arm(k)

	// The timestamp lets the server reject a captured first message once its
	// clock window has passed.
	p1 := uniformInt(pol.Handshake)
	payload1 := make([]byte, timestampSize+p1)
	binary.BigEndian.PutUint64(payload1, uint64(handshakeClock().UnixNano()))
	out, _, _, err := hs.WriteMessage(nil, payload1)
	if err != nil {
		return nil, err
	}
	// out is u || enc(S) || enc(payload1). Its first 32 bytes must be the point
	// that R encodes, or the wire form would not decode to the key Noise used.
	n1 := len(out) - hsKeyLen
	if !bytes.Equal(out[:hsKeyLen], u) || n1 != hsMinN1+p1 {
		return nil, errors.New("raywire: unexpected first message")
	}

	dh, err := curve25519.X25519(k, serverPublic)
	if err != nil {
		return nil, err
	}
	// W1 hides the length of the remainder under a key from the PSK and the DH
	// secret. T binds the head to this server, to R and to W1, so the server
	// rejects a head it did not expect before it reads W1.
	w1 := binary.BigEndian.AppendUint16(nil, uint16(n1)^lengthMask(keys.maskKey, dh))
	tag := headTag(keys.headKey, serverPublic, R, w1)
	msg1 := make([]byte, 0, hsHeadLen+n1)
	msg1 = append(msg1, R...)
	msg1 = append(msg1, w1...)
	msg1 = append(msg1, tag...)
	msg1 = append(msg1, out[hsKeyLen:]...)
	if _, err := conn.Write(msg1); err != nil {
		return nil, err
	}

	// msg2 is R_s, the sealed pad length and then P2 random bytes. The pad is
	// read only after the length authenticates, and its bytes are discarded.
	var rs [hsKeyLen]byte
	if _, err := io.ReadFull(conn, rs[:]); err != nil {
		return nil, err
	}
	var sealed [hsCountLen]byte
	if _, err := io.ReadFull(conn, sealed[:]); err != nil {
		return nil, err
	}
	// R_s encodes u + T. Noise hashes the ephemeral bytes, and the responder
	// hashed the subgroup point u, so the canonical point is the one to use.
	us := canonicalDecode(rs[:])
	if us == nil {
		return nil, errors.New("raywire: invalid responder ephemeral key")
	}
	payload2, send, recv, err := hs.ReadMessage(nil, append(us, sealed[:]...))
	if err != nil {
		return nil, err
	}
	if len(payload2) != 2 {
		return nil, errors.New("raywire: invalid responder pad length")
	}
	p2 := int(binary.BigEndian.Uint16(payload2))
	if p2 > maxHandshakePad {
		return nil, errors.New("raywire: responder pad is too long")
	}
	if _, err := io.CopyN(io.Discard, conn, int64(p2)); err != nil {
		return nil, err
	}
	return newConn(conn, send, recv, pol, true), nil
}

// ServerHandshake is serverHandshake for a caller that needs no account. authorize
// only decides whether the client's static public key may connect.
func ServerHandshake(conn net.Conn, static noise.DHKey, authorize func(clientPublic []byte) bool, replay *ReplayFilter, seen *seenHeads, keys headKeys, pol padPolicy) (*Conn, error) {
	return serverHandshake(conn, static, func(clientPublic []byte) (*Account, bool) {
		return nil, authorize(clientPublic)
	}, replay, seen, keys, pol)
}

// serverHandshake runs the responder side of the handshake over conn. authorize returns
// the account of a client's static public key and whether that key may connect, and
// replay must be shared by all connections to the same server. seen is the memory of
// remembered and in-flight heads (seen.go), and nil keeps none. keys are the PSK-derived
// keys of the inbound, and pol sets the random pad on msg2. On success the returned Conn
// carries the account that authorize returned.
//
// On failure it returns a *HandshakeError whose Consumed holds every byte read from
// conn before the decision. A rejected client gets no reply from raywire, and the caller
// owns conn on error.
func serverHandshake(conn net.Conn, static noise.DHKey, authorize func(clientPublic []byte) (*Account, bool), replay *ReplayFilter, seen *seenHeads, keys headKeys, pol padPolicy) (*Conn, error) {
	rng := &scriptedRand{}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cipherSuite,
		Random:        rng,
		Pattern:       noise.HandshakeIK,
		Initiator:     false,
		Prologue:      []byte(prologue),
		StaticKeypair: static,
	})
	if err != nil {
		return nil, err
	}

	// One budget covers every read up to a successful msg2. The deadline is
	// cleared on every return path.
	start := time.Now()
	if err := conn.SetDeadline(start.Add(preAuthTimeout)); err != nil {
		return nil, err
	}
	defer conn.SetDeadline(time.Time{})

	// Each read is checked before the next, so a probe is decided at the byte
	// where it can first be told apart. Nothing is read past the decision.
	r := &preAuthReader{conn: conn, last: start}
	if err := r.read(2); err != nil {
		return nil, err
	}
	if string(r.buf[:2]) == prefixTable2 {
		return nil, r.fail("prefix", nil)
	}
	if err := r.read(2); err != nil {
		return nil, err
	}
	if slices.Contains(prefixTable4, string(r.buf[:4])) {
		return nil, r.fail("prefix", nil)
	}
	if err := r.read(hsKeyLen - 4); err != nil {
		return nil, err
	}
	// The rest of the head is read in one go. The tag is checked before W1 is
	// used or any further byte is awaited, so a head without the PSK costs one
	// HMAC and no key work.
	if err := r.read(hsHeadLen - hsKeyLen); err != nil {
		return nil, err
	}
	re := r.buf[:hsKeyLen]
	w1 := r.buf[hsKeyLen : hsKeyLen+2]
	tag := r.buf[hsKeyLen+2 : hsHeadLen]

	// Both candidate tags are computed before either is compared. A head that verifies
	// under psk therefore costs the same as one that verifies under previousPsk, and the
	// same as one that verifies under neither.
	expectCur := headTag(keys.cur.headKey, static.Public, re, w1)
	expectPrev := headTag(keys.prev.headKey, static.Public, re, w1)
	okCur := hmac.Equal(expectCur, tag)
	okPrev := hmac.Equal(expectPrev, tag)
	now := handshakeClock()
	okPrev = okPrev && keys.hasPrev && now.Before(keys.prevUntil)
	if !okCur && !okPrev {
		return nil, r.fail("tag", ErrTag)
	}
	// ks is the PSK that verified the tag. The length mask and the tag come from it.
	ks, viaPrev := keys.cur, false
	if !okCur {
		ks, viaPrev = keys.prev, true
	}

	// A head that is remembered, or still in flight, takes the path of a junk head:
	// it is answered at byte 50, with no DH. Admit makes the head in flight until this
	// function returns, so a copy that arrives meanwhile is answered the same way.
	if !seen.Admit(re, now) {
		return nil, r.fail("seen", ErrReplay)
	}
	defer seen.Release(re)
	seenHook()

	// R_e decodes to u + T, where u is the client's subgroup point. The length
	// DH uses the raw point u + T. A clamped scalar is a multiple of 8, so it
	// kills T, and the DH equals the DH with u. The canonical point is needed only
	// for Noise and the replay key, so it is computed after the length check.
	// That keeps a head with a valid tag to one Elligator map and one X25519
	// before its length is read.
	elligatorCalls()
	up := elligatorDecode(re)
	dhCalls()
	dh, err := curve25519.X25519(static.Private, up)
	if err != nil {
		return nil, r.fail("ephemeral", err)
	}
	// A variant of a remembered head decodes to the same DH output, so it is answered
	// here, before its length word is used.
	if seen.SeenDH(dh, now) {
		return nil, r.fail("seen", ErrReplay)
	}
	n1 := int(binary.BigEndian.Uint16(w1) ^ lengthMask(ks.maskKey, dh))
	if n1 < hsMinN1 || n1 > hsMaxN1 {
		return nil, r.fail("length", nil)
	}
	if err := r.read(n1); err != nil {
		return nil, err
	}

	// The canonical point is nil only for a torsion input, and the DH above has
	// already failed for those. The check is kept so that a nil never reaches
	// Noise or the replay filter.
	canonCalls()
	uc := canonicalPoint(up)
	if uc == nil {
		return nil, r.fail("ephemeral", errLowOrderEphemeral)
	}
	// Noise mixes the canonical point, so the wire form R is replaced here.
	msg := make([]byte, 0, hsKeyLen+n1)
	msg = append(msg, uc...)
	msg = append(msg, r.buf[hsHeadLen:r.n]...)
	noiseCalls()
	payload, _, _, err := hs.ReadMessage(nil, msg)
	if err != nil {
		return nil, r.fail("noise", err)
	}
	// The payload is the remainder less enc(S) and the payload's tag, so it is
	// n1 - hsStaticLen - tagSize bytes long. The length check above admits only
	// n1 >= hsMinN1, and that makes the payload at least timestampSize bytes, so
	// the timestamp read below is always in range.
	account, ok := authorize(hs.PeerStatic())
	if !ok {
		return nil, r.fail("unauthorized", ErrUnauthorized)
	}
	// Only after authorize, so that a stranger cannot fill the filter. The key
	// is the client's identity for the per-client quota.
	ts := time.Unix(0, int64(binary.BigEndian.Uint64(payload[:timestampSize])))
	if !replay.Accept(string(hs.PeerStatic()), uc, ts, handshakeClock()) {
		return nil, r.fail("replay", ErrReplay)
	}
	// The head is remembered only now, after authorize and the replay accept, and before
	// msg2 is written. A head whose msg2 write fails was authenticated, so it stays. The
	// client's key is its identity for the per-client share of the memory (seen.go).
	seen.Remember(re, dh, hs.PeerStatic(), now)

	// The responder's ephemeral key is searched after authorize, so a rejected
	// probe costs no key work.
	k, u, R, err := wireEphemeral()
	if err != nil {
		return nil, err
	}
	rng.arm(k)
	p2 := uniformInt(pol.Handshake)
	msg2, recv, send, err := hs.WriteMessage(nil, binary.BigEndian.AppendUint16(nil, uint16(p2)))
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(msg2[:hsKeyLen], u) {
		return nil, errors.New("raywire: unexpected second message")
	}

	// msg2 is R_s, the sealed count, then P2 random bytes that the client discards.
	reply := make([]byte, hsKeyLen+hsCountLen+p2)
	copy(reply, R)
	copy(reply[hsKeyLen:], msg2[hsKeyLen:])
	if _, err := io.ReadFull(padRand, reply[hsKeyLen+hsCountLen:]); err != nil {
		return nil, err
	}
	// The peer is authenticated by now, so a failed write just closes the connection.
	if _, err := conn.Write(reply); err != nil {
		return nil, err
	}
	rc := newConn(conn, send, recv, pol, false)
	rc.peer = account
	rc.viaPrevious = viaPrev
	return rc, nil
}

// preAuthReader reads the first bytes of a connection and keeps each one, so a
// failure reports exactly what was read.
type preAuthReader struct {
	conn net.Conn
	buf  [hsMaxConsumed]byte
	n    int
	// last is when the most recent byte was read, or when the budget started.
	last time.Time
}

// read fills the next size bytes. A failed read returns the decision with the
// bytes read so far. It reads with Read, not io.ReadFull, so that last is set when
// each chunk arrives. A partial read that ends in a deadline must not move last to
// the deadline, or a relay would start its idle clock too late.
func (r *preAuthReader) read(size int) error {
	start := r.n
	end := r.n + size
	for r.n < end {
		m, err := r.conn.Read(r.buf[r.n:end])
		if m > 0 {
			r.last = time.Now()
			r.n += m
		}
		if r.n == end {
			return nil
		}
		if err != nil {
			if errors.Is(err, io.EOF) && r.n > start {
				err = io.ErrUnexpectedEOF
			}
			return r.fail(readReason(err), err)
		}
	}
	return nil
}

// fail returns a HandshakeError with every byte read so far.
func (r *preAuthReader) fail(reason string, err error) error {
	return &HandshakeError{
		Consumed: append([]byte(nil), r.buf[:r.n]...),
		Reason:   reason,
		Err:      err,
		LastRead: r.last,
	}
}

// readReason names the decision for a failed read.
func readReason(err error) string {
	switch {
	case errors.Is(err, os.ErrDeadlineExceeded):
		return "deadline"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "eof"
	default:
		return "read"
	}
}

// selectEphemeral calls next until the wire form of its key starts with no probe
// prefix, since a client never sends one as its first bytes.
func selectEphemeral(next func() ([]byte, []byte, []byte, error)) ([]byte, []byte, []byte, error) {
	for {
		k, u, R, err := next()
		if err != nil || !(hasPrefix2(R) || hasPrefix4(R)) {
			return k, u, R, err
		}
	}
}

// wireEphemeral returns an X25519 private key k, its public point u and the
// wire form R of u + T for a random torsion point T. The receiver removes T, so
// the subgroup point u is what the handshake uses.
func wireEphemeral() ([]byte, []byte, []byte, error) {
	k, u, r, err := encodableKey(ephRand)
	if err != nil {
		return nil, nil, nil, err
	}
	// The search always returns the first-branch preimage, for which the Jacobi
	// symbol of g(x1) is never -1. Uniform bytes fail that test half the time,
	// so R must be randomized over the four preimages. wireForm does that.
	R := wireForm(r, ephRand)
	if R == nil {
		return nil, nil, nil, errors.New("raywire: failed to encode ephemeral key")
	}
	return k, u, R, nil
}

// hasPrefix2 and hasPrefix4 report whether b starts with a probe table entry.
// Both need at least that many bytes.
func hasPrefix2(b []byte) bool {
	return len(b) >= 2 && string(b[:2]) == prefixTable2
}

func hasPrefix4(b []byte) bool {
	return len(b) >= 4 && slices.Contains(prefixTable4, string(b[:4]))
}

// headTag returns T, the tag over the label, the server's public key, R_e and
// W1, keyed with the PSK-derived head key. Both sides use the server's public
// key, so a head made for another server does not verify.
func headTag(headKey, serverPub, re, w1 []byte) []byte {
	headTagCalls()
	mac := hmac.New(sha256.New, headKey)
	mac.Write([]byte(tagLabel))
	mac.Write(serverPub)
	mac.Write(re)
	mac.Write(w1)
	return mac.Sum(nil)[:headTagLen]
}

// lengthMask returns the 16-bit mask of the length word. It is keyed by the
// PSK-derived mask key and by the DH secret, so a holder of the server's public
// key alone cannot compute it.
func lengthMask(maskKey, dh []byte) uint16 {
	mac := hmac.New(sha256.New, maskKey)
	mac.Write(dh)
	return binary.BigEndian.Uint16(mac.Sum(nil))
}

// scriptedRand gives flynn the one 32-byte draw for an ephemeral key, and
// nothing else. A draw with nothing armed is an error, so an unexpected use
// fails loudly.
type scriptedRand struct {
	next []byte
}

var errUnexpectedDraw = errors.New("raywire: unexpected randomness draw during handshake")

// arm sets the bytes that the next draw returns.
func (r *scriptedRand) arm(k []byte) {
	r.next = append([]byte(nil), k...)
}

// Read returns the armed bytes once. It needs the whole armed length in one
// call, which is how flynn reads the ephemeral key.
func (r *scriptedRand) Read(p []byte) (int, error) {
	if r.next == nil || len(p) != len(r.next) {
		return 0, errUnexpectedDraw
	}
	n := copy(p, r.next)
	r.next = nil
	return n, nil
}
