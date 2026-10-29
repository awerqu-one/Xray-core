package raywire

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"sync"
	"time"

	"github.com/flynn/noise"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// Server is the inbound handler for the raywire protocol.
type Server struct {
	privateKey noise.DHKey
	// keys are the PSK-derived keys of this inbound, and of previousPsk during a
	// rotation. The PSK itself is not kept.
	keys headKeys
	// clients maps each client static public key, as a string, to its account. It is
	// read only after the key has been authenticated by the handshake.
	clients  map[string]*Account
	pad      padPolicy
	fallback net.Destination // zero when no fallback is configured
	// allowSilentClose lets a failed connection close without a decoy.
	allowSilentClose bool
	policyManager    policy.Manager
	// replay starts at the server's clock, so a first message from before a
	// restart is refused.
	replay *ReplayFilter
	// seen remembers the heads of accepted handshakes, so a copy is refused before
	// any DH (seen.go). It is released by Close.
	seen  *seenHeads
	adm   *admission
	relay *admission
	live  liveSessions
	// headFails counts the first messages that fail the head check, and the
	// handshakes accepted under previousPsk, for one summary line a minute.
	headFails headFailLog
	// prevTimer logs once when previousPsk expires. It is nil without previousPsk.
	prevTimer *time.Timer
}

// headFailLog counts first messages that fail with reason tag, length or noise, and the
// handshakes accepted under previousPsk. A wrong PSK, a wrong server key and a probe all
// look the same to the server, so the count is the operator's only signal. It carries no
// peer address and no key material. The labels of the previousPsk accounts are the
// account's email, or a hash of its public key, which is public.
//
// The first event of a window arms a timer for the end of that window. When the timer
// fires, it logs the counts of the window and clears them. So a burst is reported even
// when no later event arrives, a window without events logs nothing, and no goroutine
// runs while the log is idle.
type headFailLog struct {
	mu         sync.Mutex
	fp         string              // 8 hex digits of the fingerprint of psk: the inbound label
	count      int                 // failures in the current window
	prev       int                 // handshakes accepted under previousPsk in the current window
	prevLabels map[string]struct{} // accounts that connected under previousPsk in the window
	timer      *time.Timer         // ends the current window; nil when no event is counted
	stopped    bool                // set by stop; the log then neither counts nor logs
}

// headFailWindow is the length of one summary window: the server logs at most
// one line per window, and that line counts the failures in the window. It is a
// variable so that a test can shorten it.
var headFailWindow = time.Minute

// armLocked starts the window timer for the first event of a window. The caller must
// hold mu.
func (l *headFailLog) armLocked() {
	if l.timer == nil {
		l.timer = time.AfterFunc(headFailWindow, l.flush)
	}
}

// add counts one failure. The first event of a window arms the timer that ends it.
func (l *headFailLog) add() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.stopped {
		return
	}
	l.count++
	l.armLocked()
}

// addPrevious counts one handshake accepted under previousPsk, for the account label.
func (l *headFailLog) addPrevious(label string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.stopped {
		return
	}
	l.prev++
	if l.prevLabels == nil {
		l.prevLabels = make(map[string]struct{})
	}
	l.prevLabels[label] = struct{}{}
	l.armLocked()
}

// flush ends the current window. It logs the counts that are not zero, and then clears
// the counts and the timer. The rotation lines are Warning: one summary line when a
// handshake was accepted under previousPsk, and one line per account, sorted by label.
func (l *headFailLog) flush() {
	l.mu.Lock()
	n, m, stopped, fp := l.count, l.prev, l.stopped, l.fp
	labels := make([]string, 0, len(l.prevLabels))
	for label := range l.prevLabels {
		labels = append(labels, label)
	}
	l.count, l.prev, l.prevLabels, l.timer = 0, 0, nil, nil
	l.mu.Unlock()
	if stopped || (n == 0 && m == 0) {
		return
	}
	ctx := context.Background()
	switch {
	case m == 0:
		errors.LogInfo(ctx, "raywire: ", n, " first messages failed the head check in the last minute (wrong psk or serverPublicKey, old client, clock skew, replay, or probes)")
	case n == 0:
		errors.LogWarning(ctx, "raywire: ", m, " handshakes accepted under previousPsk in the last minute (inbound psk fingerprint ", fp, ")")
	default:
		errors.LogWarning(ctx, "raywire: ", n, " first messages failed the head check in the last minute (wrong psk or serverPublicKey, old client, clock skew, replay, or probes); ", m, " handshakes accepted under previousPsk in the last minute (inbound psk fingerprint ", fp, ")")
	}
	sort.Strings(labels)
	for _, label := range labels {
		errors.LogWarning(ctx, "raywire: account ", label, " connected under previousPsk in the last minute (inbound psk fingerprint ", fp, ")")
	}
}

// stop ends the log. A count that has not been logged is dropped, because its
// window has not ended, and the pending timer is stopped.
func (l *headFailLog) stop() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.stopped = true
	l.count, l.prev, l.prevLabels = 0, 0, nil
	if l.timer != nil {
		l.timer.Stop()
		l.timer = nil
	}
}

// accountLabel names an account in the log. It is the email when there is one, and
// otherwise "key " and the first 4 bytes of SHA-256 of the public key, in hex.
func accountLabel(a *Account) string {
	if a == nil {
		return ""
	}
	if a.Email != "" {
		return a.Email
	}
	sum := sha256.Sum256(a.PublicKey)
	return "key " + hex.EncodeToString(sum[:4])
}

// NewServer creates a raywire inbound from its configuration.
func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	key, err := keyFromPrivate(config.PrivateKey)
	if err != nil {
		return nil, err
	}
	psk, err := pskFromConfig(config.Psk)
	if err != nil {
		return nil, err
	}
	// previousPskUntil is a Unix time in seconds. Zero means unset. newHeadKeys runs
	// ValidatePreviousPsk, which refuses a previousPskUntil that is set without
	// previousPsk, or the reverse.
	var until time.Time
	if config.PreviousPskUntil != 0 {
		until = time.Unix(config.PreviousPskUntil, 0)
	}
	keys, err := newHeadKeys(psk, config.PreviousPsk, until)
	if err != nil {
		return nil, err
	}

	// A server without clients would start and silently reject every peer. The
	// JSON path refuses this too, so the typed path must not build such a server.
	if len(config.Clients) == 0 {
		return nil, errors.New(`raywire: "clients" must contain at least one client`)
	}
	if err := ValidateAccounts(config.Clients); err != nil {
		return nil, err
	}
	clients := make(map[string]*Account, len(config.Clients))
	for _, account := range config.Clients {
		clients[string(account.PublicKey)] = account
	}

	pad := padFromProto(config.Padding)
	if err := pad.validate(); err != nil {
		return nil, err
	}

	var fallback net.Destination
	switch {
	case config.Fallback != "":
		fallback, err = ParseFallback(config.Fallback)
		if err != nil {
			return nil, err
		}
	case !config.AllowSilentClose:
		return nil, errors.New(`raywire: "fallback" is required unless "allowSilentClose" is set`)
	}

	v := core.MustFromContext(ctx)
	now := handshakeClock()
	fp := hex.EncodeToString(keys.cur.fingerprint)
	errors.LogInfo(ctx, "raywire: version raywire/4, psk fingerprint ", fp)
	s := &Server{
		privateKey:       key,
		keys:             keys,
		clients:          clients,
		pad:              pad,
		fallback:         fallback,
		allowSilentClose: config.AllowSilentClose,
		policyManager:    v.GetFeature(policy.ManagerType()).(policy.Manager),
		replay:           newReplayFilterAt(now),
		seen:             newSeenHeads(seenHeadCap, seenHeadTTL, now),
		adm:              newAdmission(maxPendingHandshakes, maxPendingPerIP),
		relay:            newAdmission(maxRelays, maxRelaysPerIP),
	}
	s.headFails.fp = fp
	if keys.hasPrev {
		s.logPreviousPsk(ctx, now, fp)
	}
	return s, nil
}

// logPreviousPsk logs the state of previousPsk at start, and arms the one-shot timer
// that logs its expiry. The lines are Warning, because the rotation depends on them.
func (s *Server) logPreviousPsk(ctx context.Context, now time.Time, fp string) {
	prevFP := hex.EncodeToString(s.keys.prev.fingerprint)
	until := s.keys.prevUntil.UTC().Format(time.RFC3339)
	if !now.Before(s.keys.prevUntil) {
		errors.LogWarning(ctx, "raywire: previousPsk expired at ", until, " and is ignored; remove it from the config (inbound psk fingerprint ", fp, ")")
		return
	}
	errors.LogWarning(ctx, "raywire: previousPsk set, fingerprint ", prevFP, ", accepted until ", until, " (inbound psk fingerprint ", fp, ")")
	s.prevTimer = time.AfterFunc(s.keys.prevUntil.Sub(now), func() {
		errors.LogWarning(context.Background(), "raywire: previousPsk expired at ", until, "; heads under it are refused now; remove it from the config (inbound psk fingerprint ", fp, ")")
	})
}

// Network implements proxy.Inbound.Network().
func (s *Server) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

// Close implements common.Closable. The core calls it when the inbound is closed. It
// stops the head-failure summary and the previousPsk expiry timer, and it releases the
// memory of remembered heads, so no timer and no memory outlives the server.
func (s *Server) Close() error {
	s.headFails.stop()
	if s.prevTimer != nil {
		s.prevTimer.Stop()
	}
	s.seen.Close()
	return nil
}

// authorize returns the account of a client key that may connect. The handshake
// calls it only after Noise has authenticated the key, so the email cannot come
// from the peer.
func (s *Server) authorize(clientPublic []byte) (*Account, bool) {
	account, ok := s.clients[string(clientPublic)]
	return account, ok
}

// errRefused is returned for a connection that the pre-auth limit refused before
// any read.
var errRefused = errors.New("raywire: pre-auth limit reached")

// handlePreAuth runs the pre-auth stage of one connection. It takes a pre-auth
// slot, runs the handshake and releases the slot at the decision or at success.
// A connection that fails the handshake goes to the decoy, or is closed when
// there is none. Every close that does not relay drains the queued bytes first
// (drain.go). It returns a *HandshakeError for a decision about the peer and
// errRefused for a refused connection. On success it returns the session. The
// caller must not use conn after an error. The policy manager is not used here,
// so tests can call it without a core.
func (s *Server) handlePreAuth(ctx context.Context, conn stat.Connection, pol padPolicy) (*Conn, error) {
	release, ok := s.adm.TryAcquire(sourceKey(conn.RemoteAddr()))
	if !ok {
		// Refused before any read, so the peer learns nothing.
		errors.LogDebug(ctx, "raywire: pre-auth limit reached, closing connection from ", conn.RemoteAddr())
		closeAfterDrain(conn)
		return nil, errRefused
	}
	rc, err := serverHandshake(conn, s.privateKey, s.authorize, s.replay, s.seen, s.keys, pol)
	release()
	if err == nil {
		if rc.viaPrevious {
			s.headFails.addPrevious(accountLabel(rc.peer))
		}
		return rc, nil
	}

	he, ok := err.(*HandshakeError)
	if !ok {
		// Not a decision about the peer, so there is nothing to relay.
		closeAfterDrain(conn)
		return nil, err
	}
	// On a security: tls inbound the handshake may have failed in the TLS layer,
	// before raywire saw a byte. The bytes that the TLS layer read are then relayed
	// first, unless the TLS layer answered or overflowed (tlsprefix.go). The EOF
	// rule is unchanged: an EOF closes after the drain.
	var relayFrom stat.Connection = conn
	if he.Reason != "eof" {
		if prefix, last, socket, wrote, overflow, found := tlsPrefix(conn); found {
			if overflow || wrote {
				// The TLS layer already answered, or the record is too large to relay
				// whole, so the decoy would see a stream with its beginning missing.
				errors.LogDebug(ctx, "raywire: ", he.Reason, " after the TLS layer answered or overflowed, from ", conn.RemoteAddr())
				closeAfterDrain(socket)
				return nil, err
			}
			he = &HandshakeError{Consumed: prefix, Reason: he.Reason, Err: he.Err, LastRead: last}
			relayFrom = counterSocket(conn, socket, len(prefix))
		}
	}
	errors.LogDebug(ctx, "raywire: ", he.Reason, " from ", conn.RemoteAddr(), " after ", len(he.Consumed), " bytes")
	switch he.Reason {
	case "tag", "length", "noise", "replay":
		s.headFails.add()
	}
	// A peer that closed without sending a byte gets no decoy, since the decoy
	// would only see an empty connection.
	if (he.Reason == "eof" && len(he.Consumed) == 0) || !s.fallback.IsValid() {
		closeAfterDrain(relayFrom)
		return nil, err
	}
	// relayToDecoy takes its own relay slot and closes the connection when none is free.
	relayToDecoy(ctx, relayFrom, he.Consumed, he.LastRead, s.fallback, s.relay)
	return nil, err
}

// Process implements proxy.Inbound.Process(). An unauthorized or malformed
// connection gets no reply from raywire: it is relayed to the decoy or closed.
func (s *Server) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	sessionPolicy := s.policyManager.ForLevel(0)

	rc, err := s.handlePreAuth(ctx, conn, s.pad)
	if err != nil {
		// A decision about the peer was handled: the peer was relayed or closed,
		// and handlePreAuth logged the reason at debug level. Returning an error
		// here would log every probe at info level.
		if _, ok := err.(*HandshakeError); ok || err == errRefused {
			return nil
		}
		return errors.New("raywire: rejected connection from ", conn.RemoteAddr()).Base(err)
	}

	if rc.peer == nil {
		// Process only runs after authorize; a nil account would be a wiring
		// bug. Refuse instead of dereferencing it in the live quota.
		conn.Close()
		return nil
	}

	// Hold the authenticated key's slot through every exit, including header
	// errors and dispatch failures. UDP uses the same connection and quota.
	release, ok := s.live.TryAcquire(rc.peer.PublicKey)
	if !ok {
		errors.LogDebug(ctx, "raywire: live session limit reached, closing connection")
		conn.Close()
		return nil
	}
	defer release()

	// The header must arrive within the handshake timeout. The deadline is
	// cleared after the header, so the idle timer governs the rest of the session.
	if err := conn.SetReadDeadline(time.Now().Add(sessionPolicy.Timeouts.Handshake)); err != nil {
		return errors.New("raywire: unable to set read deadline").Base(err)
	}
	destination, err := decodeHeader(rc)
	if err != nil {
		return errors.New("raywire: bad request from ", conn.RemoteAddr()).Base(err)
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return errors.New("raywire: unable to clear read deadline").Base(err)
	}

	// The email is the client that authenticated, not anything the peer sent.
	// A client without an email gets a user with an empty email. The dispatcher
	// counts only a non-empty email, and the mux path reads inbound.User.Email
	// without a nil check, so the user must never be nil here.
	var email string
	if rc.peer != nil {
		email = rc.peer.Email
	}
	inbound := session.InboundFromContext(ctx)
	if inbound != nil {
		inbound.Name = "raywire"
		// The stats count this connection's traffic under the email. This must be
		// set before Dispatch, which is where the stats read the user.
		inbound.User = &protocol.MemoryUser{Email: email, Level: 0}
	}

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   conn.RemoteAddr(),
		To:     destination,
		Status: log.AccessAccepted,
		Reason: "",
		Email:  email,
	})
	errors.LogInfo(ctx, "received request for ", destination)

	link, err := dispatcher.Dispatch(ctx, destination)
	if err != nil {
		return errors.New("raywire: failed to dispatch request to ", destination).Base(err)
	}

	// A UDP session sends each datagram with its own address, so both
	// directions use the datagram framing. The requested destination is the
	// source of any reply that carries no address.
	fromClient, toClient := buf.NewReader(rc), buf.NewWriter(rc)
	if destination.Network == net.Network_UDP {
		fromClient, toClient = newPacketReader(rc), newPacketWriter(rc, destination)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)

	requestDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
		return buf.Copy(fromClient, link.Writer, buf.UpdateActivity(timer))
	}
	responseDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
		return buf.Copy(link.Reader, toClient, buf.UpdateActivity(timer))
	}

	// The client's end-of-stream closes the destination's input. The end of the
	// destination's output becomes an end-of-stream frame to the client.
	requestDonePost := task.OnSuccess(requestDone, task.Close(link.Writer))
	responseDonePost := task.OnSuccess(responseDone, rc.CloseWrite)
	if err := task.Run(ctx, requestDonePost, responseDonePost); err != nil {
		common.Must(common.Interrupt(link.Reader))
		common.Must(common.Interrupt(link.Writer))
		return errors.New("connection ends").Base(err)
	}
	return nil
}

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}
