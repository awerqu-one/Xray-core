package raywire

import (
	"context"
	stderrors "errors"
	"io"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

const (
	// maxRelays bounds the decoy relays in progress. Each relay holds two buffers
	// of buf.Size, so the pool caps the memory that probes can take.
	maxRelays = 512

	// maxRelaysPerIP bounds the relays from one source address, so that one source
	// cannot take the whole pool and leave none for other probes.
	maxRelaysPerIP = 16
)

var (
	// decoyDialTimeout bounds the dial to the decoy.
	decoyDialTimeout = 5 * time.Second

	// relayInactivity ends a relay in which no byte moves in either direction.
	relayInactivity = 60 * time.Second

	// relayMaxLife ends a relay however busy it is. A probe is not a session,
	// so a relay should not hold a slot for as long as a session may.
	relayMaxLife = 5 * time.Minute

	// decoyDownEvery is the least time between two error-level logs for an
	// unreachable decoy. A probe is unauthenticated, so each one can make a dial
	// fail. Logging each failure at error level would let a prober set the log rate.
	decoyDownEvery = time.Minute

	// dialDecoy opens the connection to the decoy. Tests replace it.
	dialDecoy = internet.DialSystem

	// relayAdm bounds the relays in progress, in total and per source address.
	// Tests replace it with a smaller pool.
	relayAdm = newAdmission(maxRelays, maxRelaysPerIP)
)

// decoyDownLog holds the time of the last error-level log for an unreachable decoy.
var decoyDownLog struct {
	mu   sync.Mutex
	last time.Time
}

// logDecoyDown logs a failed decoy dial at error level at most once per
// decoyDownEvery, so that an operator still sees a decoy that is down. Other
// failures are logged at debug level.
func logDecoyDown(ctx context.Context, err error, dest xnet.Destination) {
	decoyDownLog.mu.Lock()
	now := time.Now()
	loud := decoyDownLog.last.IsZero() || now.Sub(decoyDownLog.last) >= decoyDownEvery
	if loud {
		decoyDownLog.last = now
	}
	decoyDownLog.mu.Unlock()

	if loud {
		errors.LogErrorInner(ctx, err, "raywire: decoy unreachable at ", dest)
		return
	}
	errors.LogDebugInner(ctx, err, "raywire: decoy unreachable at ", dest)
}

// closeWriter is implemented by connections that can half-close, such as TCP.
type closeWriter interface {
	CloseWrite() error
}

// passReset makes the prober see a reset, not an end, when a copy fails with a
// reset. A direct connection to the decoy would show the prober a reset when the
// decoy resets. Setting SO_LINGER to zero makes the next Close send RST instead
// of FIN. The TCP socket may sit under the stats wrapper, PROXY protocol, TLS,
// or a wrapper that embeds net.Conn (the HTTP header), so the linger is set on
// the socket tcpUnder finds, not on the wrapper.
func passReset(prober net.Conn, err error) {
	if !stderrors.Is(err, syscall.ECONNRESET) {
		return
	}
	if tcp := tcpUnder(prober); tcp != nil {
		tcp.SetLinger(0)
	}
}

// netConnType is the type of an embedded net.Conn field.
var netConnType = reflect.TypeOf((*net.Conn)(nil)).Elem()

// embeddedConn returns the net.Conn embedded in conn. A wrapper such as the
// HTTP header connection embeds net.Conn and defines Close, which keeps
// CloseWrite out of the method set. The socket is the embedded field. A named
// field is not followed: it is not the wrapper.
func embeddedConn(conn net.Conn) net.Conn {
	v := reflect.ValueOf(conn)
	if !v.IsValid() {
		return nil
	}
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil
	}
	f, ok := v.Type().FieldByName("Conn")
	if !ok || !f.Anonymous || f.Type != netConnType {
		return nil
	}
	fv := v.FieldByIndex(f.Index)
	if !fv.IsValid() || !fv.CanInterface() {
		return nil
	}
	inner, _ := fv.Interface().(net.Conn)
	if inner == nil || inner == conn {
		return nil
	}
	return inner
}

// unwrapOne returns the connection directly under conn, following NetConn
// (TLS, REALITY), Raw (proxy protocol), or an embedded net.Conn. It reports
// false when conn is the end of the chain.
func unwrapOne(conn net.Conn) (net.Conn, bool) {
	switch c := conn.(type) {
	case netConner:
		next := c.NetConn()
		if next == nil || next == conn {
			return nil, false
		}
		return next, true
	case rawConner:
		next := c.Raw()
		if next == nil || next == conn {
			return nil, false
		}
		return next, true
	default:
		next := embeddedConn(conn)
		if next == nil {
			return nil, false
		}
		return next, true
	}
}

// tcpUnder returns the TCP socket under conn. It removes one stats wrapper per
// level and follows the same chain as rawSocket, plus a wrapper that embeds
// net.Conn. It returns nil when the chain ends without a TCP socket or is
// longer than maxUnwrap.
func tcpUnder(conn net.Conn) *net.TCPConn {
	for range maxUnwrap {
		if conn == nil {
			return nil
		}
		conn = stat.TryUnwrapStatsConn(conn)
		if tcp, ok := conn.(*net.TCPConn); ok {
			return tcp
		}
		next, ok := unwrapOne(conn)
		if !ok {
			return nil
		}
		conn = next
	}
	return nil
}

// halfCloser returns the first connection under conn that can half-close.
// Wrappers that hide CloseWrite are peeled first (stats, proxy protocol, an
// embedded net.Conn). A connection that already has CloseWrite, such as TLS,
// is used as it is: its CloseWrite is the end-of-stream the peer must see.
func halfCloser(conn net.Conn) (closeWriter, bool) {
	for range maxUnwrap {
		if conn == nil {
			return nil, false
		}
		conn = stat.TryUnwrapStatsConn(conn)
		if cw, ok := conn.(closeWriter); ok {
			return cw, true
		}
		next, ok := unwrapOne(conn)
		if !ok {
			return nil, false
		}
		conn = next
	}
	return nil, false
}

// relayToDecoy passes a connection that failed the handshake to the decoy. The
// decoy receives the bytes already read, in one write, and then the rest of the
// stream in order, so the prober sees what it would see by connecting to the
// decoy directly. The relay sends nothing of its own and dials only dest. The
// idle limit counts from lastRead, the last byte the prober sent, so a silent
// probe is closed relayInactivity after that byte. The replay of bytes already
// read is inside those limits: a Write that blocks on a decoy that has stopped
// ACKing is ended by closing that side. It returns when both directions have
// ended, or when the inactivity or life limit closes both sides. A connection
// that is not relayed, because the relay pool is full, the decoy cannot be
// dialed, no idle time is left, or the replay of consumed bytes fails without
// a reset, is closed after a drain (drain.go).
func relayToDecoy(ctx context.Context, prober net.Conn, consumed []byte, lastRead time.Time, dest xnet.Destination, relay *admission) {
	if relay == nil {
		relay = relayAdm
	}
	release, ok := relay.TryAcquire(sourceKey(prober.RemoteAddr()))
	if !ok {
		errors.LogDebug(ctx, "raywire: no relay slot free, closing connection from ", prober.RemoteAddr())
		closeAfterDrain(prober)
		return
	}
	defer release()

	// The server clears the deadlines on success, but the relay must not depend
	// on that. A deadline still set would cut the relay at the handshake limit.
	if err := prober.SetDeadline(time.Time{}); err != nil {
		errors.LogDebugInner(ctx, err, "raywire: unable to clear deadline before relay")
		closeAfterDrain(prober)
		return
	}

	if lastRead.IsZero() {
		lastRead = time.Now()
	}
	// No dial for a probe that has been quiet for the whole idle limit.
	if relayInactivity-time.Since(lastRead) <= 0 {
		closeAfterDrain(prober)
		return
	}

	dialCtx, dialCancel := context.WithTimeout(ctx, decoyDialTimeout)
	decoy, err := dialDecoy(dialCtx, dest, nil)
	dialCancel()
	if err != nil {
		logDecoyDown(ctx, err, dest)
		closeAfterDrain(prober)
		return
	}
	defer prober.Close()
	defer decoy.Close()

	ctx, cancel := context.WithTimeout(ctx, relayMaxLife)
	defer cancel()
	idle := newRelayIdle(lastRead)
	go idle.watch(ctx, cancel, relayInactivity)

	// A copy blocks in Read, and the replay of consumed bytes blocks in Write.
	// Ending the relay closes both sides to wake either one.
	go func() {
		<-ctx.Done()
		prober.Close()
		decoy.Close()
	}()

	if !replayConsumed(ctx, prober, decoy, consumed) {
		return
	}

	// proberReads is held for each read of the prober by the uplink copy, and
	// by the read-through drain the downlink copy runs when the decoy's output
	// ends. Transports such as WebSocket allow one reader, so the two must
	// never read at the same time.
	var proberReads proberReads
	// draining is set by the downlink copy before it drains. A blocked read
	// woken by the drain's deadline then ends quietly instead of cancelling
	// the relay.
	var draining atomic.Bool

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := copyFixedGated(decoy, prober, &proberReads, idle.touch); err != nil {
			if draining.Load() {
				// The read-through drain took over this connection.
				return
			}
			passReset(prober, err)
			cancel()
			return
		}
		// The prober's end-of-stream becomes the decoy's. The decoy's output
		// keeps flowing, as it would for a direct connection.
		if cw, ok := decoy.(closeWriter); ok {
			cw.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		if err := copyFixed(prober, decoy, idle.touch); err != nil {
			passReset(prober, err)
			cancel()
			return
		}
		// The decoy's end-of-stream becomes the prober's. A prober without
		// CloseWrite is closed instead, once the decoy's output has ended.
		// Stats, PROXY protocol, and an embedded net.Conn hide CloseWrite, so
		// the check walks to the connection under them.
		if cw, ok := halfCloser(prober); ok {
			cw.CloseWrite()
			return
		}
		// Drain queued probe bytes before closing; a bare Close would turn a
		// direct decoy FIN into an RST on the prober. The relay has already
		// read this connection, so the drain may read through it as well: a
		// wrapper chain deeper than maxUnwrap has no reachable socket.
		//
		// The uplink copy must have stopped first. Its blocked Read is woken by
		// a deadline in the past; if it does not return in time it is stuck
		// elsewhere and the close happens without a concurrent read.
		draining.Store(true)
		closeAfterRelayDrainGated(prober, &proberReads)
	}()
	wg.Wait()
}

// replayConsumed writes the bytes already read to the decoy. The life and idle
// limits are already running; a blocked Write ends when they close decoy, and
// the slot is released when this returns even if that Write never notices the
// close. A reset is passed on to the prober. Any other failure means the
// connection was not relayed, so the prober is drained and closed: a bare Close
// would turn the reset into a FIN and any other error into a RST while unread
// probe bytes are still queued. It reports whether the relay should continue.
func replayConsumed(ctx context.Context, prober, decoy net.Conn, consumed []byte) bool {
	if len(consumed) == 0 {
		return true
	}
	errCh := make(chan error, 1)
	go func() {
		// net.Conn is not required to accept a whole buffer in one Write.
		for len(consumed) > 0 {
			n, err := decoy.Write(consumed)
			if n > 0 {
				consumed = consumed[n:]
			}
			if err != nil {
				errCh <- err
				return
			}
			if n == 0 {
				errCh <- io.ErrShortWrite
				return
			}
		}
		errCh <- nil
	}()
	var err error
	select {
	case err = <-errCh:
	case <-ctx.Done():
		select {
		case err = <-errCh:
		default:
			return false
		}
	}
	if err != nil {
		// Our own close woke the Write. The relay is already ending.
		if ctx.Err() != nil {
			return false
		}
		errors.LogDebugInner(ctx, err, "raywire: unable to send bytes to decoy")
		if stderrors.Is(err, syscall.ECONNRESET) {
			passReset(prober, err)
			return false
		}
		// Drain the socket under the wrapper before closeAfterDrain. That helper
		// follows NetConn and Raw, not an embedded net.Conn, so a header wrapper
		// would otherwise Close with the probe still queued and the kernel would
		// send RST.
		if tcp := tcpUnder(prober); tcp != nil {
			_ = tcp.SetReadDeadline(time.Time{})
			drainQueued(tcp)
		}
		closeAfterDrain(prober)
		return false
	}
	return ctx.Err() == nil
}

// copyFixed copies src to dst through one buffer of buf.Size. A relay therefore
// holds at most that much per direction: a read is never larger than the buffer,
// and the next read waits until the write has finished. moved is called after
// each write that completes. It returns nil at the end of src.
// proberReads serializes reads of one connection. The uplink copy and the
// read-through drain both read the prober, and a transport wrapper may allow
// only one reader at a time.
type proberReads struct {
	mu sync.Mutex
}

// read is one read under the gate. A nil gate reads directly.
func (g *proberReads) read(conn net.Conn, b []byte) (int, error) {
	if g == nil {
		return conn.Read(b)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return conn.Read(b)
}

// copyFixedGated is copyFixed with every read taken under gate.
func copyFixedGated(dst io.Writer, src net.Conn, gate *proberReads, moved func()) error {
	b := make([]byte, buf.Size)
	for {
		n, rerr := gate.read(src, b)
		if n > 0 {
			if _, werr := dst.Write(b[:n]); werr != nil {
				return werr
			}
			moved()
		}
		if rerr == io.EOF {
			return nil
		}
		if rerr != nil {
			return rerr
		}
	}
}

func copyFixed(dst io.Writer, src io.Reader, moved func()) error {
	b := make([]byte, buf.Size)
	for {
		n, rerr := src.Read(b)
		if n > 0 {
			if _, werr := dst.Write(b[:n]); werr != nil {
				return werr
			}
			moved()
		}
		if rerr == io.EOF {
			return nil
		}
		if rerr != nil {
			return rerr
		}
	}
}

// relayIdle records when the last byte moved through a relay, in either
// direction. Its clock is monotonic, so a change of wall time does not move it.
type relayIdle struct {
	start time.Time
	last  atomic.Int64 // nanoseconds since start, when the last byte moved
}

// newRelayIdle starts the idle clock at since, the last byte the prober sent. It
// is a time from before the relay, so a relay that starts late may be closed
// sooner than relayInactivity after its own start.
func newRelayIdle(since time.Time) *relayIdle {
	return &relayIdle{start: since}
}

// touch records that a byte moved.
func (r *relayIdle) touch() {
	r.last.Store(int64(time.Since(r.start)))
}

// idleFor reports how long it has been since a byte last moved.
func (r *relayIdle) idleFor() time.Duration {
	return time.Since(r.start) - time.Duration(r.last.Load())
}

// watch cancels ctx once no byte has moved for limit. It re-arms for the time
// that is left after each byte, so it cancels exactly limit after the last
// byte. A timer that checks at fixed steps would cancel between one and two
// steps after it.
func (r *relayIdle) watch(ctx context.Context, cancel context.CancelFunc, limit time.Duration) {
	timer := time.NewTimer(limit - r.idleFor())
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		idle := r.idleFor()
		if idle >= limit {
			cancel()
			return
		}
		timer.Reset(limit - idle)
	}
}
