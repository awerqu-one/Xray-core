package raywire

import (
	"net"
	"syscall"
	"time"

	"github.com/xtls/xray-core/transport/internet/stat"
)

const (
	// drainChunk is the size of one read in the drain.
	drainChunk = 4096

	// drainLimit is the most bytes the drain discards. A longer queue still
	// resets the connection on close (R13).
	drainLimit = 262144

	// maxUnwrap bounds the walk from a connection to its socket in rawSocket.
	maxUnwrap = 8

	// relayDrainWait bounds one read of the read-through drain in drainThrough.
	// It only has to give the kernel's queue time to reach the read.
	relayDrainWait = 20 * time.Millisecond
)

// netConner is implemented by the TLS and REALITY connections of the transport
// layer. NetConn returns the connection that they wrap.
type netConner interface {
	NetConn() net.Conn
}

// rawConner is implemented by the proxy protocol connection of the listener.
type rawConner interface {
	Raw() net.Conn
}

// rawSocket returns the socket under conn. It removes the stats wrapper and
// follows NetConn (TLS, REALITY) or Raw (proxy protocol), so that a connection under security:tls or REALITY reaches
// its socket. It gives false when the chain ends without a socket, such as a pipe
// in a test, or when it is longer than maxUnwrap.
func rawSocket(conn net.Conn) (syscall.Conn, bool) {
	for range maxUnwrap {
		conn = stat.TryUnwrapStatsConn(conn)
		if sc, ok := conn.(syscall.Conn); ok {
			return sc, true
		}
		switch c := conn.(type) {
		case netConner:
			conn = c.NetConn()
		case rawConner:
			conn = c.Raw()
		default:
			return nil, false
		}
		if conn == nil {
			return nil, false
		}
	}
	return nil, false
}

// closeAfterDrain closes a connection that is not relayed. A close while bytes
// are unread in the socket's receive queue makes the kernel send a reset. A
// prober can then tell a refusal from a relay, which closes after its reads
// without a reset. The queued bytes are therefore discarded first, and the close
// sends FIN. A connection without a raw socket, such as a pipe in a test, is
// closed as it is.
func closeAfterDrain(conn net.Conn) {
	sc, ok := rawSocket(conn)
	if !ok {
		conn.Close()
		return
	}
	// A read deadline in the past makes the raw read return without reading, so
	// the deadline is cleared before the queue is drained.
	_ = conn.SetReadDeadline(time.Time{})
	drainQueued(sc)
	if cw, ok := stat.TryUnwrapStatsConn(conn).(closeWriter); ok {
		cw.CloseWrite()
	}
	conn.Close()
}

// closeAfterRelayDrain closes a relayed connection for which halfCloser found no
// CloseWrite. When the socket can be reached, the drain is the raw one of
// closeAfterDrain. A wrapper chain longer than maxUnwrap hides its socket, but
// the relay has already read this connection through its wrappers, so the queued
// bytes are read through them as well and the close still sends FIN.
//
// The refusal path must keep closeAfterDrain: a refused connection is closed
// unread, which is how a prober tells a refusal from a relay
// (TestRefusedConnectionIsNotRead).
func closeAfterRelayDrain(conn net.Conn) {
	closeAfterRelayDrainGated(conn, nil)
}

// closeAfterRelayDrainGated is closeAfterRelayDrain for a connection whose
// reads are shared with the relay's uplink copy. Every read of the drain is
// taken under gate, so the two never read at the same time.
func closeAfterRelayDrainGated(conn net.Conn, gate *proberReads) {
	if _, ok := rawSocket(conn); ok {
		// halfCloser searched at least as far as rawSocket, so it found no
		// CloseWrite to use here.
		closeAfterDrain(conn)
		return
	}
	drainThroughGated(conn, gate)
	conn.Close()
}

// drainThrough reads and discards the bytes queued on conn through conn's own
// Read, which reaches the socket whatever the length of the wrapper chain. Each
// read is bounded by relayDrainWait, so a prober that has stopped sending ends
// the drain instead of holding the relay open.
func drainThrough(conn net.Conn) {
	drainThroughGated(conn, nil)
}

// drainThroughGated is drainThrough with every read taken under gate.
func drainThroughGated(conn net.Conn, gate *proberReads) {
	// A read deadline in the past returns without reading, so the deadline is
	// set shortly ahead and cleared again after the last read. This first one
	// also wakes the uplink copy: while it sits in Read it holds the gate, and
	// the drain cannot start until that read returns.
	_ = conn.SetReadDeadline(time.Now().Add(relayDrainWait))
	defer conn.SetReadDeadline(time.Time{})
	b := make([]byte, drainChunk)
	// The budget for the reads starts once the gate is held: the wait for it
	// above may have spent the first deadline, and a read with an expired
	// deadline returns without reading anything. One deadline covers the whole
	// drain, so a prober that keeps talking cannot hold the relay open.
	var deadline time.Time
	read := func() (int, error) {
		if gate == nil {
			if deadline.IsZero() {
				deadline = time.Now().Add(relayDrainWait)
			}
			_ = conn.SetReadDeadline(deadline)
			return conn.Read(b)
		}
		gate.mu.Lock()
		defer gate.mu.Unlock()
		if deadline.IsZero() {
			deadline = time.Now().Add(relayDrainWait)
		}
		_ = conn.SetReadDeadline(deadline)
		return conn.Read(b)
	}
	for discarded := 0; discarded < drainLimit; {
		n, err := read()
		discarded += n
		// A reader that makes no progress and reports no error would spin.
		if err != nil || n == 0 {
			return
		}
	}
}
