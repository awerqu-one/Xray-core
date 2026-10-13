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
