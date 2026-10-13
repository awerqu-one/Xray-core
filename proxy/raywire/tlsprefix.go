package raywire

import (
	"net"
	"time"

	"github.com/xtls/xray-core/transport/internet/stat"
)

// preHandshakeRecord is implemented by the TLS server connection (transport/internet/tls).
// It describes a handshake that failed on this connection, and the bytes it read before
// the failure.
type preHandshakeRecord interface {
	PreHandshakeRecord() (prefix []byte, last time.Time, socket net.Conn, wrote, overflow, ok bool)
}

// tlsPrefix finds the TLS wrapper of a failed handshake under conn. It walks the wrappers
// as rawSocket does (drain.go): the stats wrapper, then NetConn or Raw, at most maxUnwrap
// levels. At the first wrapper that implements preHandshakeRecord it returns that
// wrapper's answer, and found is that answer's ok. It never walks past that wrapper.
// A connection with no TLS wrapper below its other wrappers gives found = false.
func tlsPrefix(conn net.Conn) (prefix []byte, last time.Time, socket net.Conn, wrote, overflow, found bool) {
	for range maxUnwrap {
		conn = stat.TryUnwrapStatsConn(conn)
		if p, ok := conn.(preHandshakeRecord); ok {
			return p.PreHandshakeRecord()
		}
		switch c := conn.(type) {
		case netConner:
			conn = c.NetConn()
		case rawConner:
			conn = c.Raw()
		default:
			return nil, time.Time{}, nil, false, false, false
		}
		if conn == nil {
			return nil, time.Time{}, nil, false, false, false
		}
	}
	return nil, time.Time{}, nil, false, false, false
}

// counterSocket returns socket with the stats counters of conn, so that the bytes a TLS
// probe sends and receives are counted as a plain TCP probe's are (worker.go). The prefix
// bytes were read below the TLS layer, which the counters never saw, so prefixLen is added
// to the read counter once.
func counterSocket(conn, socket net.Conn, prefixLen int) net.Conn {
	cc, ok := conn.(*stat.CounterConnection)
	if !ok {
		return socket
	}
	if cc.ReadCounter != nil && prefixLen > 0 {
		cc.ReadCounter.Add(int64(prefixLen))
	}
	return &stat.CounterConnection{
		Connection:   socket,
		ReadCounter:  cc.ReadCounter,
		WriteCounter: cc.WriteCounter,
	}
}
