package httpupgrade

import "net"

type connection struct {
	net.Conn
	remoteAddr net.Addr
	// pending holds bytes read past the upgrade request, they come before the socket
	pending []byte
}

func newConnection(conn net.Conn, remoteAddr net.Addr, pending []byte) *connection {
	return &connection{
		Conn:       conn,
		remoteAddr: remoteAddr,
		pending:    pending,
	}
}

func (c *connection) Read(b []byte) (int, error) {
	if len(c.pending) > 0 {
		n := copy(b, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

func (c *connection) RemoteAddr() net.Addr {
	return c.remoteAddr
}
