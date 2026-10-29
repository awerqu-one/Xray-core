package xicmp

import (
	"net"
	"reflect"
	"syscall"
	"unsafe"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/net/icmp"
)

// listenICMP opens an ICMP socket and runs the dialer controllers before
// the socket is returned. icmp.ListenPacket has no Control hook, so the
// fd is taken from the conn it created. A controller error closes it.
func listenICMP(network, address string) (*icmp.PacketConn, error) {
	conn, err := icmp.ListenPacket(network, address)
	if err != nil {
		return nil, err
	}
	if err := protectICMP(conn, controllerNetwork(network), address); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func protectICMP(conn *icmp.PacketConn, network, address string) error {
	if len(internet.DialerControllers()) == 0 {
		return nil
	}
	raw, err := icmpRawConn(conn)
	if err != nil {
		return errors.New("failed to apply external controller").Base(err)
	}
	return internet.ApplyDialerControllers(network, address, raw)
}

// controllerNetwork is the network string DialSystem's UDP and raw IP
// listens pass to controllers. Windows' interface controller panics on
// any other value, including "ip4:icmp".
func controllerNetwork(network string) string {
	switch network {
	case "udp4", "udp6":
		return network
	case "ip4:icmp":
		return "ip4"
	case "ip6:ipv6-icmp":
		return "ip6"
	default:
		return network
	}
}

func icmpRawConn(conn *icmp.PacketConn) (syscall.RawConn, error) {
	pc, err := icmpUnderlying(conn)
	if err != nil {
		return nil, err
	}
	sc, ok := pc.(syscall.Conn)
	if !ok {
		return nil, errors.New("icmp socket cannot be protected")
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// icmpUnderlying reads icmp.PacketConn's unexported net.PacketConn.
// x/net/icmp does not expose SyscallConn.
func icmpUnderlying(conn *icmp.PacketConn) (net.PacketConn, error) {
	v := reflect.ValueOf(conn).Elem().FieldByName("c")
	if !v.IsValid() || !v.CanAddr() || v.IsNil() {
		return nil, errors.New("icmp socket cannot be protected")
	}
	pc, ok := reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem().Interface().(net.PacketConn)
	if !ok || pc == nil {
		return nil, errors.New("icmp socket cannot be protected")
	}
	return pc, nil
}
