package internet

import (
	"context"
	"sync"
	"syscall"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
)

var (
	// Controllers mirrors the registered dialer controllers for code that
	// reads it directly. It is replaced, never modified in place; readers
	// inside Xray use DialerControllers, which takes ControllersLock.
	Controllers           []func(network, address string, c syscall.RawConn) error
	ControllersLock       sync.Mutex
	controllerIDs         []uint64
	nextControllerID      uint64
	effectiveSystemDialer SystemDialer = &DefaultSystemDialer{}
)

type SystemDialer interface {
	Dial(ctx context.Context, source net.Address, destination net.Destination, sockopt *SocketConfig) (net.Conn, error)
	DestIpAddress() net.IP
}

type DefaultSystemDialer struct {
	dns dns.Client
	obm outbound.Manager
}

func resolveSrcAddr(network net.Network, src net.Address) net.Addr {
	if src == nil || src == net.AnyIP {
		return nil
	}

	if network == net.Network_TCP {
		return &net.TCPAddr{
			IP:   src.IP(),
			Port: 0,
		}
	}

	return &net.UDPAddr{
		IP:   src.IP(),
		Port: 0,
	}
}

func (d *DefaultSystemDialer) Dial(ctx context.Context, src net.Address, dest net.Destination, sockopt *SocketConfig) (net.Conn, error) {
	errors.LogDebug(ctx, "dialing to "+dest.String())

	if dest.Network == net.Network_UDP {
		destAddr, err := net.ResolveUDPAddr("udp", dest.NetAddr())
		if err != nil {
			return nil, err
		}
		srcAddr := resolveSrcAddr(net.Network_UDP, src)
		if srcAddr == nil {
			// some OS don't support mapped IPv4 dual stack
			// and need to select 0.0.0.0 or [::] manually based on the destination
			wildcard := net.AnyIP.IP()
			if destAddr.IP.To4() == nil {
				wildcard = net.AnyIPv6.IP()
			}
			srcAddr = &net.UDPAddr{
				IP:   wildcard,
				Port: 0,
			}
		}
		var lc net.ListenConfig
		lc.Control = func(network, address string, c syscall.RawConn) error {
			for _, ctl := range DialerControllers() {
				if err := ctl(network, address, c); err != nil {
					// A socket the controller could not protect or bind
					// must not be used: it would follow the default route,
					// which may lead back into the tunnel.
					return errors.New("failed to apply external controller").Base(err)
				}
			}
			return c.Control(func(fd uintptr) {
				if sockopt != nil {
					if err := applyOutboundSocketOptions(network, destAddr.String(), fd, sockopt); err != nil {
						errors.LogInfo(ctx, err, "failed to apply socket options")
					}
				}
			})
		}
		packetConn, err := lc.ListenPacket(ctx, srcAddr.Network(), srcAddr.String())
		if err != nil {
			return nil, err
		}
		return &net.PacketConnWrapper{
			PacketConn: packetConn,
			Dest:       destAddr,
		}, nil
	}
	// Chrome defaults
	keepAliveConfig := net.KeepAliveConfig{
		Enable:   true,
		Idle:     45 * time.Second,
		Interval: 45 * time.Second,
		Count:    -1,
	}
	keepAlive := time.Duration(0)
	if sockopt != nil {
		if sockopt.TcpKeepAliveIdle*sockopt.TcpKeepAliveInterval < 0 {
			return nil, errors.New("invalid TcpKeepAliveIdle or TcpKeepAliveInterval value: ", sockopt.TcpKeepAliveIdle, " ", sockopt.TcpKeepAliveInterval)
		}
		if sockopt.TcpKeepAliveIdle < 0 || sockopt.TcpKeepAliveInterval < 0 {
			keepAlive = -1
			keepAliveConfig.Enable = false
		}
		if sockopt.TcpKeepAliveIdle > 0 {
			keepAliveConfig.Idle = time.Duration(sockopt.TcpKeepAliveIdle) * time.Second
		}
		if sockopt.TcpKeepAliveInterval > 0 {
			keepAliveConfig.Interval = time.Duration(sockopt.TcpKeepAliveInterval) * time.Second
		}
	}
	dialer := &net.Dialer{
		Timeout:         time.Second * 16,
		LocalAddr:       resolveSrcAddr(dest.Network, src),
		KeepAlive:       keepAlive,
		KeepAliveConfig: keepAliveConfig,
	}

	if sockopt != nil || len(DialerControllers()) > 0 {
		if sockopt != nil && sockopt.TcpMptcp {
			dialer.SetMultipathTCP(true)
		}
		dialer.Control = func(network, address string, c syscall.RawConn) error {
			for _, ctl := range DialerControllers() {
				if err := ctl(network, address, c); err != nil {
					// A socket the controller could not protect or bind
					// must not be used: it would follow the default route,
					// which may lead back into the tunnel.
					return errors.New("failed to apply external controller").Base(err)
				}
			}
			return c.Control(func(fd uintptr) {
				if sockopt != nil {
					if err := applyOutboundSocketOptions(network, address, fd, sockopt); err != nil {
						errors.LogInfoInner(ctx, err, "failed to apply socket options")
					}
				}
			})
		}
	}

	return dialer.DialContext(ctx, dest.Network.SystemString(), dest.NetAddr())
}

func (d *DefaultSystemDialer) DestIpAddress() net.IP {
	return nil
}

type SystemDialerAdapter interface {
	Dial(network string, address string) (net.Conn, error)
}

type SimpleSystemDialer struct {
	adapter SystemDialerAdapter
}

func WithAdapter(dialer SystemDialerAdapter) SystemDialer {
	return &SimpleSystemDialer{
		adapter: dialer,
	}
}

func (v *SimpleSystemDialer) Dial(ctx context.Context, src net.Address, dest net.Destination, sockopt *SocketConfig) (net.Conn, error) {
	return v.adapter.Dial(dest.Network.SystemString(), dest.NetAddr())
}

func (d *SimpleSystemDialer) DestIpAddress() net.IP {
	return nil
}

// UseAlternativeSystemDialer replaces the current system dialer with a given one.
// Caller must ensure there is no race condition.
//
// xray:api:stable
func UseAlternativeSystemDialer(dialer SystemDialer) {
	if dialer == nil {
		dialer = &DefaultSystemDialer{}
	}
	effectiveSystemDialer = dialer
}

// RegisterDialerController adds a controller to the effective system dialer.
// The controller can be used to operate on file descriptors before they are put into use.
// An error from the controller aborts the dial.
// It only works when effective dialer is the default dialer.
//
// xray:api:beta
func RegisterDialerController(ctl func(network, address string, c syscall.RawConn) error) error {
	_, err := AddDialerController(ctl)
	return err
}

// AddDialerController is RegisterDialerController that also returns a function
// removing the controller again. The remove function may be called more than once.
//
// xray:api:beta
func AddDialerController(ctl func(network, address string, c syscall.RawConn) error) (remove func(), err error) {
	if ctl == nil {
		return nil, errors.New("nil listener controller")
	}
	if _, ok := effectiveSystemDialer.(*DefaultSystemDialer); !ok {
		return nil, errors.New("RegisterListenerController not supported in custom dialer")
	}

	ControllersLock.Lock()
	nextControllerID++
	id := nextControllerID
	Controllers = append(append([]func(network, address string, c syscall.RawConn) error(nil), Controllers...), ctl)
	controllerIDs = append(append([]uint64(nil), controllerIDs...), id)
	ControllersLock.Unlock()

	return func() {
		ControllersLock.Lock()
		defer ControllersLock.Unlock()
		for i, have := range controllerIDs {
			if have != id {
				continue
			}
			Controllers = append(append([]func(network, address string, c syscall.RawConn) error(nil), Controllers[:i]...), Controllers[i+1:]...)
			controllerIDs = append(append([]uint64(nil), controllerIDs[:i]...), controllerIDs[i+1:]...)
			return
		}
	}, nil
}

// DialerControllers returns the registered dialer controllers. The slice is a
// snapshot and must not be modified.
func DialerControllers() []func(network, address string, c syscall.RawConn) error {
	ControllersLock.Lock()
	defer ControllersLock.Unlock()
	return Controllers
}

// ApplyDialerControllers runs the registered dialer controllers.
// The error matches DefaultSystemDialer: the socket must not be used.
func ApplyDialerControllers(network, address string, c syscall.RawConn) error {
	for _, ctl := range DialerControllers() {
		if err := ctl(network, address, c); err != nil {
			return errors.New("failed to apply external controller").Base(err)
		}
	}
	return nil
}

type FakePacketConn struct {
	net.Conn
}

func (c *FakePacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, err = c.Read(p)
	return n, &net.UDPAddr{IP: c.Conn.RemoteAddr().(*net.TCPAddr).IP, Port: c.Conn.RemoteAddr().(*net.TCPAddr).Port}, err
}

func (c *FakePacketConn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	return c.Write(p)
}

func (c *FakePacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: []byte{0, 0, 0, 0}}
}
