package tun

import (
	"context"
	stdnet "net"
	"strings"
	"testing"
	"time"

	appdns "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/common/geodata"
	xnet "github.com/xtls/xray-core/common/net"
	feature_dns "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/transport/internet"
)

var errCapturedDial = stdnet.ErrClosed

// captureDialer records the destination DialSystem was about to dial and does
// not open a socket.
type captureDialer struct {
	called bool
	dest   xnet.Destination
}

func (d *captureDialer) Dial(_ context.Context, _ xnet.Address, dest xnet.Destination, _ *internet.SocketConfig) (stdnet.Conn, error) {
	d.called = true
	d.dest = dest
	return nil, errCapturedDial
}

func (d *captureDialer) DestIpAddress() stdnet.IP { return nil }

type scriptedDNS struct {
	hosts   map[string][]stdnet.IP
	answer  []stdnet.IP
	queries int
	inner   error
	system  bool
	reenter bool
}

func (s *scriptedDNS) Type() interface{} { return feature_dns.ClientType() }
func (s *scriptedDNS) Start() error      { return nil }
func (s *scriptedDNS) Close() error      { return nil }

func (s *scriptedDNS) LookupHosts(domain string) ([]stdnet.IP, error) {
	if ips, ok := s.hosts[domain]; ok {
		return ips, nil
	}
	return nil, nil
}

func (s *scriptedDNS) MayUseSystemResolver() bool { return s.system }

func (s *scriptedDNS) LookupIP(domain string, _ feature_dns.IPOption) ([]stdnet.IP, uint32, error) {
	s.queries++
	if s.reenter {
		_, s.inner = internet.DialSystem(context.Background(), xnet.TCPDestination(xnet.DomainAddress(domain), 443), nil)
	}
	if s.system {
		return nil, 0, stdnet.ErrClosed
	}
	if len(s.answer) == 0 {
		return nil, 0, feature_dns.ErrEmptyResponse
	}
	return s.answer, 1, nil
}

func useOwnDial(t *testing.T, client feature_dns.Client, on bool) *captureDialer {
	t.Helper()
	dialer := &captureDialer{}
	internet.InitSystemDialer(client, nil)
	internet.UseAlternativeSystemDialer(dialer)
	internet.SetOwnResolve(on)
	t.Cleanup(func() {
		internet.SetOwnResolve(false)
		internet.UseAlternativeSystemDialer(nil)
		internet.InitSystemDialer(nil, nil)
	})
	return dialer
}

func bootstrapDNS(t *testing.T) *appdns.DNS {
	t.Helper()
	server, err := appdns.New(context.Background(), &appdns.Config{
		StaticHosts: []*appdns.Config_HostMapping{
			{
				Domain: &geodata.DomainRule{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Full, Value: "vpn.example"}}},
				Ip:     [][]byte{{203, 0, 113, 10}},
			},
			{
				Domain: &geodata.DomainRule{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Full, Value: "vpn6.example"}}},
				Ip:     [][]byte{stdnet.ParseIP("2001:db8::10").To16()},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !server.MayUseSystemResolver() {
		t.Fatal("DNS with no name server should fall back to the system resolver")
	}
	return server
}

func requireDialIP(t *testing.T, d *captureDialer, want string, port xnet.Port) {
	t.Helper()
	if !d.called {
		t.Fatal("destination was not dialed")
	}
	if d.dest.Address == nil || !d.dest.Address.Family().IsIP() {
		t.Fatalf("dialed %v, want an IP", d.dest)
	}
	if !d.dest.Address.IP().Equal(stdnet.ParseIP(want)) {
		t.Fatalf("dialed %v, want %s", d.dest.Address, want)
	}
	if d.dest.Port != port {
		t.Fatalf("port = %v, want %v", d.dest.Port, port)
	}
}

// TestOwnResolveUsesBootstrapHosts checks that, once own-resolve is on, a
// non-literal server name is taken from dns.hosts or the DNS client and is
// not passed to the system dialer. A literal address is not looked up.
func TestOwnResolveUsesBootstrapHosts(t *testing.T) {
	server := bootstrapDNS(t)

	t.Run("off leaves the domain", func(t *testing.T) {
		dialer := useOwnDial(t, server, false)
		_, err := internet.DialSystem(context.Background(), xnet.TCPDestination(xnet.DomainAddress("vpn.example"), 443), nil)
		if err != errCapturedDial {
			t.Fatal(err)
		}
		if !dialer.called || !dialer.dest.Address.Family().IsDomain() || dialer.dest.Address.Domain() != "vpn.example" {
			t.Fatalf("dialed %v", dialer.dest)
		}
	})

	t.Run("hosts map", func(t *testing.T) {
		dialer := useOwnDial(t, server, true)
		for _, sockopt := range []*internet.SocketConfig{nil, {}} {
			dialer.called = false
			_, err := internet.DialSystem(context.Background(), xnet.TCPDestination(xnet.DomainAddress("VPN.Example."), 443), sockopt)
			if err != errCapturedDial {
				t.Fatal(err)
			}
			requireDialIP(t, dialer, "203.0.113.10", 443)
		}
		_, err := internet.DialSystem(context.Background(), xnet.UDPDestination(xnet.DomainAddress("vpn6.example"), 2408), nil)
		if err != errCapturedDial {
			t.Fatal(err)
		}
		requireDialIP(t, dialer, "2001:db8::10", 2408)
		if dialer.dest.Network != xnet.Network_UDP {
			t.Fatalf("network = %v", dialer.dest.Network)
		}
	})

	t.Run("literal is not queried", func(t *testing.T) {
		client := &scriptedDNS{system: true}
		dialer := useOwnDial(t, client, true)
		for _, addr := range []string{"203.0.113.50", "2001:db8::50"} {
			dialer.called = false
			dest := xnet.TCPDestination(xnet.ParseAddress(addr), 8443)
			_, err := internet.DialSystem(context.Background(), dest, nil)
			if err != errCapturedDial {
				t.Fatal(err)
			}
			requireDialIP(t, dialer, addr, 8443)
			if client.queries != 0 {
				t.Fatalf("literal %s was looked up", addr)
			}
		}
	})

	t.Run("unmapped name does not use the system resolver", func(t *testing.T) {
		dialer := useOwnDial(t, server, true)
		done := make(chan error, 1)
		go func() {
			_, err := internet.DialSystem(context.Background(), xnet.TCPDestination(xnet.DomainAddress("other.example"), 443), nil)
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), "system resolver") {
				t.Fatalf("err = %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("unmapped name waited on a resolver")
		}
		if dialer.called {
			t.Fatalf("system dialer was used for %v", dialer.dest)
		}
	})

	t.Run("dns client when it is not the system resolver", func(t *testing.T) {
		client := &scriptedDNS{answer: []stdnet.IP{stdnet.ParseIP("203.0.113.20")}}
		dialer := useOwnDial(t, client, true)
		_, err := internet.DialSystem(context.Background(), xnet.TCPDestination(xnet.DomainAddress("vpn.example"), 443), nil)
		if err != errCapturedDial {
			t.Fatal(err)
		}
		requireDialIP(t, dialer, "203.0.113.20", 443)
		if client.queries != 1 {
			t.Fatalf("queries = %d, want 1", client.queries)
		}
	})

	t.Run("hosts win over the dns client", func(t *testing.T) {
		client := &scriptedDNS{
			hosts:  map[string][]stdnet.IP{"vpn.example": {stdnet.ParseIP("203.0.113.10")}},
			answer: []stdnet.IP{stdnet.ParseIP("198.51.100.1")},
		}
		dialer := useOwnDial(t, client, true)
		_, err := internet.DialSystem(context.Background(), xnet.TCPDestination(xnet.DomainAddress("vpn.example"), 443), nil)
		if err != errCapturedDial {
			t.Fatal(err)
		}
		requireDialIP(t, dialer, "203.0.113.10", 443)
		if client.queries != 0 {
			t.Fatalf("hosts miss fell through to LookupIP (%d)", client.queries)
		}
	})

	t.Run("reentry does not query again", func(t *testing.T) {
		client := &scriptedDNS{answer: []stdnet.IP{stdnet.ParseIP("203.0.113.20")}, reenter: true}
		dialer := useOwnDial(t, client, true)
		_, err := internet.DialSystem(context.Background(), xnet.TCPDestination(xnet.DomainAddress("vpn.example"), 443), nil)
		if err != errCapturedDial {
			t.Fatal(err)
		}
		requireDialIP(t, dialer, "203.0.113.20", 443)
		if client.queries != 1 {
			t.Fatalf("queries = %d, want 1", client.queries)
		}
		if client.inner == nil || !strings.Contains(client.inner.Error(), "already resolving") {
			t.Fatalf("inner = %v", client.inner)
		}
	})
}
