package internet

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
)

// ownResolve is set while a Windows TUN answers DNS only inside the tunnel.
// Go would otherwise look the outbound server name up on the physical
// interface's port-53 servers, which never reads the DNS static hosts.
var ownResolve atomic.Bool

// Names currently inside LookupIP. A second dial of the same name fails
// instead of asking the system resolver or waiting on itself.
var ownInFlight sync.Map

// hostsLookup is implemented by the DNS feature when it has a static hosts
// map. The bootstrap map is written only there.
type hostsLookup interface {
	LookupHosts(domain string) ([]net.IP, error)
}

// systemResolver is implemented by a DNS feature that may still query the
// host resolver for a name the hosts map did not answer.
type systemResolver interface {
	MayUseSystemResolver() bool
}

// SetOwnResolve makes a non-literal dial use the Xray DNS client instead of
// the system resolver. Static hosts are checked first. A literal address is
// not looked up. restore from the Windows TUN turns it back off.
func SetOwnResolve(on bool) {
	ownResolve.Store(on)
}

// OwnResolveEnabled reports whether SetOwnResolve is on.
func OwnResolveEnabled() bool {
	return ownResolve.Load()
}

func dialOwnResolved(ctx context.Context, src net.Address, dest net.Destination, sockopt *SocketConfig) (net.Conn, error) {
	resolved, err := applyOwnResolve(ctx, dest)
	if err != nil {
		return nil, err
	}
	return effectiveSystemDialer.Dial(ctx, src, resolved, sockopt)
}

// applyOwnResolve leaves a literal destination untouched. A domain is replaced
// with an IP from the DNS client, or the dial fails. It is never handed to
// the system dialer, which would query the physical resolver.
func applyOwnResolve(ctx context.Context, dest net.Destination) (net.Destination, error) {
	if !ownResolve.Load() || dest.Address == nil || !dest.Address.Family().IsDomain() {
		return dest, nil
	}
	domain := dest.Address.Domain()
	ip, err := lookupOwn(domain)
	if err != nil {
		return dest, errors.New("failed to resolve ", domain, " without the system resolver").Base(err)
	}
	addr := net.IPAddress(ip)
	if addr == nil {
		return dest, errors.New("invalid resolved address for ", domain)
	}
	dest.Address = addr
	errors.LogInfo(ctx, "replace destination with ", dest.String())
	return dest, nil
}

func lookupOwn(domain string) (net.IP, error) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if domain == "" {
		return nil, errors.New("empty domain name")
	}
	if dnsClient == nil {
		return nil, errors.New("DNS client not initialized")
	}
	if hosts, ok := dnsClient.(hostsLookup); ok {
		ips, err := hosts.LookupHosts(domain)
		if err != nil {
			return nil, err
		}
		if ip, ok := pickOwnIP(ips); ok {
			return ip, nil
		}
		if sys, ok := dnsClient.(systemResolver); ok && sys.MayUseSystemResolver() {
			return nil, errors.New("refusing to resolve ", domain, " via the system resolver")
		}
	} else {
		// No static hosts: this is the system resolver (localdns), or a
		// client that cannot answer without it.
		return nil, errors.New("refusing to resolve ", domain, " via the system resolver")
	}
	if _, loaded := ownInFlight.LoadOrStore(domain, struct{}{}); loaded {
		return nil, errors.New("already resolving ", domain)
	}
	defer ownInFlight.Delete(domain)

	ips, _, err := dnsClient.LookupIP(domain, dns.IPOption{IPv4Enable: true, IPv6Enable: true})
	if err != nil {
		return nil, err
	}
	if ip, ok := pickOwnIP(ips); ok {
		return ip, nil
	}
	return nil, dns.ErrEmptyResponse
}

func pickOwnIP(ips []net.IP) (net.IP, bool) {
	if len(ips) == 0 {
		return nil, false
	}
	ip := ips[dice.Roll(len(ips))]
	if len(ip) != net.IPv4len && len(ip) != net.IPv6len {
		return nil, false
	}
	return ip, true
}
