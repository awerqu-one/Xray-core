package raywire

import (
	"net"
	"strings"
	"sync"
)

const (
	// maxPendingHandshakes bounds the connections in the pre-auth stage, from
	// accept until the decision or success. A connection holds at most about 634
	// bytes (50 bytes of head and up to 584 of msg1) plus a goroutine, so 1024
	// slots cap the buffers at about 0.65 MB. These are the FINAL.md values.
	maxPendingHandshakes = 1024

	// maxPendingPerIP bounds the pre-auth connections from one source, so that
	// one source cannot take every slot. A pre-auth connection lasts at most the
	// handshake budget, so 32 is far above what one source opens at once. This
	// is the FINAL.md value. A larger value makes a single source reach the
	// refusal much sooner, which a prober can see.
	maxPendingPerIP = 32
)

// admission limits the connections in one stage. It never blocks: a connection
// over a limit is refused at once, before it is read. A nil admission admits
// every connection. NewServer and the relay pool always set one, so nil only
// occurs in tests that build a Server by hand.
type admission struct {
	mu         sync.Mutex
	maxTotal   int
	maxPerHost int
	pending    int            // slots taken, over all hosts
	perHost    map[string]int // slots taken per host; a host with none is deleted
}

// newAdmission returns an admission with the given limits.
func newAdmission(maxTotal, maxPerHost int) *admission {
	return &admission{
		maxTotal:   maxTotal,
		maxPerHost: maxPerHost,
		perHost:    make(map[string]int),
	}
}

// TryAcquire takes a slot for a connection from host. The returned release gives
// the slot back, and further calls to it do nothing. A false result means a
// limit is full, and the caller must close the connection without reading it.
func (a *admission) TryAcquire(host string) (release func(), ok bool) {
	if a == nil {
		return func() {}, true
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.pending >= a.maxTotal || a.perHost[host] >= a.maxPerHost {
		return nil, false
	}
	a.pending++
	a.perHost[host]++

	var once sync.Once
	return func() { once.Do(func() { a.release(host) }) }, true
}

// release gives back one slot taken for host.
func (a *admission) release(host string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.pending--
	a.perHost[host]--
	if a.perHost[host] == 0 {
		delete(a.perHost, host)
	}
}

// pendingCount reports the slots in use.
func (a *admission) pendingCount() int {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.pending
}

// sourceKey returns the key of the per-source limits for addr. An IPv4 address
// is its own key. An IPv6 address that carries its host as an IPv4 (mapped,
// translated, compatible, NAT64, or Teredo) uses that IPv4, so those hosts do
// not share one bucket. Any other IPv6 address is keyed by its /64 prefix, so
// one subscriber's addresses share the limit and cannot take 2^64 keys. A zone
// is stripped before the parse. A host:port whose host is not an IP is keyed by
// that host, without the port. A string that does not split and does not parse
// keeps its full text.
func sourceKey(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	s := addr.String()
	host, _, err := net.SplitHostPort(s)
	unsplit := err != nil
	if unsplit {
		host = s
	}
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// A name has no port in its key. An unsplit string, such as "pipe", has
		// no port to drop, so it keeps the text that was given.
		if unsplit {
			return s
		}
		return host
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	if v4 := embeddedIPv4(ip); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// embeddedIPv4 returns the IPv4 host inside ip when that host is not in the top
// 64 bits. A /64 key would count every such host as one source. Other IPv6
// addresses return nil and keep the /64 key. :: and ::1 are not IPv4 hosts.
func embeddedIPv4(ip net.IP) net.IP {
	ip = ip.To16()
	if ip == nil {
		return nil
	}
	switch {
	case allZero(ip[:8]) && ip[8] == 0xff && ip[9] == 0xff && ip[10] == 0 && ip[11] == 0:
		// IPv4-translated ::ffff:0:a.b.c.d. To4 already took ::ffff:a.b.c.d.
		return net.IPv4(ip[12], ip[13], ip[14], ip[15])
	case allZero(ip[:12]):
		// Deprecated IPv4-compatible ::a.b.c.d. :: and ::1 stay on the /64 key.
		if ip[12] == 0 && ip[13] == 0 && ip[14] == 0 && ip[15] <= 1 {
			return nil
		}
		return net.IPv4(ip[12], ip[13], ip[14], ip[15])
	case ip[0] == 0x00 && ip[1] == 0x64 && ip[2] == 0xff && ip[3] == 0x9b && allZero(ip[4:12]):
		// NAT64 well-known prefix 64:ff9b::/96. The IPv4 is the last 32 bits.
		return net.IPv4(ip[12], ip[13], ip[14], ip[15])
	case ip[0] == 0x00 && ip[1] == 0x64 && ip[2] == 0xff && ip[3] == 0x9b && ip[4] == 0x00 && ip[5] == 0x01 &&
		ip[8] == 0 && allZero(ip[11:]):
		// NAT64 local-use prefix 64:ff9b:1::/48. The IPv4 is split around the
		// zero octet at bits 64-71: 16 bits, then 16 bits.
		return net.IPv4(ip[6], ip[7], ip[9], ip[10])
	case ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0 && ip[3] == 0:
		// Teredo 2001:0::/32. The client IPv4 is the last 32 bits XOR 0xffffffff.
		return net.IPv4(ip[12]^0xff, ip[13]^0xff, ip[14]^0xff, ip[15]^0xff)
	default:
		return nil
	}
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
