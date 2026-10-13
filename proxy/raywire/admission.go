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

// sourceKey returns the key of the per-source limits for addr. An IPv4 address,
// and an IPv4-mapped IPv6 address, is its own key. An IPv6 address is keyed by its
// /64 prefix, so one subscriber's addresses share the limit and cannot take 2^64
// keys. A zone is stripped first. An address that does not parse as an IP keeps
// its full string.
func sourceKey(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	s := addr.String()
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		return s
	}
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return s
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}
