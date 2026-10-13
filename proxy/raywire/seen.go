package raywire

import (
	"container/heap"
	"crypto/sha256"
	"sync"
	"time"
)

const (
	// seenKeyLen is the length of the keys of the seen-heads memory: a 16-byte
	// truncation of a 256-bit value. A 128-bit key keeps the collision chance per
	// legitimate handshake near N / 2^128 for N live entries.
	seenKeyLen = 16

	// seenDHLabel separates the DH key from other SHA-256 uses. It is only in memory
	// and is never on the wire.
	seenDHLabel = "raywire/3 seen dh"

	// seenClientLabel separates the client key of the memory from other SHA-256 uses.
	// It is only in memory and is never on the wire.
	seenClientLabel = "raywire/3 seen client"

	// seenHeadTTL is how long a remembered head is refused. It is far longer than
	// the replay window (replayWindow), so a head is still refused after the replay
	// filter has forgotten it.
	seenHeadTTL = 24 * time.Hour

	// seenHeadCap bounds the remembered heads, one slot each, with two keys per slot.
	// At the cap the memory is about 7.5 MiB per inbound. The horizon of a head is
	// shorter than seenHeadTTL when the memory is full, because the heads of a client
	// at its share are evicted first.
	seenHeadCap = 65536

	// seenClientDivisor sets the share of one client: a client may hold at most
	// seenHeadCap / seenClientDivisor slots, a quarter of the memory. The replay quota
	// of one client is 16384 accepted handshakes per 10 minutes (replay.go), about 27
	// a second. Without a share, one authorized key at that rate turns the whole ring
	// over in about 40 minutes and evicts the heads of every other client, which brings
	// back the stall for their captured heads. With the share, a client's new heads
	// evict only its own oldest heads once it is at its share, and a client below its
	// share is never evicted by another client's traffic.
	seenClientDivisor = 4
)

// seenSlot is one remembered head: its two keys, the time it was remembered and the
// next slot of its client, toward the newest. Free slots chain through next as well.
// The slot is 48 bytes, and that bounds the memory at the cap (see seenHeadCap).
type seenSlot struct {
	wire [seenKeyLen]byte // R_e[:16] of the head
	dh   [seenKeyLen]byte // seenDHKey of the DH output of the head
	at   time.Duration    // time of Remember, since seenHeads.base (monotonic)
	next int32            // next slot of the same client, -1 at the newest one
}

// seenClient holds the remembered heads of one client, as a FIFO from the oldest to
// the newest. oldestAt caches the time of the oldest head, which orders the expiry
// heap. heapAt is the index of the client in that heap, or -1.
type seenClient struct {
	key      [seenKeyLen]byte
	count    int
	oldest   int32
	newest   int32
	oldestAt time.Duration
	heapAt   int
}

// clientHeap is a min-heap of the clients that hold heads, ordered by the time of
// their oldest head. The head of the heap is the next client that may have expired
// heads, so expiry looks at one client when nothing has expired.
type clientHeap []*seenClient

func (h clientHeap) Len() int           { return len(h) }
func (h clientHeap) Less(i, j int) bool { return h[i].oldestAt < h[j].oldestAt }
func (h clientHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].heapAt = i
	h[j].heapAt = j
}

func (h *clientHeap) Push(x any) {
	c := x.(*seenClient)
	c.heapAt = len(*h)
	*h = append(*h, c)
}

func (h *clientHeap) Pop() any {
	old := *h
	n := len(old)
	c := old[n-1]
	old[n-1] = nil
	*h = old[:n-1]
	c.heapAt = -1
	return c
}

// seenHeads remembers the heads of accepted handshakes, and the heads that are still
// in flight, so that a copy of a head is answered at byte 50 and not after a DH and a
// wait for the rest of msg1. A nil *seenHeads keeps nothing. It is safe for concurrent
// use.
//
// The memory is fair between clients. A client holds at most share slots. At its share,
// a new head of the client replaces its oldest head. When the memory is full, a new head
// of a client below its share replaces the oldest head of a client at its share. A
// client below its share is never evicted by another client's traffic. If the memory is
// full and no client is at its share, a new head is not remembered.
type seenHeads struct {
	mu       sync.Mutex
	base     time.Time
	ttl      time.Duration
	capacity int
	share    int        // most slots one client may hold
	slots    []seenSlot // capacity slots, linked by next
	free     int32      // head of the free slots, -1 when none
	n        int        // live slots, 0 <= n <= capacity
	clients  map[[seenKeyLen]byte]*seenClient
	expiry   clientHeap                    // clients with live heads, by oldestAt
	atShare  []*seenClient                 // clients at share, at most capacity/share
	byWire   map[[seenKeyLen]byte]struct{} // wire keys of the live slots
	byDH     map[[seenKeyLen]byte]struct{} // DH keys of the live slots
	pending  map[[seenKeyLen]byte]struct{} // wire keys of admitted handshakes not yet released
	closed   bool
}

// newSeenHeads returns an empty memory that holds at most capacity heads for ttl. Its
// clock starts at now. All maps and the slots are allocated here, so no write can reach
// a nil map.
func newSeenHeads(capacity int, ttl time.Duration, now time.Time) *seenHeads {
	if capacity < 1 {
		capacity = 1
	}
	share := capacity / seenClientDivisor
	if share < 1 {
		share = 1
	}
	s := &seenHeads{
		base:     now,
		ttl:      ttl,
		capacity: capacity,
		share:    share,
		slots:    make([]seenSlot, capacity),
		free:     0,
		clients:  make(map[[seenKeyLen]byte]*seenClient),
		byWire:   make(map[[seenKeyLen]byte]struct{}, capacity),
		byDH:     make(map[[seenKeyLen]byte]struct{}, capacity),
		pending:  make(map[[seenKeyLen]byte]struct{}, maxPendingHandshakes),
	}
	for i := range s.slots {
		s.slots[i].next = int32(i + 1)
	}
	s.slots[capacity-1].next = -1
	return s
}

// seenWireKey returns the wire key of a head: the first 16 bytes of its wire form R_e.
// The key is a copy, so it does not alias the caller's buffer.
func seenWireKey(re []byte) [seenKeyLen]byte {
	var k [seenKeyLen]byte
	copy(k[:], re)
	return k
}

// seenDHKey returns the DH key of a head: the first 16 bytes of SHA-256 of the label and
// the DH output. The DH output is the same for every wire form that decodes to the same
// point, so the key also covers the variants of a head.
func seenDHKey(dh []byte) [seenKeyLen]byte {
	h := sha256.New()
	h.Write([]byte(seenDHLabel))
	h.Write(dh)
	var k [seenKeyLen]byte
	copy(k[:], h.Sum(nil))
	return k
}

// seenClientKey returns the key of a client in the memory: the first 16 bytes of
// SHA-256 of the label and the client's static public key. The key is the same for
// every head of the client.
func seenClientKey(client []byte) [seenKeyLen]byte {
	h := sha256.New()
	h.Write([]byte(seenClientLabel))
	h.Write(client)
	var k [seenKeyLen]byte
	copy(k[:], h.Sum(nil))
	return k
}

// Admit is step S6a. It returns false when the head is remembered or in flight, and
// then the caller must not call Release. It returns true when the caller now owns a
// pending entry for re, and it must call Release on every exit. Admit only marks the
// head as in flight. A head is remembered only by Remember, after a successful
// handshake.
func (s *seenHeads) Admit(re []byte, now time.Time) bool {
	if s == nil {
		return true
	}
	k := seenWireKey(re)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return true
	}
	s.expireLocked(now)
	if _, ok := s.byWire[k]; ok {
		return false
	}
	if _, ok := s.pending[k]; ok {
		return false
	}
	s.pending[k] = struct{}{}
	return true
}

// Release gives back the pending entry that Admit made for re. After Close the pending
// map is nil, and the delete does nothing.
func (s *seenHeads) Release(re []byte) {
	if s == nil {
		return
	}
	k := seenWireKey(re)
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pending, k)
}

// SeenDH is step S7a. It reports whether a head with this DH output is remembered.
func (s *seenHeads) SeenDH(dh []byte, now time.Time) bool {
	if s == nil {
		return false
	}
	k := seenDHKey(dh)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.expireLocked(now)
	_, ok := s.byDH[k]
	return ok
}

// Remember records a head whose handshake fully succeeded (S14a), for the client whose
// static public key is client. A head that is already remembered, by either key, is not
// added again and is not refreshed. The share rules are described on seenHeads: a client
// at its share replaces its own oldest head, and a full memory evicts the oldest head of
// a client at its share. When no client is at its share and the memory is full, the head
// is not remembered.
func (s *seenHeads) Remember(re, dh, client []byte, now time.Time) {
	if s == nil {
		return
	}
	kw, kd, kc := seenWireKey(re), seenDHKey(dh), seenClientKey(client)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.expireLocked(now)
	if _, ok := s.byWire[kw]; ok {
		return
	}
	if _, ok := s.byDH[kd]; ok {
		return
	}
	if c := s.clients[kc]; c != nil && c.count >= s.share {
		// At its share, the client's new head replaces its own oldest head.
		s.removeOldestLocked(c)
	} else if s.n == s.capacity {
		// The memory is full and the client is below its share, so only the oldest head
		// of a client at its share may go.
		victim := s.victimLocked()
		if victim == nil {
			return
		}
		s.removeOldestLocked(victim)
	}
	// A removal can drop the client to no heads, which removes it from the map, so the
	// client is looked up again here.
	c := s.clients[kc]
	if c == nil {
		c = &seenClient{key: kc, oldest: -1, newest: -1, heapAt: -1}
		s.clients[kc] = c
	}
	s.insertLocked(c, kw, kd, now)
}

// victimLocked returns the client at its share whose oldest head is the oldest of all
// clients at their share. It returns nil when no client is at its share. There are at
// most capacity/share such clients, so the scan is constant.
func (s *seenHeads) victimLocked() *seenClient {
	var victim *seenClient
	for _, c := range s.atShare {
		if victim == nil || c.oldestAt < victim.oldestAt {
			victim = c
		}
	}
	return victim
}

// insertLocked stores a new head of client c. The caller must have made a free slot
// available, and must hold mu.
func (s *seenHeads) insertLocked(c *seenClient, kw, kd [seenKeyLen]byte, now time.Time) {
	i := s.free
	sl := &s.slots[i]
	s.free = sl.next
	at := now.Sub(s.base)
	*sl = seenSlot{wire: kw, dh: kd, at: at, next: -1}
	if c.count == 0 {
		c.oldest, c.oldestAt = i, at
		heap.Push(&s.expiry, c)
	} else {
		s.slots[c.newest].next = i
	}
	c.newest = i
	c.count++
	if c.count == s.share {
		s.atShare = append(s.atShare, c)
	}
	s.byWire[kw] = struct{}{}
	s.byDH[kd] = struct{}{}
	s.n++
}

// removeOldestLocked forgets the oldest head of client c and frees its slot. It serves
// expiry, the per-client eviction at share and the eviction of a client at its share. The
// caller must hold mu, and c must hold at least one head.
func (s *seenHeads) removeOldestLocked(c *seenClient) {
	i := c.oldest
	sl := &s.slots[i]
	next := sl.next
	delete(s.byWire, sl.wire)
	delete(s.byDH, sl.dh)
	wasAtShare := c.count >= s.share
	c.count--
	if wasAtShare && c.count < s.share {
		s.dropAtShareLocked(c)
	}
	*sl = seenSlot{next: s.free}
	s.free = i
	s.n--
	if c.count == 0 {
		heap.Remove(&s.expiry, c.heapAt)
		c.oldest, c.newest = -1, -1
		delete(s.clients, c.key)
		return
	}
	c.oldest = next
	c.oldestAt = s.slots[next].at
	heap.Fix(&s.expiry, c.heapAt)
}

// dropAtShareLocked removes client c from the list of clients at their share. The caller
// must hold mu.
func (s *seenHeads) dropAtShareLocked(c *seenClient) {
	for k, o := range s.atShare {
		if o == c {
			last := len(s.atShare) - 1
			s.atShare[k] = s.atShare[last]
			s.atShare[last] = nil
			s.atShare = s.atShare[:last]
			return
		}
	}
}

// expireLocked forgets the heads remembered more than ttl before now. Each client is
// in insertion order, and the expiry heap gives the client whose oldest head is the
// oldest of all, so only the heads that have expired are touched. The caller must hold mu.
func (s *seenHeads) expireLocked(now time.Time) {
	limit := now.Sub(s.base) - s.ttl
	for len(s.expiry) > 0 && s.expiry[0].oldestAt < limit {
		s.removeOldestLocked(s.expiry[0])
	}
}

// Close releases the memory. After Close, Admit admits every head without keeping it,
// SeenDH finds nothing, and Remember and Release do nothing.
func (s *seenHeads) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.slots = nil
	s.clients = nil
	s.expiry = nil
	s.atShare = nil
	s.byWire = nil
	s.byDH = nil
	s.pending = nil
	s.n = 0
	s.free = -1
}

// Len returns the number of remembered heads. It does not expire anything, so it
// shows what the next call will see before expiry. It is for tests.
func (s *seenHeads) Len() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.n
}
