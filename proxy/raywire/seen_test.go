package raywire

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/flynn/noise"
	xnet "github.com/xtls/xray-core/common/net"
	mrand "math/rand/v2"
)

// seenBase is the server clock of the memory tests. The tests give every time as an
// offset from it.
var seenBase = time.Unix(1_800_000_000, 0)

// seenHead returns a distinct wire form and DH output for index i. The memory keys only
// their bytes, so the values need not be valid points.
func seenHead(i int) (re, dh []byte) {
	re = make([]byte, hsKeyLen)
	binary.BigEndian.PutUint64(re[:8], uint64(i)+1)
	binary.BigEndian.PutUint64(re[8:16], uint64(i)*7+3)
	dh = make([]byte, hsKeyLen)
	binary.BigEndian.PutUint64(dh[:8], uint64(i)+1)
	return re, dh
}

// rememberedBy reports whether a head with wire form re is remembered by its wire key,
// and whether a head with DH output dh is seen by its DH key at now.
func rememberedBy(s *seenHeads, re, dh []byte, now time.Time) (wire, dhSeen bool) {
	s.mu.Lock()
	_, wire = s.byWire[seenWireKey(re)]
	s.mu.Unlock()
	return wire, s.SeenDH(dh, now)
}

// seenInFlight returns the number of in-flight heads of the memory.
func seenInFlight(s *seenHeads) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending)
}

// headFailCount returns the head failures that the summary has counted and not yet logged.
func headFailCount(srv *Server) int {
	srv.headFails.mu.Lock()
	defer srv.headFails.mu.Unlock()
	return srv.headFails.count
}

// stepCounts counts the server's expensive steps while a test runs.
type stepCounts struct {
	dh, elligator, canon, noise, tag int
}

// countSteps replaces the step hooks with counters, and restores them when the test ends.
// The counters are plain ints: the handshake under test runs on the test goroutine.
func countSteps(t *testing.T) *stepCounts {
	t.Helper()
	c := &stepCounts{}
	savedDH, savedEl, savedCanon, savedNoise, savedTag := dhCalls, elligatorCalls, canonCalls, noiseCalls, headTagCalls
	dhCalls = func() { c.dh++ }
	elligatorCalls = func() { c.elligator++ }
	canonCalls = func() { c.canon++ }
	noiseCalls = func() { c.noise++ }
	headTagCalls = func() { c.tag++ }
	t.Cleanup(func() {
		dhCalls, elligatorCalls, canonCalls, noiseCalls, headTagCalls = savedDH, savedEl, savedCanon, savedNoise, savedTag
	})
	return c
}

// heldProbe runs the pre-auth stage of srv on one loopback connection and sends probe
// held: the prober waits for the decoy's banner before it ends its side (exchangeHeld).
// It returns the decision, the bytes the prober read and the time from the write to the
// banner.
func heldProbe(t *testing.T, srv *Server, probe []byte) (serverErr error, got []byte, waited time.Duration) {
	t.Helper()
	server, prober := tcpPair(t)
	done := make(chan error, 1)
	go func() {
		_, err := srv.handlePreAuth(context.Background(), server, srv.pad)
		done <- err
	}()
	got, waited = exchangeHeld(t, prober, probe)
	select {
	case serverErr = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("pre-auth stage did not return")
	}
	return serverErr, got, waited
}

// heldDirect sends probe to the decoy directly, held as heldProbe holds it, and returns
// what the prober reads. A relayed probe must read the same bytes.
func heldDirect(t *testing.T, decoy *net.TCPAddr, probe []byte) []byte {
	t.Helper()
	c, err := net.DialTCP("tcp", nil, decoy)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	got, _ := exchangeHeld(t, c, probe)
	return got
}

// serveOnce runs serverHandshake on one pipe, where the peer writes probe. With drop, the
// peer closes its end after the write, so the server meets the end of the stream, or fails
// its msg2 write when the probe was a whole msg1. Without drop, the peer reads what the
// server writes. It returns what serverHandshake returned.
func serveOnce(t *testing.T, serverKey noise.DHKey, authorize func([]byte) (*Account, bool), replay *ReplayFilter, seen *seenHeads, probe []byte, drop bool) (*Conn, error) {
	t.Helper()
	return serveOnceKeys(t, serverKey, authorize, replay, seen, testHeadKeys(), probe, drop)
}

// serveOnceKeys is serveOnce with the server's head keys given, so that a test can give the
// server a previous PSK.
func serveOnceKeys(t *testing.T, serverKey noise.DHKey, authorize func([]byte) (*Account, bool), replay *ReplayFilter, seen *seenHeads, keys headKeys, probe []byte, drop bool) (*Conn, error) {
	t.Helper()
	cc, sc := net.Pipe()
	go func() {
		_, _ = cc.Write(probe)
		if drop {
			cc.Close()
			return
		}
		_, _ = io.Copy(io.Discard, cc)
	}()
	conn, err := serverHandshake(sc, serverKey, authorize, replay, seen, keys, defaultPadPolicy())
	sc.Close()
	cc.Close()
	return conn, err
}

// allowKeys returns an authorize function that accepts exactly the given client keys.
func allowKeys(keys ...noise.DHKey) func([]byte) (*Account, bool) {
	return func(pub []byte) (*Account, bool) {
		for _, k := range keys {
			if bytes.Equal(pub, k.Public) {
				return &Account{PublicKey: k.Public}, true
			}
		}
		return nil, false
	}
}

// inverseVariant returns the wire form 1/(2r) of a wire form whose bit 255 is kept. It is
// the third preimage of the same point (E2), and it decodes to the same point as wire.
func inverseVariant(wire []byte) []byte {
	body := bytes.Clone(wire)
	bit := body[31] & 0x80
	body[31] &= 0x7f
	r := new(big.Int).Mod(feFromLE(body), elliP)
	twice := new(big.Int).Lsh(r, 1)
	twice.Mod(twice, elliP)
	out := feToLE(new(big.Int).ModInverse(twice, elliP))
	out[31] |= bit
	return out
}

// negVariant returns the wire form p - r of a wire form, with bit 255 kept. It decodes to
// the same point as wire.
func negVariant(wire []byte) []byte {
	body := bytes.Clone(wire)
	bit := body[31] & 0x80
	body[31] &= 0x7f
	r := new(big.Int).Mod(feFromLE(body), elliP)
	neg := feToLE(new(big.Int).Sub(elliP, r))
	neg[31] |= bit
	return neg
}

// torsionHead returns a head with a valid tag whose R_e decodes to a torsion point. It is
// refused with reason ephemeral, after one X25519 call that fails.
func torsionHead(t *testing.T, serverKey noise.DHKey) []byte {
	t.Helper()
	for _, T := range elliTorsion {
		if T == nil {
			continue
		}
		r, ok := elligatorE(feToLE(T.u))
		if !ok {
			continue
		}
		R := wireForm(r, mrand.NewChaCha8([32]byte{9}))
		if R == nil || hasPrefix2(R) || hasPrefix4(R) {
			continue
		}
		return rawHead(testPSK, serverKey.Public, R, []byte{0x12, 0x34})
	}
	t.Fatal("no torsion point gave an encodable head")
	return nil
}

// TestSeenNilSafe checks that a nil memory keeps nothing and refuses nothing, so a server
// built by hand behaves as v3.
func TestSeenNilSafe(t *testing.T) {
	var s *seenHeads
	re, dh := seenHead(1)
	if !s.Admit(re, seenBase) {
		t.Fatal("a nil memory refused a head")
	}
	s.Release(re)
	if s.SeenDH(dh, seenBase) {
		t.Fatal("a nil memory reports a remembered head")
	}
	s.Remember(re, dh, seenPeer(0), seenBase)
	s.Close()
	if n := s.Len(); n != 0 {
		t.Fatalf("Len() = %d on a nil memory, want 0", n)
	}
}

// TestSeenAdmitHoldsInFlightUntilRelease checks the in-flight set on its own: a second
// Admit of a head that is in flight is refused, and the refusal adds no entry.
func TestSeenAdmitHoldsInFlightUntilRelease(t *testing.T) {
	s := newSeenHeads(8, time.Hour, seenBase)
	t.Cleanup(s.Close)
	re, _ := seenHead(1)
	if !s.Admit(re, seenBase) {
		t.Fatal("first Admit refused a new head")
	}
	if s.Admit(re, seenBase) {
		t.Fatal("second Admit of an in-flight head was admitted")
	}
	if n := seenInFlight(s); n != 1 {
		t.Fatalf("%d in-flight entries after a refused Admit, want 1", n)
	}
	s.Release(re)
	if n := seenInFlight(s); n != 0 {
		t.Fatalf("%d in-flight entries after Release, want 0", n)
	}
	if !s.Admit(re, seenBase) {
		t.Fatal("Admit after Release refused the head")
	}
	s.Release(re)
}

// TestSeenRememberedHeadAddsNoInFlight checks that a remembered head is refused at Admit
// without an in-flight entry, so a caller that gets false has nothing to release.
func TestSeenRememberedHeadAddsNoInFlight(t *testing.T) {
	s := newSeenHeads(8, time.Hour, seenBase)
	t.Cleanup(s.Close)
	re, dh := seenHead(1)
	s.Remember(re, dh, seenPeer(0), seenBase)
	if s.Admit(re, seenBase) {
		t.Fatal("Admit admitted a remembered head")
	}
	if n := seenInFlight(s); n != 0 {
		t.Fatalf("%d in-flight entries for a remembered head, want 0", n)
	}
}

// TestSeenEvictionAtCap is T-H1-5. The memory holds four heads, so a fifth and a sixth
// evict the two oldest, and the slots never grow. Each head has its own client, so each
// client is at its share (one slot of four) and the FIFO order of the heads is kept.
func TestSeenEvictionAtCap(t *testing.T) {
	s := newSeenHeads(4, time.Hour, seenBase)
	t.Cleanup(s.Close)
	for i := range 6 {
		re, dh := seenHead(i)
		s.Remember(re, dh, seenPeer(i), seenAt(i))
	}
	if n := s.Len(); n != 4 {
		t.Fatalf("Len() = %d, want 4", n)
	}
	if len(s.slots) != 4 || cap(s.slots) != 4 {
		t.Fatalf("slots length %d and capacity %d, want 4 and 4", len(s.slots), cap(s.slots))
	}
	for i := range 6 {
		re, dh := seenHead(i)
		wire, dhSeen := rememberedBy(s, re, dh, seenBase)
		want := i >= 2
		if wire != want || dhSeen != want {
			t.Fatalf("head %d: wire key seen %v, DH key seen %v, want %v for both", i, wire, dhSeen, want)
		}
	}
}

// TestSeenTTL is T-H1-6. A head is seen at exactly its TTL and forgotten one nanosecond
// after it. Len does not expire, so it drops only after a call that does.
func TestSeenTTL(t *testing.T) {
	const ttl = time.Hour
	s := newSeenHeads(8, ttl, seenBase)
	t.Cleanup(s.Close)
	re, dh := seenHead(1)
	s.Remember(re, dh, seenPeer(0), seenBase)
	if _, dhSeen := rememberedBy(s, re, dh, seenBase.Add(ttl)); !dhSeen {
		t.Fatal("head forgotten at exactly its TTL")
	}
	if _, dhSeen := rememberedBy(s, re, dh, seenBase.Add(ttl+time.Nanosecond)); dhSeen {
		t.Fatal("head still seen one nanosecond after its TTL")
	}
	if n := s.Len(); n != 0 {
		t.Fatalf("Len() = %d after expiry, want 0", n)
	}
}

// TestSeenNoRefreshOnRemember is T-H1-7. A second Remember of a live head adds no slot and
// does not extend the head's life.
func TestSeenNoRefreshOnRemember(t *testing.T) {
	const ttl = time.Hour
	s := newSeenHeads(8, ttl, seenBase)
	t.Cleanup(s.Close)
	re, dh := seenHead(1)
	s.Remember(re, dh, seenPeer(0), seenBase)
	s.Remember(re, dh, seenPeer(0), seenBase.Add(ttl/2))
	if n := s.Len(); n != 1 {
		t.Fatalf("Len() = %d after a second Remember, want 1", n)
	}
	if _, dhSeen := rememberedBy(s, re, dh, seenBase.Add(ttl+time.Nanosecond)); dhSeen {
		t.Fatal("a second Remember extended the life of the head")
	}
}

// TestSeenIndexesOneToOne is T-H1-20. A head whose DH key is already live adds no slot,
// and after an eviction the two indexes and the count still agree.
func TestSeenIndexesOneToOne(t *testing.T) {
	s := newSeenHeads(3, time.Hour, seenBase)
	t.Cleanup(s.Close)
	reA, dhA := seenHead(0)
	s.Remember(reA, dhA, seenPeer(0), seenAt(0))

	// A second wire form of the same point: a different R_e and the same DH output.
	reA2, _ := seenHead(100)
	s.Remember(reA2, dhA, seenPeer(0), seenBase)
	if n := s.Len(); n != 1 {
		t.Fatalf("Len() = %d after a head with a live DH key, want 1", n)
	}
	s.mu.Lock()
	byWire, byDH := len(s.byWire), len(s.byDH)
	s.mu.Unlock()
	if byWire != 1 || byDH != 1 {
		t.Fatalf("indexes hold %d wire and %d DH keys, want 1 and 1", byWire, byDH)
	}

	for i := 1; i <= 2; i++ {
		re, dh := seenHead(i)
		s.Remember(re, dh, seenPeer(i), seenAt(i))
	}
	re, dh := seenHead(3)
	s.Remember(re, dh, seenPeer(3), seenAt(3)) // evicts the oldest, head A, a client at its share

	if wire, dhSeen := rememberedBy(s, reA, dhA, seenBase); wire || dhSeen {
		t.Fatalf("evicted head is still seen: wire %v, DH %v", wire, dhSeen)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.n != 3 || len(s.byWire) != 3 || len(s.byDH) != 3 {
		t.Fatalf("after eviction n=%d, wire keys %d, DH keys %d; want 3, 3, 3", s.n, len(s.byWire), len(s.byDH))
	}
}

// TestSeenConcurrentRace is T-H1-8. Many goroutines use overlapping keys, with eviction
// and expiry, and the memory stays consistent. Eight clients are shared by the workers, so
// the shares are reached and the victims of the shares are taken. Run it under -race.
func TestSeenConcurrentRace(t *testing.T) {
	const capacity, workers, rounds = 256, 64, 2000
	s := newSeenHeads(capacity, 50*time.Microsecond, seenBase)
	t.Cleanup(s.Close)

	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			peer := seenPeer(w % 8)
			for i := range rounds {
				re, dh := seenHead((w*7 + i) % 700)
				now := seenBase.Add(time.Duration(i) * time.Microsecond)
				if s.Admit(re, now) {
					s.Release(re)
				}
				if i%3 == 0 {
					s.Remember(re, dh, peer, now)
				}
				s.SeenDH(dh, now)
			}
		}()
	}
	wg.Wait()

	if n := s.Len(); n > capacity {
		t.Fatalf("Len() = %d, above the capacity %d", n, capacity)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pending) != 0 {
		t.Fatalf("%d in-flight entries after every goroutine released its own", len(s.pending))
	}
	checkSeenStructure(t, s)
}

// seenAt is the time of the i-th Remember in a test that fills the memory. The clock moves, as the
// server's does, so the heads have distinct times and the oldest is the first remembered.
func seenAt(i int) time.Time {
	return seenBase.Add(time.Duration(i) * time.Millisecond)
}

// seenPeer returns the static key of client i. The memory keys a client by this key, so
// clients i and j are the same client only when i == j.
func seenPeer(i int) []byte {
	p := make([]byte, hsKeyLen)
	binary.BigEndian.PutUint64(p[:8], uint64(i)+1)
	binary.BigEndian.PutUint64(p[8:16], 0x5e3e5e3e5e3e5e3e)
	return p
}

// checkSeenStructure checks every invariant of the memory's data: the live slots against the
// two indexes, each client's chain from its oldest head to its newest, the expiry heap, the list
// of clients at their share, and the free list, which together hold each slot exactly once. The
// caller must hold s.mu and s must not be closed.
func checkSeenStructure(t *testing.T, s *seenHeads) {
	t.Helper()
	if s.n < 0 || s.n > s.capacity {
		t.Fatalf("%d live slots, outside 0..%d", s.n, s.capacity)
	}
	if len(s.byWire) != s.n || len(s.byDH) != s.n {
		t.Fatalf("indexes hold %d wire and %d DH keys for %d live slots", len(s.byWire), len(s.byDH), s.n)
	}
	used := make([]bool, s.capacity)
	total, shareCount := 0, 0
	for key, c := range s.clients {
		if c.key != key {
			t.Fatalf("client stored under %x has key %x", key, c.key)
		}
		if c.count < 1 || c.count > s.share {
			t.Fatalf("a client holds %d heads, want 1..%d", c.count, s.share)
		}
		total += c.count
		listed := false
		for _, o := range s.atShare {
			if o == c {
				listed = true
			}
		}
		if listed != (c.count >= s.share) {
			t.Fatalf("a client with %d heads (share %d): listed at share %v", c.count, s.share, listed)
		}
		if c.count >= s.share {
			shareCount++
		}
		if c.heapAt < 0 || c.heapAt >= len(s.expiry) || s.expiry[c.heapAt] != c {
			t.Fatalf("a client is not in the expiry heap at its index %d", c.heapAt)
		}
		i := c.oldest
		for k := range c.count {
			if i < 0 || int(i) >= s.capacity || used[i] {
				t.Fatalf("a client's chain reaches slot %d twice or out of range", i)
			}
			used[i] = true
			sl := &s.slots[i]
			if _, ok := s.byWire[sl.wire]; !ok {
				t.Fatalf("a live slot has no wire index entry")
			}
			if _, ok := s.byDH[sl.dh]; !ok {
				t.Fatalf("a live slot has no DH index entry")
			}
			if k == 0 && c.oldestAt != sl.at {
				t.Fatalf("a client's oldestAt is not its oldest head's time")
			}
			if k == c.count-1 && i != c.newest {
				t.Fatalf("a client's newest slot %d is not the end of its chain at %d", c.newest, i)
			}
			i = sl.next
		}
	}
	if total != s.n {
		t.Fatalf("clients hold %d heads, live slots %d", total, s.n)
	}
	if len(s.clients) != len(s.expiry) {
		t.Fatalf("%d clients, %d in the expiry heap", len(s.clients), len(s.expiry))
	}
	if len(s.atShare) != shareCount {
		t.Fatalf("%d clients listed at share, %d hold a share", len(s.atShare), shareCount)
	}
	for i := 1; i < len(s.expiry); i++ {
		if parent := (i - 1) / 2; s.expiry[i].oldestAt < s.expiry[parent].oldestAt {
			t.Fatalf("the expiry heap is out of order at index %d", i)
		}
	}
	free := 0
	for i := s.free; i >= 0; i = s.slots[i].next {
		if free >= s.capacity || used[i] {
			t.Fatalf("the free list reaches slot %d twice or holds a live slot", i)
		}
		used[i] = true
		free++
	}
	if free != s.capacity-s.n {
		t.Fatalf("%d free slots, want %d", free, s.capacity-s.n)
	}
	for i, u := range used {
		if !u {
			t.Fatalf("slot %d is neither live nor free", i)
		}
	}
}

// TestSeenClosedReleasesMemory is T-H1-9. After Close the memory keeps nothing, and every
// map and the ring are nil.
func TestSeenClosedReleasesMemory(t *testing.T) {
	s := newSeenHeads(8, time.Hour, seenBase)
	re, dh := seenHead(1)
	s.Remember(re, dh, seenPeer(0), seenBase)
	s.Close()

	re2, dh2 := seenHead(2)
	if !s.Admit(re2, seenBase) {
		t.Fatal("a closed memory refused a head")
	}
	if s.SeenDH(dh, seenBase) {
		t.Fatal("a closed memory reports a remembered head")
	}
	s.Remember(re2, dh2, seenPeer(0), seenBase)
	s.Release(re2)
	if s.Len() != 0 {
		t.Fatalf("Len() = %d after Close, want 0", s.Len())
	}
	if s.slots != nil || s.clients != nil || s.byWire != nil || s.byDH != nil || s.pending != nil {
		t.Fatal("Close kept the slots, the clients or an index")
	}
}

// TestServerCloseReleasesSeenMemory checks that Server.Close releases the memory of
// remembered heads, as the summary and the expiry timer are released.
func TestServerCloseReleasesSeenMemory(t *testing.T) {
	srv := newProbeServer(t, xnet.Destination{}, newKey(t))
	re, dh := seenHead(1)
	srv.seen.Remember(re, dh, seenPeer(0), handshakeClock())
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	if srv.seen.slots != nil || srv.seen.byWire != nil || srv.seen.byDH != nil {
		t.Fatal("Server.Close did not release the seen memory")
	}
}

// TestSeenMemoryAtCap is T-H1-21. The heap of a memory filled to seenHeadCap is logged for
// BENCH.txt and bounded. Two fills are measured. Four clients at their share is the realistic
// fill, and it must stay under 8 MiB, the bound of T-H1-21. One head per client is the worst case:
// each client keeps a record, so the heap is larger, about 14.4 MiB measured. The 16 MiB bound on
// that fill is a regression guard, not the 8 MiB of the spec, and the claim of about 7.5 MiB per
// inbound in seen.go holds only for the realistic fill.
func TestSeenMemoryAtCap(t *testing.T) {
	for _, fill := range []struct {
		name    string
		clients int
		limit   int64
	}{
		{"four clients at their share", 4, 8 << 20},
		{"one head per client", seenHeadCap, 16 << 20},
	} {
		t.Run(fill.name, func(t *testing.T) {
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			s := newSeenHeads(seenHeadCap, seenHeadTTL, seenBase)
			perClient := seenHeadCap / fill.clients
			for i := range seenHeadCap {
				re, dh := seenHead(i)
				s.Remember(re, dh, seenPeer(i/perClient), seenAt(i))
			}
			runtime.GC()
			runtime.ReadMemStats(&after)
			if n := s.Len(); n != seenHeadCap {
				t.Fatalf("Len() = %d at the cap, want %d", n, seenHeadCap)
			}
			used := int64(after.HeapAlloc) - int64(before.HeapAlloc)
			t.Logf("seen memory at cap %d, %s: %d bytes of heap (%.2f MiB)", seenHeadCap, fill.name, used, float64(used)/(1<<20))
			if used > fill.limit {
				t.Fatalf("seen memory at cap uses %d bytes, want at most %d", used, fill.limit)
			}
			runtime.KeepAlive(s)
		})
	}
}

// TestSeenReasonNotCounted is T-H1-10. A remembered head is refused with ErrReplay, and the
// head-failure summary does not count it.
func TestSeenReasonNotCounted(t *testing.T) {
	clientKey := newKey(t)
	srv := newProbeServer(t, xnet.Destination{}, clientKey)
	msg1 := recordMsg1(t, clientKey, srv.privateKey.Public, time.Now())
	acceptFirst(t, srv, msg1)

	o := probeViaServer(t, srv, msg1)
	if reason := reasonOf(o.serverErr); reason != "seen" {
		t.Fatalf("decision = %v, want reason seen", o.serverErr)
	}
	if !errors.Is(o.serverErr, ErrReplay) {
		t.Fatalf("decision %v does not wrap ErrReplay", o.serverErr)
	}
	if n := headFailCount(srv); n != 0 {
		t.Fatalf("a seen decision was counted as %d head failures", n)
	}
}

// TestSeenReplayedMsg1RelayedAtOnce is T-H1-1. A complete msg1 that was accepted is sent
// again. The server answers at byte 50 with no key work, and the decoy receives every byte.
func TestSeenReplayedMsg1RelayedAtOnce(t *testing.T) {
	setPreAuthTimeout(t, 5*time.Second)
	decoy := startBannerDecoy(t)
	clientKey := newKey(t)
	srv := newProbeServer(t, xnet.DestinationFromAddr(decoy), clientKey)
	msg1 := recordMsg1(t, clientKey, srv.privateKey.Public, time.Now())
	acceptFirst(t, srv, msg1)

	c := countSteps(t)
	err, got, waited := heldProbe(t, srv, msg1)
	he, ok := err.(*HandshakeError)
	if !ok || he.Reason != "seen" {
		t.Fatalf("decision = %v, want reason seen", err)
	}
	if len(he.Consumed) != hsHeadLen {
		t.Fatalf("decided after %d bytes, want %d", len(he.Consumed), hsHeadLen)
	}
	if waited > time.Second {
		t.Fatalf("decoy answered after %v, want at once", waited)
	}
	if c.dh != 0 || c.elligator != 0 || c.canon != 0 || c.noise != 0 {
		t.Fatalf("key work for a remembered msg1: dh %d, elligator %d, canon %d, noise %d",
			c.dh, c.elligator, c.canon, c.noise)
	}
	if want := heldDirect(t, decoy, msg1); !bytes.Equal(got, want) {
		t.Fatalf("prober read %q through raywire, %q direct", got, want)
	}
}

// TestSeenHeadRelayedAtByte50 is T-H1-2. The 50-byte head of an accepted msg1, sent alone,
// is answered at once and not at the 5 s budget.
func TestSeenHeadRelayedAtByte50(t *testing.T) {
	setPreAuthTimeout(t, 5*time.Second)
	decoy := startBannerDecoy(t)
	clientKey := newKey(t)
	srv := newProbeServer(t, xnet.DestinationFromAddr(decoy), clientKey)
	msg1 := recordMsg1(t, clientKey, srv.privateKey.Public, time.Now())
	acceptFirst(t, srv, msg1)

	c := countSteps(t)
	err, got, waited := heldProbe(t, srv, msg1[:hsHeadLen])
	if reason := reasonOf(err); reason != "seen" {
		t.Fatalf("decision = %v, want reason seen", err)
	}
	if waited > time.Second {
		t.Fatalf("decoy answered after %v, want at once (budget 5 s)", waited)
	}
	if c.dh != 0 || c.elligator != 0 || c.canon != 0 || c.noise != 0 {
		t.Fatalf("key work for a remembered head: dh %d, elligator %d, canon %d, noise %d",
			c.dh, c.elligator, c.canon, c.noise)
	}
	if want := heldDirect(t, decoy, msg1[:hsHeadLen]); !bytes.Equal(got, want) {
		t.Fatalf("prober read %q through raywire, %q direct", got, want)
	}
}

// TestSeenHeadNotRememberedBeforeSuccess is T-H1-3. A head whose handshake fails after the
// tag is not remembered. Sent alone afterwards, it takes the old path: the DH runs and the
// server waits for the rest of msg1 until the budget ends.
func TestSeenHeadNotRememberedBeforeSuccess(t *testing.T) {
	setPreAuthTimeout(t, 300*time.Millisecond)
	decoy := startBannerDecoy(t)
	clientKey := newKey(t)
	now := time.Now()

	cases := []struct {
		name          string
		build         func(srv *Server) []byte // the full msg1 whose handshake fails
		wantFirst     string
		clientAllowed bool // whether the test client is an authorized key
	}{
		{name: "authorize refuses the key", wantFirst: "unauthorized", clientAllowed: false,
			build: func(srv *Server) []byte { return recordMsg1(t, clientKey, srv.privateKey.Public, now) }},
		{name: "timestamp out of skew", wantFirst: "replay", clientAllowed: true,
			build: func(srv *Server) []byte {
				return recordMsg1(t, clientKey, srv.privateKey.Public, now.Add(-10*time.Minute))
			}},
		{name: "Noise payload corrupted behind a valid tag", wantFirst: "noise", clientAllowed: true,
			build: func(srv *Server) []byte {
				msg := recordMsg1(t, clientKey, srv.privateKey.Public, now)
				msg[len(msg)-1] ^= 0x01
				return msg
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var srv *Server
			if tc.clientAllowed {
				srv = newProbeServer(t, xnet.DestinationFromAddr(decoy), clientKey)
			} else {
				srv = newProbeServer(t, xnet.DestinationFromAddr(decoy))
			}
			msg1 := tc.build(srv)
			o := probeViaServer(t, srv, msg1)
			if reason := reasonOf(o.serverErr); reason != tc.wantFirst {
				t.Fatalf("first attempt = %v, want reason %s", o.serverErr, tc.wantFirst)
			}
			if n := srv.seen.Len(); n != 0 {
				t.Fatalf("%d heads remembered after a failed handshake, want 0", n)
			}

			c := countSteps(t)
			err, _, _ := heldProbe(t, srv, msg1[:hsHeadLen])
			if reason := reasonOf(err); reason != "deadline" {
				t.Fatalf("second attempt, head alone = %v, want reason deadline (the old path)", err)
			}
			if c.dh != 1 {
				t.Fatalf("second attempt ran %d DH calls, want 1", c.dh)
			}
		})
	}
}

// TestSeenRememberedEvenIfMsg2Fails is T-H1-4. The msg2 write fails because the peer has
// closed. The head was authenticated, so it stays remembered (section 3.4).
func TestSeenRememberedEvenIfMsg2Fails(t *testing.T) {
	serverKey, clientKey := newKey(t), newKey(t)
	seen := newSeenHeads(seenHeadCap, seenHeadTTL, seenBase)
	t.Cleanup(seen.Close)
	msg1 := recordMsg1(t, clientKey, serverKey.Public, time.Now())
	authorize := allowKeys(clientKey)

	conn, err := serveOnce(t, serverKey, authorize, NewReplayFilter(), seen, msg1, true)
	if conn != nil {
		conn.Close()
		t.Fatal("handshake succeeded although the peer closed before msg2")
	}
	if reasonOf(err) != "" {
		t.Fatalf("error %v is a peer decision, want the msg2 write failure", err)
	}
	if n := seen.Len(); n != 1 {
		t.Fatalf("%d heads remembered after a msg2 write failure, want 1", n)
	}
	if n := seenInFlight(seen); n != 0 {
		t.Fatalf("%d in-flight entries after the failure, want 0", n)
	}

	_, err = serveOnce(t, serverKey, authorize, NewReplayFilter(), seen, msg1[:hsHeadLen], false)
	if reason := reasonOf(err); reason != "seen" {
		t.Fatalf("head alone after the msg2 failure = %v, want reason seen", err)
	}
}

// TestSeenInFlightCopyRelayedAtByte50 is T-H1-15. The original is held after its head is
// admitted, so it is in flight. A copy with the same wire form is answered at byte 50 at
// once, and the original then completes.
func TestSeenInFlightCopyRelayedAtByte50(t *testing.T) {
	setPreAuthTimeout(t, 5*time.Second)
	decoy := startBannerDecoy(t)
	clientKey := newKey(t)
	srv := newProbeServer(t, xnet.DestinationFromAddr(decoy), clientKey)
	msg1 := recordMsg1(t, clientKey, srv.privateKey.Public, time.Now())

	entered, release := make(chan struct{}), make(chan struct{})
	var once, unblockOnce sync.Once
	unblock := func() { unblockOnce.Do(func() { close(release) }) }
	saved := seenHook
	seenHook = func() {
		once.Do(func() {
			close(entered)
			<-release
		})
	}
	t.Cleanup(func() {
		unblock()
		seenHook = saved
	})

	origServer, origProber := tcpPair(t)
	origDone := make(chan error, 1)
	go func() {
		rc, err := srv.handlePreAuth(context.Background(), origServer, srv.pad)
		if rc != nil {
			rc.Close()
		}
		origDone <- err
	}()
	if _, err := origProber.Write(msg1); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the original did not reach its in-flight point")
	}

	err, got, waited := heldProbe(t, srv, msg1)
	if reason := reasonOf(err); reason != "seen" {
		t.Fatalf("copy = %v, want reason seen while the original is in flight", err)
	}
	if waited > time.Second {
		t.Fatalf("copy answered after %v, want at once", waited)
	}
	if want := heldDirect(t, decoy, msg1); !bytes.Equal(got, want) {
		t.Fatalf("copy: prober read %q through raywire, %q direct", got, want)
	}

	unblock()
	select {
	case err := <-origDone:
		if err != nil {
			t.Fatalf("original refused after the copy: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the original did not complete")
	}
}

// TestSeenCopyFirstRefusesOriginal is T-H1-16 (O-8). A copy that reaches the server first
// holds the in-flight entry until its own budget ends, so the original is refused with
// seen meanwhile. After the copy ends, a new msg1 with a new ephemeral key succeeds.
func TestSeenCopyFirstRefusesOriginal(t *testing.T) {
	setPreAuthTimeout(t, 500*time.Millisecond)
	setRelayTimers(t, 200*time.Millisecond, time.Minute)
	decoy := startBannerDecoy(t)
	clientKey := newKey(t)
	srv := newProbeServer(t, xnet.DestinationFromAddr(decoy), clientKey)
	msg1 := recordMsg1(t, clientKey, srv.privateKey.Public, time.Now())

	copyServer, copyProber := tcpPair(t)
	copyDone := make(chan error, 1)
	go func() {
		_, err := srv.handlePreAuth(context.Background(), copyServer, srv.pad)
		copyDone <- err
	}()
	if _, err := copyProber.Write(msg1[:hsHeadLen]); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)

	err, _, waited := heldProbe(t, srv, msg1)
	if reason := reasonOf(err); reason != "seen" {
		t.Fatalf("original while the copy is in flight = %v, want reason seen", err)
	}
	if waited > 300*time.Millisecond {
		t.Fatalf("original answered after %v, want at once", waited)
	}

	select {
	case err := <-copyDone:
		if reason := reasonOf(err); reason != "deadline" {
			t.Fatalf("copy ended with %v, want reason deadline", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the copy did not end at its budget")
	}

	retry := recordMsg1(t, clientKey, srv.privateKey.Public, time.Now())
	acceptFirst(t, srv, retry)
}

// TestSeenPendingReleasedOnEveryExit is T-H1-17. After each exit of serverHandshake the
// in-flight set is empty. A second attempt with the same head gets the reason of the first
// attempt, not seen, except after a success or a failed msg2 write, which remember the head.
func TestSeenPendingReleasedOnEveryExit(t *testing.T) {
	serverKey, clientKey, otherKey := newKey(t), newKey(t), newKey(t)
	authorize := allowKeys(clientKey)
	now := time.Now()
	full := recordMsg1(t, clientKey, serverKey.Public, now)

	cases := []struct {
		name       string
		probe      []byte
		drop       bool
		authorize  func([]byte) (*Account, bool)
		wantFirst  string // a decision reason, or "" when the first attempt is not a decision
		wantSecond string
		// first is "success", "msg2" (the msg2 write failed) or "decision"
		first string
	}{
		{name: "length", probe: forgedMsg1(t, serverKey, 0)[:hsHeadLen], drop: false,
			authorize: authorize, wantFirst: "length", wantSecond: "length"},
		{name: "noise", probe: forgedMsg1(t, serverKey, 72), drop: false,
			authorize: authorize, wantFirst: "noise", wantSecond: "noise"},
		{name: "unauthorized", probe: recordMsg1(t, otherKey, serverKey.Public, now), drop: false,
			authorize: authorize, wantFirst: "unauthorized", wantSecond: "unauthorized"},
		{name: "replay", probe: recordMsg1(t, clientKey, serverKey.Public, now.Add(-10*time.Minute)), drop: false,
			authorize: authorize, wantFirst: "replay", wantSecond: "replay"},
		{name: "ephemeral", probe: torsionHead(t, serverKey), drop: false,
			authorize: authorize, wantFirst: "ephemeral", wantSecond: "ephemeral"},
		{name: "read error after the head", probe: full[:hsHeadLen], drop: true,
			authorize: authorize, wantFirst: "eof", wantSecond: "eof"},
		{name: "msg2 write error", probe: full, drop: true,
			authorize: authorize, first: "msg2", wantSecond: "seen"},
		{name: "success", probe: full, drop: false,
			authorize: authorize, first: "success", wantSecond: "seen"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seen := newSeenHeads(seenHeadCap, seenHeadTTL, seenBase)
			t.Cleanup(seen.Close)

			conn, err := serveOnce(t, serverKey, tc.authorize, NewReplayFilter(), seen, tc.probe, tc.drop)
			if conn != nil {
				conn.Close()
			}
			switch tc.first {
			case "success":
				if err != nil || conn == nil {
					t.Fatalf("first attempt = %v, want a success", err)
				}
			case "msg2":
				if conn != nil || err == nil || reasonOf(err) != "" {
					t.Fatalf("first attempt = %v, want a msg2 write failure", err)
				}
			default:
				if reasonOf(err) != tc.wantFirst {
					t.Fatalf("first attempt = %v, want reason %s", err, tc.wantFirst)
				}
			}
			if n := seenInFlight(seen); n != 0 {
				t.Fatalf("%d in-flight entries after the first attempt, want 0", n)
			}

			conn, err = serveOnce(t, serverKey, tc.authorize, NewReplayFilter(), seen, tc.probe, tc.drop)
			if conn != nil {
				conn.Close()
			}
			if reason := reasonOf(err); reason != tc.wantSecond {
				t.Fatalf("second attempt = %v, want reason %s", err, tc.wantSecond)
			}
			if n := seenInFlight(seen); n != 0 {
				t.Fatalf("%d in-flight entries after the second attempt, want 0", n)
			}
		})
	}
}

// TestVariantAnsweredAtByte50 is T-H1-18. The three wire variants of an accepted head (bit
// 255 flipped, p - r and 1/(2r)) decode to the same point. Each one is refused with seen at
// byte 50, both as a full msg1 and as its 50-byte head, with no Noise run. The DH runs once
// for the two variants that miss the wire key. The bit-255 variant shares the first 16 bytes
// of R_e with the original, so the wire key catches it before any DH.
func TestVariantAnsweredAtByte50(t *testing.T) {
	fixRandomness(t)
	serverKey, clientKey := newKey(t), newKey(t)
	msg1, _ := captureHandshake(t, clientKey, serverKey, defaultPadPolicy())
	authorize := allowKeys(clientKey)
	seen := newSeenHeads(seenHeadCap, seenHeadTTL, testNow)
	t.Cleanup(seen.Close)

	conn, err := serveOnce(t, serverKey, authorize, NewReplayFilter(), seen, msg1, false)
	if err != nil {
		t.Fatalf("original refused: %v", err)
	}
	conn.Close()

	orig := msg1[:hsKeyLen]
	flipped := bytes.Clone(orig)
	flipped[31] ^= 0x80
	variants := []struct {
		name   string
		wire   []byte
		wantDH int
	}{
		{"bit 255 flipped", flipped, 0},
		{"p - r", negVariant(orig), 1},
		{"1/(2r)", inverseVariant(orig), 1},
	}
	for _, v := range variants {
		if hasPrefix2(v.wire) || hasPrefix4(v.wire) {
			t.Fatalf("%s: the variant starts with a probe prefix", v.name)
		}
		if !bytes.Equal(elligatorDecode(v.wire), elligatorDecode(orig)) {
			t.Fatalf("%s: the variant does not decode to the original point", v.name)
		}
		probe := retagged(t, msg1, serverKey, v.wire)
		for _, part := range []struct {
			name string
			b    []byte
		}{{"full msg1", probe}, {"head alone", probe[:hsHeadLen]}} {
			c := countSteps(t)
			_, err := serveOnce(t, serverKey, authorize, NewReplayFilter(), seen, part.b, false)
			he, ok := err.(*HandshakeError)
			if !ok || he.Reason != "seen" || len(he.Consumed) != hsHeadLen {
				t.Fatalf("%s, %s: decision = %v, want reason seen after %d bytes", v.name, part.name, err, hsHeadLen)
			}
			if c.noise != 0 {
				t.Fatalf("%s, %s: %d Noise runs, want 0", v.name, part.name, c.noise)
			}
			if c.dh != v.wantDH {
				t.Fatalf("%s, %s: %d DH calls, want %d", v.name, part.name, c.dh, v.wantDH)
			}
		}
	}
}

// TestVariantTorsionShiftAnsweredAtByte50 is T-H1-19. The wire form of a point shifted by a
// small-order point decodes to a different raw point. Its DH output is the same, because the
// clamped scalar kills the torsion part, so the DH key answers it at byte 50.
func TestVariantTorsionShiftAnsweredAtByte50(t *testing.T) {
	fixRandomness(t)
	serverKey, clientKey := newKey(t), newKey(t)
	msg1, _ := captureHandshake(t, clientKey, serverKey, defaultPadPolicy())
	authorize := allowKeys(clientKey)
	seen := newSeenHeads(seenHeadCap, seenHeadTTL, testNow)
	t.Cleanup(seen.Close)

	conn, err := serveOnce(t, serverKey, authorize, NewReplayFilter(), seen, msg1, false)
	if err != nil {
		t.Fatalf("original refused: %v", err)
	}
	conn.Close()

	up := elligatorDecode(msg1[:hsKeyLen])
	built := 0
	for sel := 1; sel < 8; sel++ {
		shifted := torsionShift(up, sel)
		if shifted == nil {
			continue
		}
		r, ok := elligatorE(shifted)
		if !ok {
			continue
		}
		var wire []byte
		for seed := byte(1); seed < 64 && wire == nil; seed++ {
			w := wireForm(r, mrand.NewChaCha8([32]byte{seed, 0x5e}))
			if w != nil && !hasPrefix2(w) && !hasPrefix4(w) {
				wire = w
			}
		}
		if wire == nil {
			t.Fatalf("shift %d: no wire form without a probe prefix", sel)
		}
		if !bytes.Equal(elligatorDecode(wire), shifted) {
			t.Fatalf("shift %d: the wire form does not decode to the shifted point", sel)
		}
		if !bytes.Equal(canonicalDecode(wire), canonicalDecode(msg1[:hsKeyLen])) {
			t.Fatalf("shift %d: the canonical point differs from the original", sel)
		}
		built++

		probe := retagged(t, msg1, serverKey, wire)
		c := countSteps(t)
		_, err := serveOnce(t, serverKey, authorize, NewReplayFilter(), seen, probe[:hsHeadLen], false)
		if reason := reasonOf(err); reason != "seen" {
			t.Fatalf("shift %d: decision = %v, want reason seen at byte 50", sel, err)
		}
		if c.dh != 1 || c.noise != 0 {
			t.Fatalf("shift %d: %d DH calls and %d Noise runs, want 1 and 0", sel, c.dh, c.noise)
		}
	}
	if built == 0 {
		t.Fatal("no torsion shift of the original point was encodable")
	}
	t.Logf("%d of 7 torsion shifts were encodable and answered", built)
}

// headCopyUnder returns msg1 with its head replaced by the wire form re, the length word w1 and
// the head tag built under headKey for serverPub. The rest of msg1 is kept. A holder of the PSK
// that headKey comes from can build it: the same R_e with a different W1, or the same R_e and W1
// with a tag under another valid key.
func headCopyUnder(msg1, serverPub, headKey, re, w1 []byte) []byte {
	out := append([]byte(nil), re...)
	out = append(out, w1...)
	out = append(out, refTag(headKey, serverPub, re, w1)...)
	return append(out, msg1[hsHeadLen:]...)
}

// checkRememberedCopy sends probe to a server whose memory holds the original, and checks that
// the copy is refused as seen after the head, with no DH and no Noise run. The probe is the whole
// copy of msg1 or its head alone; the server must stop at byte 50 either way.
func checkRememberedCopy(t *testing.T, name string, serverKey noise.DHKey, authorize func([]byte) (*Account, bool), seen *seenHeads, keys headKeys, probe []byte) {
	t.Helper()
	c := countSteps(t)
	_, err := serveOnceKeys(t, serverKey, authorize, NewReplayFilter(), seen, keys, probe, false)
	he, ok := err.(*HandshakeError)
	if !ok || he.Reason != "seen" || len(he.Consumed) != hsHeadLen {
		t.Fatalf("%s: decision = %v, want reason seen after %d bytes", name, err, hsHeadLen)
	}
	if c.dh != 0 || c.noise != 0 {
		t.Fatalf("%s: %d DH calls and %d Noise runs for a remembered head, want 0 and 0", name, c.dh, c.noise)
	}
}

// TestSeenRememberedW1VariantAnsweredAtByte50 covers the W1 variant of a remembered head (finding 29,
// SPEC-v3b 3.1). A PSK holder can send the same R_e with a different length word and a tag that
// verifies under the PSK. The wire key covers R_e, so the copy is refused as seen at byte 50, with no
// DH and no Noise. The two edge bits of W1 are flipped, each as the whole msg1 and as the head alone.
func TestSeenRememberedW1VariantAnsweredAtByte50(t *testing.T) {
	fixRandomness(t)
	serverKey, clientKey := newKey(t), newKey(t)
	msg1, _ := captureHandshake(t, clientKey, serverKey, defaultPadPolicy())
	authorize := allowKeys(clientKey)
	keys := testHeadKeys()
	seen := newSeenHeads(seenHeadCap, seenHeadTTL, testNow)
	t.Cleanup(seen.Close)

	conn, err := serveOnceKeys(t, serverKey, authorize, NewReplayFilter(), seen, keys, msg1, false)
	if err != nil {
		t.Fatalf("original refused: %v", err)
	}
	conn.Close()

	re := msg1[:hsKeyLen]
	w1 := msg1[hsKeyLen : hsKeyLen+2]
	variants := []struct {
		name string
		w1   []byte
	}{
		{"W1 bit 0 flipped", flipBit(w1, 0)},
		{"W1 bit 15 flipped", flipBit(w1, 15)},
	}
	for _, v := range variants {
		if bytes.Equal(v.w1, w1) {
			t.Fatalf("%s: the variant has the original W1", v.name)
		}
		probe := headCopyUnder(msg1, serverKey.Public, refHeadKey(testPSK), re, v.w1)
		checkRememberedCopy(t, v.name+", full msg1", serverKey, authorize, seen, keys, probe)
		checkRememberedCopy(t, v.name+", head alone", serverKey, authorize, seen, keys, probe[:hsHeadLen])
	}
}

// TestSeenRememberedTagVariantAnsweredAtByte50 covers the T variant of a remembered head (finding
// 29, SPEC-v3b 3.1). During the overlap a server also accepts heads under its previous PSK. The
// original is built under the current PSK and remembered. A holder of the previous PSK then sends
// the same R_e with a head built under that key: a different T that verifies, and a different W1,
// because the length mask comes from the PSK too. The wire key covers R_e, so the copy is refused as
// seen at byte 50, with no DH and no Noise. On an empty memory the same copy is not refused for its
// head, so the refusal is the memory's.
func TestSeenRememberedTagVariantAnsweredAtByte50(t *testing.T) {
	fixRandomness(t)
	serverKey, clientKey := newKey(t), newKey(t)
	msg1, _ := captureHandshake(t, clientKey, serverKey, defaultPadPolicy())
	authorize := allowKeys(clientKey)
	prevPSK := bytes.Repeat([]byte{0x44}, pskLen)
	keys, err := newHeadKeys(testPSK, prevPSK, testNow.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	seen := newSeenHeads(seenHeadCap, seenHeadTTL, testNow)
	t.Cleanup(seen.Close)

	conn, err := serveOnceKeys(t, serverKey, authorize, NewReplayFilter(), seen, keys, msg1, false)
	if err != nil {
		t.Fatalf("original refused: %v", err)
	}
	conn.Close()

	// The same R_e and remainder length, under the previous PSK: its own W1 and its own T.
	re := msg1[:hsKeyLen]
	n1 := checkHeadFormulas(t, msg1, serverKey, testPSK)
	probe := append(headWithLength(t, serverKey, prevPSK, re, n1), msg1[hsHeadLen:]...)
	if bytes.Equal(probe[hsKeyLen+2:hsHeadLen], msg1[hsKeyLen+2:hsHeadLen]) {
		t.Fatal("the copy has the original's tag; it is not a different T")
	}
	if bytes.Equal(probe[hsKeyLen:hsKeyLen+2], msg1[hsKeyLen:hsKeyLen+2]) {
		t.Fatal("the copy has the original's W1; it is not a valid head under the previous PSK")
	}
	// On an empty memory the copy passes the tag and the length. Any later refusal is not "tag" or
	// "length", so the refusal on the memory is not a head check.
	fresh, err := serveOnceKeys(t, serverKey, authorize, NewReplayFilter(), newSeenHeads(seenHeadCap, seenHeadTTL, testNow), keys, probe, false)
	t.Logf("the copy on an empty memory: %v", err)
	if err == nil {
		fresh.Close()
	} else if r := reasonOf(err); r == "tag" || r == "length" {
		t.Fatalf("the copy fails the %s check on an empty memory, so it is not a valid head: %v", r, err)
	}
	checkRememberedCopy(t, "tag under previous PSK, full msg1", serverKey, authorize, seen, keys, probe)
	checkRememberedCopy(t, "tag under previous PSK, head alone", serverKey, authorize, seen, keys, probe[:hsHeadLen])
}

// TestSeenWireKeyIsCopied checks that the memory keys are copies of the caller's buffers,
// so a reused read buffer cannot change what is remembered.
func TestSeenWireKeyIsCopied(t *testing.T) {
	s := newSeenHeads(8, time.Hour, seenBase)
	t.Cleanup(s.Close)
	re, dh := seenHead(1)
	s.Remember(re, dh, seenPeer(0), seenBase)
	for i := range re {
		re[i] = 0xff
		dh[i] = 0xff
	}
	re1, dh1 := seenHead(1)
	if wire, dhSeen := rememberedBy(s, re1, dh1, seenBase); !wire || !dhSeen {
		t.Fatal("the memory changed when the caller's buffers changed")
	}
}
