package raywire

import (
	"sync"
	"testing"
	"time"
)

// seenFairCapacity is the memory of the fairness tests: 64 slots, so each client's share is 16.
const seenFairCapacity = 64

// seenHeadPair is one remembered head: its wire form and its DH output.
type seenHeadPair struct {
	re, dh []byte
}

// seenFiller remembers heads in order, each with a time that moves forward, so that the oldest
// head of a memory is the first one remembered.
type seenFiller struct {
	t    *testing.T
	s    *seenHeads
	next int
}

// add remembers the next head for client and returns it.
func (f *seenFiller) add(client []byte) seenHeadPair {
	re, dh := seenHead(f.next)
	f.s.Remember(re, dh, client, seenAt(f.next))
	f.next++
	return seenHeadPair{re, dh}
}

// clientCount returns the number of heads the memory holds for client, under the lock.
func clientCount(s *seenHeads, client []byte) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.clients[seenClientKey(client)]; c != nil {
		return c.count
	}
	return 0
}

// remembered reports whether the head is remembered by its wire key and its DH key at now.
func remembered(s *seenHeads, h seenHeadPair, now time.Time) bool {
	wire, dhSeen := rememberedBy(s, h.re, h.dh, now)
	return wire && dhSeen
}

// checkFairLocked runs checkSeenStructure under the lock, as the tests of this file need.
func checkFairLocked(t *testing.T, s *seenHeads) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	checkSeenStructure(t, s)
}

// TestSeenFairFullMemory checks the share rules with the memory full. Client B holds three heads
// and clients D1 to D3 hold a share each (3 + 3 x 16 = 51). Client D4 holds 13 more, so the memory is
// full at 64 with every client below or at its share. A flood from client A can evict only the heads
// of clients at their share, so B and D4, both below their share, keep every head at every step. The
// structure and the bound hold after each Remember. Once the three clients at share have each given
// up one head, no client is at its share, and a further head of A is not remembered.
func TestSeenFairFullMemory(t *testing.T) {
	s := newSeenHeads(seenFairCapacity, time.Hour, seenBase)
	t.Cleanup(s.Close)
	f := &seenFiller{t: t, s: s}
	bPeer, aPeer := seenPeer(100), seenPeer(200)
	var bHeads, d4Heads []seenHeadPair
	for range 3 {
		bHeads = append(bHeads, f.add(bPeer))
	}
	for d := range 3 {
		for range s.share {
			f.add(seenPeer(10 + d))
		}
	}
	for range 13 {
		d4Heads = append(d4Heads, f.add(seenPeer(104)))
	}
	if n := s.Len(); n != seenFairCapacity {
		t.Fatalf("Len() = %d before the flood, want the memory full at %d", n, seenFairCapacity)
	}
	checkFairLocked(t, s)

	var aHeads []seenHeadPair
	for i := range 200 {
		aHeads = append(aHeads, f.add(aPeer))
		now := seenAt(f.next)
		for _, h := range bHeads {
			if !remembered(s, h, now) {
				t.Fatalf("flood step %d evicted a head of B, which is below its share", i)
			}
		}
		for _, h := range d4Heads {
			if !remembered(s, h, now) {
				t.Fatalf("flood step %d evicted a head of D4, which is below its share", i)
			}
		}
		if n := clientCount(s, bPeer); n != len(bHeads) {
			t.Fatalf("flood step %d: B holds %d heads, want %d", i, n, len(bHeads))
		}
		checkFairLocked(t, s)
	}

	// A took one slot from each client at share, one at a time. No client is at its share now.
	if n := clientCount(s, aPeer); n != 3 {
		t.Fatalf("A holds %d heads after the flood, want 3: one from each client at share", n)
	}
	for d := range 3 {
		if n := clientCount(s, seenPeer(10+d)); n != s.share-1 {
			t.Fatalf("client D%d holds %d heads after losing one, want %d", d+1, n, s.share-1)
		}
	}
	if last := aHeads[len(aHeads)-1]; remembered(s, last, seenAt(f.next)) {
		t.Fatal("a head of A was remembered with no client at its share and the memory full")
	}
}

// TestSeenFairFloodEvictsOwn checks that a client at its share evicts only its own heads. Client B
// holds three heads in a memory that is not full. Client A floods 200 heads. A grows to its share,
// and then each new head of A evicts A's oldest head. B keeps its heads. At every step A remembers
// exactly its newest share of heads, and the structure and the bound hold.
func TestSeenFairFloodEvictsOwn(t *testing.T) {
	s := newSeenHeads(seenFairCapacity, time.Hour, seenBase)
	t.Cleanup(s.Close)
	f := &seenFiller{t: t, s: s}
	bPeer, aPeer := seenPeer(100), seenPeer(200)
	var bHeads, aHeads []seenHeadPair
	for range 3 {
		bHeads = append(bHeads, f.add(bPeer))
	}
	for i := range 200 {
		aHeads = append(aHeads, f.add(aPeer))
		now := seenAt(f.next)
		oldestKept := max(0, len(aHeads)-s.share)
		for k, h := range aHeads {
			if want := k >= oldestKept; remembered(s, h, now) != want {
				t.Fatalf("flood step %d: A's head %d remembered %v, want %v (A keeps its newest %d)",
					i, k, !want, want, s.share)
			}
		}
		for _, h := range bHeads {
			if !remembered(s, h, now) {
				t.Fatalf("flood step %d evicted a head of B, which holds no more than its share", i)
			}
		}
		checkFairLocked(t, s)
	}
	if n := clientCount(s, aPeer); n != s.share {
		t.Fatalf("A holds %d heads, want its share %d", n, s.share)
	}
	if n := clientCount(s, bPeer); n != len(bHeads) {
		t.Fatalf("B holds %d heads, want %d", n, len(bHeads))
	}
	if n := s.Len(); n != s.share+len(bHeads) {
		t.Fatalf("Len() = %d, want A's share and B's heads: %d", n, s.share+len(bHeads))
	}
}

// TestSeenFairSameHeadNotMoved checks that a head already remembered for one client is not added
// again for another. A second client that sends the same head gets no slot, so it cannot evict
// anything with a head the memory already holds.
func TestSeenFairSameHeadNotMoved(t *testing.T) {
	s := newSeenHeads(seenFairCapacity, time.Hour, seenBase)
	t.Cleanup(s.Close)
	f := &seenFiller{t: t, s: s}
	owner, other := seenPeer(1), seenPeer(2)
	h := f.add(owner)
	s.Remember(h.re, h.dh, other, seenAt(f.next))
	if n := clientCount(s, other); n != 0 {
		t.Fatalf("the second client holds %d heads for a head it did not remember first, want 0", n)
	}
	if n := clientCount(s, owner); n != 1 {
		t.Fatalf("the owner holds %d heads, want 1", n)
	}
	checkFairLocked(t, s)
}

// TestSeenFairExpiryRemovesClients checks that heads expire from their clients in time order, and
// that a client whose heads have all expired leaves the client map and the expiry heap. Ten clients
// hold three heads each, a minute apart, and the memory expires them as the clock moves.
func TestSeenFairExpiryRemovesClients(t *testing.T) {
	const ttl = time.Hour
	s := newSeenHeads(seenFairCapacity, ttl, seenBase)
	t.Cleanup(s.Close)
	heads := make([]seenHeadPair, 0, 30)
	for i := range 30 {
		re, dh := seenHead(i)
		s.Remember(re, dh, seenPeer(i%10), seenBase.Add(time.Duration(i)*time.Minute))
		heads = append(heads, seenHeadPair{re, dh})
	}
	checkFairLocked(t, s)
	for _, at := range []time.Duration{ttl + 10*time.Minute, ttl + 25*time.Minute, ttl + 40*time.Minute} {
		now := seenBase.Add(at)
		s.SeenDH(heads[0].dh, now) // expires the heads remembered before now - ttl
		checkFairLocked(t, s)
		for i, h := range heads {
			wantSeen := !seenBase.Add(time.Duration(i) * time.Minute).Before(now.Add(-ttl))
			if got := remembered(s, h, now); got != wantSeen {
				t.Fatalf("at %v: head %d remembered %v, want %v", at, i, got, wantSeen)
			}
		}
	}
	s.SeenDH(heads[0].dh, seenBase.Add(3*ttl))
	checkFairLocked(t, s)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.n != 0 || len(s.clients) != 0 || len(s.expiry) != 0 || len(s.atShare) != 0 {
		t.Fatalf("after every head expired: %d slots, %d clients, %d in the expiry heap, %d at share; want none",
			s.n, len(s.clients), len(s.expiry), len(s.atShare))
	}
}

// TestSeenFairConcurrentRace runs flooders and small clients at once on a full memory. Four flooders
// send new heads, and two small clients hold heads that were remembered before the storm. Other
// goroutines Admit, Release and SeenDH at the same time. A small client is below its share the whole
// time, so none of its heads may be evicted, whatever the flooders do. The structure holds at the end.
// Run it under -race.
func TestSeenFairConcurrentRace(t *testing.T) {
	s := newSeenHeads(seenFairCapacity, time.Hour, seenBase)
	t.Cleanup(s.Close)
	f := &seenFiller{t: t, s: s}
	var small []seenHeadPair
	for c := range 2 {
		for range 3 {
			small = append(small, f.add(seenPeer(300+c)))
		}
	}
	for flooder := range 3 {
		for range s.share {
			f.add(seenPeer(400 + flooder))
		}
	}
	for range seenFairCapacity - f.next {
		f.add(seenPeer(403))
	}
	if n := s.Len(); n != seenFairCapacity {
		t.Fatalf("Len() = %d before the storm, want the memory full at %d", n, seenFairCapacity)
	}

	var wg sync.WaitGroup
	for flooder := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			peer := seenPeer(400 + flooder)
			for i := range 500 {
				re, dh := seenHead(100000 + flooder*10000 + i)
				now := seenBase.Add(time.Duration(flooder*500+i) * time.Millisecond)
				if s.Admit(re, now) {
					s.Release(re)
				}
				s.Remember(re, dh, peer, now)
				s.SeenDH(dh, now)
			}
		}()
	}
	for c := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 500 {
				for _, h := range small[c*3 : c*3+3] {
					if s.Admit(h.re, seenBase) {
						s.Release(h.re)
					}
					s.SeenDH(h.dh, seenBase)
				}
			}
		}()
	}
	wg.Wait()

	for _, h := range small {
		if !remembered(s, h, seenBase) {
			t.Fatal("a head of a small client, below its share, was evicted during the storm")
		}
	}
	if n := s.Len(); n > seenFairCapacity {
		t.Fatalf("Len() = %d, above the capacity %d", n, seenFairCapacity)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pending) != 0 {
		t.Fatalf("%d in-flight entries after every goroutine released its own", len(s.pending))
	}
	checkSeenStructure(t, s)
}
