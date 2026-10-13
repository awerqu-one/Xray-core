package raywire

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testNow is the server clock used by the filter tests. It is fixed so the
// tests do not depend on the real clock.
var testNow = time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)

// newTestFilter returns a filter made an hour before testNow. Every timestamp
// that the tests use is later than that, so only the restart tests see the
// notBefore check.
func newTestFilter() *ReplayFilter {
	return newReplayFilterAt(testNow.Add(-time.Hour))
}

// testClient names the client in the filter tests that use one client.
const testClient = "alice"

// ephemeralKey returns a 32-byte key that is distinct for each n.
func ephemeralKey(n int) []byte {
	k := make([]byte, 32)
	binary.BigEndian.PutUint64(k, uint64(n))
	return k
}

func TestReplayFilterAcceptsFirstSight(t *testing.T) {
	f := newTestFilter()
	if !f.Accept(testClient, ephemeralKey(1), testNow, testNow) {
		t.Fatal("first handshake was rejected")
	}
}

func TestReplayFilterRejectsSameEphemeral(t *testing.T) {
	f := newTestFilter()
	key := ephemeralKey(1)
	if !f.Accept(testClient, key, testNow, testNow) {
		t.Fatal("first handshake was rejected")
	}

	// A fresh timestamp does not help: the key itself is the replay.
	later := testNow.Add(time.Second)
	if f.Accept(testClient, key, later, later) {
		t.Fatal("replayed ephemeral key was accepted")
	}
}

func TestReplayFilterRejectsClockSkew(t *testing.T) {
	for _, tc := range []struct {
		name string
		ts   time.Time
	}{
		{"behind", testNow.Add(-maxClockSkew - time.Nanosecond)},
		{"ahead", testNow.Add(maxClockSkew + time.Nanosecond)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newTestFilter()
			if f.Accept(testClient, ephemeralKey(1), tc.ts, testNow) {
				t.Fatal("handshake outside maxClockSkew was accepted")
			}
		})
	}
}

func TestReplayFilterClockSkewBounds(t *testing.T) {
	f := newTestFilter()

	// Exactly maxClockSkew away is still in time, in both directions.
	if !f.Accept(testClient, ephemeralKey(1), testNow.Add(-maxClockSkew), testNow) {
		t.Fatal("handshake exactly maxClockSkew behind was rejected")
	}
	if !f.Accept(testClient, ephemeralKey(2), testNow.Add(maxClockSkew), testNow) {
		t.Fatal("handshake exactly maxClockSkew ahead was rejected")
	}

	// A rejected timestamp leaves no entry, so the same key can still be
	// accepted later with a valid timestamp.
	key := ephemeralKey(3)
	if f.Accept(testClient, key, testNow.Add(-maxClockSkew-time.Nanosecond), testNow) {
		t.Fatal("handshake outside maxClockSkew was accepted")
	}
	if !f.Accept(testClient, key, testNow, testNow) {
		t.Fatal("key from a rejected handshake was remembered")
	}
}

func TestReplayFilterAcceptsOutOfOrderTimestamps(t *testing.T) {
	f := newTestFilter()

	// Parallel connections from one client arrive out of order, each with its
	// own ephemeral key. Neither may block the other.
	if !f.Accept(testClient, ephemeralKey(1), testNow.Add(-100*time.Second), testNow) {
		t.Fatal("handshake with a timestamp 100 s old was rejected")
	}
	if !f.Accept(testClient, ephemeralKey(2), testNow.Add(-99*time.Second), testNow) {
		t.Fatal("handshake with a timestamp 99 s old was rejected")
	}
}

func TestReplayFilterConcurrentSameKey(t *testing.T) {
	f := newTestFilter()
	key := ephemeralKey(1)

	const workers = 16
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if f.Accept(testClient, key, testNow, testNow) {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if n := accepted.Load(); n != 1 {
		t.Fatalf("%d concurrent handshakes with one key were accepted, want 1", n)
	}
}

func TestReplayFilterExpiresEntries(t *testing.T) {
	f := newTestFilter()
	key := ephemeralKey(1)
	if !f.Accept(testClient, key, testNow, testNow) {
		t.Fatal("first handshake was rejected")
	}

	// At the edge of the window the key is still remembered. A timestamp
	// accepted now could still pass the skew check, so the key must stay.
	edge := testNow.Add(replayWindow)
	if f.Accept(testClient, key, edge, edge) {
		t.Fatal("key was forgotten at the edge of the replay window")
	}

	// Past the window the key is forgotten. The other key triggers the purge.
	past := testNow.Add(replayWindow + time.Nanosecond)
	if !f.Accept(testClient, ephemeralKey(2), past, past) {
		t.Fatal("second handshake was rejected")
	}
	if n := len(f.entries); n != 1 {
		t.Fatalf("filter holds %d entries after expiry, want 1", n)
	}
	if !f.Accept(testClient, key, past, past) {
		t.Fatal("expired key was still remembered")
	}
}

// fillFilter accepts maxReplayEntries keys at testNow, from as many clients as it
// takes to reach the global limit. Each client stays at its quota.
func fillFilter(t *testing.T, f *ReplayFilter) {
	t.Helper()
	for i := range maxReplayEntries {
		client := strconv.Itoa(i / maxReplayPerClient)
		if !f.Accept(client, ephemeralKey(i), testNow, testNow) {
			t.Fatalf("handshake %d from client %s was rejected", i, client)
		}
	}
}

func TestReplayFilterStaysBounded(t *testing.T) {
	f := newTestFilter()
	fillFilter(t, f)

	// A full filter fails closed: the new key is refused and not stored, even
	// for a client that has not reached its quota.
	if f.Accept("fifth", ephemeralKey(maxReplayEntries), testNow, testNow) {
		t.Fatal("handshake was accepted by a full filter")
	}
	if n := len(f.entries); n != maxReplayEntries {
		t.Fatalf("filter holds %d entries, want %d", n, maxReplayEntries)
	}

	// The oldest key was not evicted, so it is still refused as a replay.
	if f.Accept("0", ephemeralKey(0), testNow, testNow) {
		t.Fatal("oldest key was forgotten by a full filter")
	}
	if n := len(f.entries); n != maxReplayEntries {
		t.Fatalf("filter holds %d entries, want %d", n, maxReplayEntries)
	}
}

func TestReplayFilterRecoversAfterExpiry(t *testing.T) {
	f := newTestFilter()
	fillFilter(t, f)

	// Once the window has passed, the full filter drops its keys and accepts
	// again.
	past := testNow.Add(replayWindow + time.Nanosecond)
	if !f.Accept(testClient, ephemeralKey(maxReplayEntries), past, past) {
		t.Fatal("handshake was rejected after every key expired")
	}
	if n := len(f.entries); n != 1 {
		t.Fatalf("filter holds %d entries after expiry, want 1", n)
	}
}

// TestReplayFilterPerClientQuota checks that one client cannot fill the filter.
// alice reaches her quota, is refused after it, and bob is still accepted. Once
// the window has passed, alice's entries are released and she is accepted again.
func TestReplayFilterPerClientQuota(t *testing.T) {
	f := newTestFilter()
	for i := range maxReplayPerClient {
		if !f.Accept("alice", ephemeralKey(i), testNow, testNow) {
			t.Fatalf("alice's handshake %d was rejected before her quota", i)
		}
	}
	if f.Accept("alice", ephemeralKey(maxReplayPerClient), testNow, testNow) {
		t.Fatal("alice was accepted above her quota")
	}
	if n := f.perClient["alice"]; n != maxReplayPerClient {
		t.Fatalf("alice holds %d entries, want %d", n, maxReplayPerClient)
	}

	// A refused handshake is not stored, so the cache holds only alice's quota.
	if n := len(f.entries); n != maxReplayPerClient {
		t.Fatalf("filter holds %d entries, want %d", n, maxReplayPerClient)
	}
	if !f.Accept("bob", ephemeralKey(maxReplayPerClient+1), testNow, testNow) {
		t.Fatal("bob was refused while alice was at her quota")
	}

	past := testNow.Add(replayWindow + time.Nanosecond)
	if !f.Accept("alice", ephemeralKey(maxReplayPerClient+2), past, past) {
		t.Fatal("alice was refused after her entries expired")
	}
	if _, ok := f.perClient["bob"]; ok {
		t.Fatal("bob's count was kept after his entry expired")
	}
	if n := f.perClient["alice"]; n != 1 {
		t.Fatalf("alice holds %d entries after expiry, want 1", n)
	}
}

// TestReplayFilterQuotaIsPerClientNotPerKey checks that a client cannot get
// past its quota by changing its key, since each new key counts against it.
func TestReplayFilterQuotaIsPerClientNotPerKey(t *testing.T) {
	f := newTestFilter()
	for i := range maxReplayPerClient {
		if !f.Accept("alice", ephemeralKey(i), testNow, testNow) {
			t.Fatalf("handshake %d was rejected", i)
		}
	}
	// A replay of a key that alice already holds is refused as before, and a
	// fresh key from her is refused too.
	if f.Accept("alice", ephemeralKey(0), testNow, testNow) {
		t.Fatal("replayed key was accepted")
	}
	if f.Accept("alice", ephemeralKey(maxReplayPerClient), testNow, testNow) {
		t.Fatal("fresh key was accepted above alice's quota")
	}
}

// TestReplayFilterCanonicalKey checks that every wire form of one point is
// the same replay key. The filter is keyed by the canonical point, so a
// captured handshake cannot be replayed with a different encoding.
func TestReplayFilterCanonicalKey(t *testing.T) {
	src := ellSource(9)
	for range 200 {
		u := ellPoint(t, src)
		r, ok := elligatorE(u)
		if !ok {
			continue
		}
		neg := feToLE(new(big.Int).Sub(elliP, feFromLE(r)))

		var forms [][]byte
		for _, b := range []byte{0, 1, 2, 3, 0x80, 0x81, 0x82, 0x83} {
			forms = append(forms, wireForm(r, bytes.NewReader([]byte{b})))
			forms = append(forms, wireForm(neg, bytes.NewReader([]byte{b})))
		}
		// Bit 255 flipped on a wire form is still the same point.
		flipped := append([]byte(nil), forms[0]...)
		flipped[31] ^= 0x80
		forms = append(forms, flipped)

		f := newTestFilter()
		for i, R := range forms {
			if R == nil {
				t.Fatal("wireForm failed")
			}
			key := elligatorDecode(R)
			if !bytes.Equal(key, u) {
				t.Fatalf("wire form %x decodes to %x, want %x", R, key, u)
			}
			if i == 0 {
				if !f.Accept(testClient, key, testNow, testNow) {
					t.Fatal("first handshake was rejected")
				}
			} else if f.Accept(testClient, key, testNow, testNow) {
				t.Fatalf("wire form %d of one point was accepted twice", i)
			}
		}
	}
}

// TestReplayFilterRefusesBeforeCreation checks the notBefore check on its own.
// The timestamp is inside the skew window, so only the filter's start can refuse
// it. A timestamp at the start is still accepted.
func TestReplayFilterRefusesBeforeCreation(t *testing.T) {
	f := newReplayFilterAt(testNow)
	if f.Accept(testClient, ephemeralKey(1), testNow.Add(-time.Nanosecond), testNow) {
		t.Fatal("timestamp before the filter's start was accepted")
	}
	if n := len(f.entries); n != 0 {
		t.Fatalf("refused handshake left %d entries, want 0", n)
	}
	if !f.Accept(testClient, ephemeralKey(2), testNow, testNow) {
		t.Fatal("timestamp at the filter's start was refused")
	}
}

// TestReplayFilterRestartRefusesCapturedMessage covers a server restart. A first
// message is accepted before the restart and sent again after it, while its
// timestamp is still inside the skew window. The new filter is empty, so only
// its start can refuse the copy. A message made after the restart is accepted.
func TestReplayFilterRestartRefusesCapturedMessage(t *testing.T) {
	captured := ephemeralKey(1)
	ts := testNow.Add(-time.Second)
	if !newTestFilter().Accept(testClient, captured, ts, testNow) {
		t.Fatal("first handshake was rejected before the restart")
	}

	restarted := newReplayFilterAt(testNow)
	now := testNow.Add(2 * time.Second)
	if restarted.Accept(testClient, captured, ts, now) {
		t.Fatal("captured handshake was accepted after a restart")
	}
	if !restarted.Accept(testClient, ephemeralKey(2), now, now) {
		t.Fatal("handshake made after the restart was rejected")
	}
}

// TestNewServerStartsReplayFilterAtServerClock checks that a server's filter takes
// its start from the server's clock, the same clock that stamps the replay check.
func TestNewServerStartsReplayFilterAtServerClock(t *testing.T) {
	saved := handshakeClock
	t.Cleanup(func() { handshakeClock = saved })
	handshakeClock = func() time.Time { return testNow }

	s, err := NewServer(coreContext(t), serverConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	if !s.replay.notBefore.Equal(testNow) {
		t.Fatalf("notBefore = %v, want the server clock %v", s.replay.notBefore, testNow)
	}
}

// TestNewReplayFilterHasNoStart checks that the constructor used by tests refuses
// no timestamp for restart reasons.
func TestNewReplayFilterHasNoStart(t *testing.T) {
	if f := NewReplayFilter(); !f.notBefore.IsZero() {
		t.Fatalf("notBefore = %v, want none", f.notBefore)
	}
}
