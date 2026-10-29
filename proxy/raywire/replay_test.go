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

// TestReplayFilterClockStepBackAcceptsFreshRealTimeHandshake checks that a
// client whose clock tracks real time is accepted after the server clock steps
// backward. The client timestamp is still at or after notBefore.
func TestReplayFilterClockStepBackAcceptsFreshRealTimeHandshake(t *testing.T) {
	f := newReplayFilterAt(testNow)
	stepped := testNow.Add(-30 * time.Second)
	fresh := testNow.Add(time.Second)
	if !f.Accept(testClient, ephemeralKey(9), fresh, stepped) {
		t.Fatal("a backward clock step refused a fresh real-time handshake")
	}
}

// TestReplayFilterBackwardStepExpiresWallOldEntries checks a key accepted after
// the wall clock steps backward. That key's window is its own wall time, so it
// is forgotten while a key accepted earlier, at a later wall time, is kept.
func TestReplayFilterBackwardStepExpiresWallOldEntries(t *testing.T) {
	f := NewReplayFilter()
	if !f.Accept(testClient, ephemeralKey(1), testNow, testNow) {
		t.Fatal("first handshake was rejected")
	}
	stepped := testNow.Add(-3 * replayWindow)
	if !f.Accept(testClient, ephemeralKey(2), stepped, stepped) {
		t.Fatal("handshake after a backward step was rejected")
	}

	// The stepped key is replayWindow+1ns old. The earlier key is still inside
	// its window because its wall time is ahead of the stepped clock.
	now := stepped.Add(replayWindow + time.Nanosecond)
	if !f.Accept(testClient, ephemeralKey(3), now, now) {
		t.Fatal("handshake was rejected while a wall-old entry should have expired")
	}
	if _, ok := f.entries[string(ephemeralKey(2))]; ok {
		t.Fatal("key accepted after the step was kept past its window")
	}
	if _, ok := f.entries[string(ephemeralKey(1))]; !ok {
		t.Fatal("key from before the step was dropped inside its window")
	}
	if !f.Accept(testClient, ephemeralKey(2), now, now) {
		t.Fatal("expired key was still remembered")
	}
	if f.Accept(testClient, ephemeralKey(1), now, now) {
		t.Fatal("key still inside its window was forgotten")
	}
}

// TestReplayFilterBackwardStepDoesNotExhaustQuota checks that entries accepted
// after a backward step are not charged to a client for the whole step. Once
// their own window has passed, the client can handshake again. The key accepted
// before the step is still a replay.
func TestReplayFilterBackwardStepDoesNotExhaustQuota(t *testing.T) {
	f := NewReplayFilter()
	if !f.Accept("alice", ephemeralKey(0), testNow, testNow) {
		t.Fatal("pre-step handshake was rejected")
	}
	stepped := testNow.Add(-3 * replayWindow)
	for i := 1; i < maxReplayPerClient; i++ {
		if !f.Accept("alice", ephemeralKey(i), stepped, stepped) {
			t.Fatalf("post-step handshake %d was rejected", i)
		}
	}
	if f.Accept("alice", ephemeralKey(maxReplayPerClient), stepped, stepped) {
		t.Fatal("alice was accepted above her quota")
	}

	now := stepped.Add(replayWindow + time.Nanosecond)
	if !f.Accept("alice", ephemeralKey(maxReplayPerClient), now, now) {
		t.Fatal("alice was refused after her post-step entries expired")
	}
	if f.Accept("alice", ephemeralKey(0), now, now) {
		t.Fatal("pre-step key was forgotten inside its window")
	}
	if n := f.perClient["alice"]; n != 2 {
		t.Fatalf("alice holds %d entries, want 2", n)
	}
}

// TestReplayFilterBackwardStepDoesNotFillCache checks that a backward step
// cannot leave the cache full of keys whose wall time is already past the
// window. A new handshake is refused while those keys are still inside it, and
// accepted once they are not. The pre-step key stays a replay.
func TestReplayFilterBackwardStepDoesNotFillCache(t *testing.T) {
	f := NewReplayFilter()
	if !f.Accept("anchor", ephemeralKey(0), testNow, testNow) {
		t.Fatal("pre-step handshake was rejected")
	}
	stepped := testNow.Add(-3 * replayWindow)
	for i := 1; i < maxReplayEntries; i++ {
		client := strconv.Itoa(i / maxReplayPerClient)
		if !f.Accept(client, ephemeralKey(i), stepped, stepped) {
			t.Fatalf("post-step handshake %d from client %s was rejected", i, client)
		}
	}
	if f.Accept("extra", ephemeralKey(maxReplayEntries), stepped, stepped) {
		t.Fatal("handshake was accepted by a full filter")
	}

	now := stepped.Add(replayWindow + time.Nanosecond)
	if !f.Accept("extra", ephemeralKey(maxReplayEntries), now, now) {
		t.Fatal("a backward step refused a new handshake after wall-old entries should have expired")
	}
	if f.Accept("anchor", ephemeralKey(0), now, now) {
		t.Fatal("pre-step key was forgotten inside its window")
	}
	if n := len(f.entries); n != 2 {
		t.Fatalf("filter holds %d entries, want 2", n)
	}
}

// TestReplayFilterClockStepsExpireByWallTime checks several steps, forward and
// back, all inside one replay window of each other so none expire early. The
// keys at the earliest wall time are then forgotten on their own, including
// one accepted after a later wall time. Keys accepted at a later wall time stay.
func TestReplayFilterClockStepsExpireByWallTime(t *testing.T) {
	f := NewReplayFilter()
	// Offsets stay within replayWindow of one another, so accepting a later
	// wall time does not expire an earlier one before the check below.
	steps := []time.Duration{
		0,
		-8 * time.Minute,
		-3 * time.Minute,
		-9 * time.Minute,
		time.Minute,
		-9 * time.Minute,
	}
	for i, d := range steps {
		at := testNow.Add(d)
		if !f.Accept(testClient, ephemeralKey(i), at, at) {
			t.Fatalf("handshake at %v was rejected", d)
		}
	}

	earliest := testNow.Add(-9 * time.Minute)
	now := earliest.Add(replayWindow + time.Nanosecond)
	if !f.Accept(testClient, ephemeralKey(len(steps)), now, now) {
		t.Fatal("handshake was rejected while only the earliest wall times should have expired")
	}
	for _, i := range []int{3, 5} {
		if _, ok := f.entries[string(ephemeralKey(i))]; ok {
			t.Fatalf("key %d accepted at -9min was kept past its window", i)
		}
		if !f.Accept(testClient, ephemeralKey(i), now, now) {
			t.Fatalf("expired key %d was still remembered", i)
		}
	}
	for _, i := range []int{0, 1, 2, 4} {
		if f.Accept(testClient, ephemeralKey(i), now, now) {
			t.Fatalf("key %d was forgotten inside its window", i)
		}
	}
}

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

// TestReplayFilterRestartGuardSurvivesClockStepBack checks that a pre-restart
// capture is refused even when the wall clock is behind notBefore. The skew
// check alone would accept it.
func TestReplayFilterRestartGuardSurvivesClockStepBack(t *testing.T) {
	f := newReplayFilterAt(testNow)
	ts := testNow.Add(-30 * time.Second)
	stepped := testNow.Add(-3 * time.Minute)
	if f.Accept(testClient, ephemeralKey(9), ts, stepped) {
		t.Fatal("pre-restart capture was accepted after a backward clock step")
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
