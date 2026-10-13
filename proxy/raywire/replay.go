package raywire

import (
	"container/list"
	"sync"
	"time"
)

const (
	// maxClockSkew is how far a handshake timestamp may differ from the
	// server's clock, in either direction.
	maxClockSkew = 5 * time.Minute

	// replayWindow is how long an accepted ephemeral key is remembered. A
	// timestamp can be maxClockSkew ahead of the server, so a key accepted at
	// time n must be kept until n+2*maxClockSkew, when its handshake would
	// stop passing the skew check.
	replayWindow = 2 * maxClockSkew

	// maxReplayEntries bounds the memory that a flood of handshakes can use.
	maxReplayEntries = 65536

	// maxReplayPerClient bounds the entries that one client can hold, so one
	// authorized key cannot fill the whole cache and lock out the others. Four
	// clients at this quota fill the cache, so the quota is a quarter of it.
	maxReplayPerClient = maxReplayEntries / 4
)

// ReplayFilter remembers the ephemeral keys of accepted handshakes, so a
// captured first message cannot be sent again. The filter is safe for
// concurrent use.
//
// A single timestamp per client is not enough: one client opens many
// connections in parallel, and their handshakes can arrive out of order.
//
// Each entry is charged to the client that sent it, and a client at its quota
// is refused until its entries expire. A client is identified by its static
// public key, which the handshake has authenticated.
//
// The filter lives in memory. After a restart it is empty, so a first message
// captured before the restart could pass again within the skew window. A server's
// filter therefore refuses every timestamp earlier than the server's start.
type ReplayFilter struct {
	// notBefore is the server's clock when a server started the filter. A first
	// message older than this may have been accepted by an earlier run of the
	// server. It is set once and never changes, so Accept reads it without mu.
	// It is zero for a filter from NewReplayFilter, which refuses no timestamp
	// for this reason.
	notBefore time.Time

	mu        sync.Mutex
	entries   map[string]*list.Element // ephemeral key to its element in order
	perClient map[string]int           // client to its number of entries
	order     *list.List               // *replayEntry, oldest accepted first
}

type replayEntry struct {
	key    string
	client string
	at     time.Time // the server's clock when the key was accepted
}

// NewReplayFilter returns an empty filter with no start time, so it refuses no
// timestamp for restart reasons. A server starts its filter at its own clock with
// newReplayFilterAt(handshakeClock()), as NewServer does. This constructor is for
// tests, and for a filter with no earlier run to guard against.
func NewReplayFilter() *ReplayFilter {
	return newReplayFilterAt(time.Time{})
}

// newReplayFilterAt returns an empty filter that refuses timestamps before
// notBefore.
func newReplayFilterAt(notBefore time.Time) *ReplayFilter {
	return &ReplayFilter{
		notBefore: notBefore,
		entries:   make(map[string]*list.Element),
		perClient: make(map[string]int),
		order:     list.New(),
	}
}

// Accept reports whether a handshake from client with this ephemeral key and
// timestamp is new. client names the authenticated client, such as its static
// public key. now is the server's clock. Only accepted keys are stored.
//
// The filter fails closed: when it is full after expiry, or when client is at
// maxReplayPerClient, a new key is refused rather than evicting an older one.
// Evicting would let a flood of handshakes make an old captured key valid again.
// A refused client's entries expire on their own, and other clients are not
// affected by its quota.
//
// A timestamp before the filter's start is refused, even inside the skew window.
// A legitimate client whose clock lags the server by up to maxClockSkew is
// refused for that long after a restart, and then retries with a newer timestamp.
func (f *ReplayFilter) Accept(client string, ephemeral []byte, ts, now time.Time) bool {
	if d := now.Sub(ts); d > maxClockSkew || d < -maxClockSkew {
		return false
	}
	if ts.Before(f.notBefore) {
		return false
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	f.expire(now)
	key := string(ephemeral)
	if _, ok := f.entries[key]; ok {
		return false
	}
	if len(f.entries) >= maxReplayEntries {
		return false
	}
	if f.perClient[client] >= maxReplayPerClient {
		return false
	}
	f.entries[key] = f.order.PushBack(&replayEntry{key: key, client: client, at: now})
	f.perClient[client]++
	return true
}

// expire forgets keys accepted more than replayWindow before now. The list is
// in acceptance order, so it stops at the first key still in the window. The
// caller must hold mu.
func (f *ReplayFilter) expire(now time.Time) {
	for e := f.order.Front(); e != nil; e = f.order.Front() {
		if now.Sub(e.Value.(*replayEntry).at) <= replayWindow {
			return
		}
		f.remove(e)
	}
}

// remove deletes one element from the list, the map and the client's count. The
// caller must hold mu.
func (f *ReplayFilter) remove(e *list.Element) {
	entry := f.order.Remove(e).(*replayEntry)
	delete(f.entries, entry.key)
	if f.perClient[entry.client]--; f.perClient[entry.client] == 0 {
		delete(f.perClient, entry.client)
	}
}
