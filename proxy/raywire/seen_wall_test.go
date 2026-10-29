package raywire

import (
	"testing"
	"time"
	"unsafe"
)

// addMono returns t with its monotonic reading moved by d and its wall time unchanged.
// t must come from time.Now.
func addMono(t time.Time, d time.Duration) time.Time {
	type twin struct {
		wall uint64
		ext  int64
		loc  *time.Location
	}
	p := (*twin)(unsafe.Pointer(&t))
	if p.wall>>63 == 0 {
		panic("time has no monotonic clock")
	}
	p.ext += int64(d)
	return t
}

func TestSeenOutOfOrderWallTTL(t *testing.T) {
	const ttl = time.Hour
	s := newSeenHeads(8, ttl, seenBase)
	t.Cleanup(s.Close)
	reB, dhB := seenHead(1)
	reA, dhA := seenHead(2)
	late := seenBase.Add(10 * time.Second)
	early := seenBase.Add(time.Second)
	s.Remember(reB, dhB, seenPeer(1), late)
	s.Remember(reA, dhA, seenPeer(1), early)

	// Exactly the early head's TTL: both still remembered.
	at := early.Add(ttl)
	if _, ok := rememberedBy(s, reA, dhA, at); !ok {
		t.Fatal("early head dropped at exactly its TTL")
	}
	if _, ok := rememberedBy(s, reB, dhB, at); !ok {
		t.Fatal("later head dropped with the early head")
	}
	// One nanosecond later the early head is gone and the later front remains.
	at = early.Add(ttl + time.Nanosecond)
	if _, ok := rememberedBy(s, reA, dhA, at); ok {
		t.Fatal("early head outlived its TTL behind a later front")
	}
	if _, ok := rememberedBy(s, reB, dhB, at); !ok {
		t.Fatal("later head was dropped with the early head")
	}
	checkFairLocked(t, s)
	at = late.Add(ttl + time.Nanosecond)
	if _, ok := rememberedBy(s, reB, dhB, at); ok {
		t.Fatal("later head outlived its own TTL")
	}
	checkFairLocked(t, s)
}

func TestSeenBackwardStepExpiresOwnWallTime(t *testing.T) {
	const ttl = time.Hour
	s := newSeenHeads(8, ttl, seenBase)
	t.Cleanup(s.Close)
	re1, dh1 := seenHead(3)
	re2, dh2 := seenHead(4)
	s.Remember(re1, dh1, seenPeer(2), seenBase)
	stepped := seenBase.Add(-3 * ttl)
	s.Remember(re2, dh2, seenPeer(2), stepped)

	now := stepped.Add(ttl + time.Nanosecond)
	if _, ok := rememberedBy(s, re2, dh2, now); ok {
		t.Fatal("head accepted after the step was kept past its wall TTL")
	}
	if _, ok := rememberedBy(s, re1, dh1, now); !ok {
		t.Fatal("head from before the step was dropped inside its wall TTL")
	}
	checkFairLocked(t, s)
}

func TestSeenMonotonicAgeDoesNotExpire(t *testing.T) {
	const ttl = time.Hour
	base := time.Now()
	s := newSeenHeads(4, ttl, base)
	t.Cleanup(s.Close)
	re, dh := seenHead(5)
	s.Remember(re, dh, seenPeer(3), base)

	// Monotonic age is past the TTL; the wall time is still base. Stripping the
	// monotonic clock is what keeps the head.
	laterMono := addMono(base, ttl+time.Nanosecond)
	if wall := laterMono.Round(0).Sub(base.Round(0)); wall != 0 {
		t.Fatalf("forged clock moved the wall time by %v", wall)
	}
	if _, ok := rememberedBy(s, re, dh, laterMono); !ok {
		t.Fatal("monotonic age past TTL dropped a head whose wall age is zero")
	}
	if _, ok := rememberedBy(s, re, dh, base.Round(0).Add(ttl+time.Nanosecond)); ok {
		t.Fatal("head kept after its wall TTL")
	}
}
