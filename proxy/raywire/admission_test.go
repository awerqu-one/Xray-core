package raywire

import (
	"strconv"
	"testing"
)

// TestAdmissionKeyIPv6Prefix checks the per-source key for IPv6. Two addresses in one
// /64 share the cap, two addresses in different /64s do not, and an IPv4-mapped
// address shares the key of its IPv4 address.
func TestAdmissionKeyIPv6Prefix(t *testing.T) {
	key := func(addr string) string { return sourceKey(fixedAddr(addr)) }
	if key("[2001:db8::1]:443") != key("[2001:db8::2]:9000") {
		t.Fatal("two addresses of one /64 have different keys")
	}
	if key("[2001:db8::1]:443") == key("[2001:db8:0:1::1]:443") {
		t.Fatal("addresses of two /64s share a key")
	}
	if key("[::ffff:203.0.113.9]:4000") != key("203.0.113.9:4000") {
		t.Fatal("an IPv4-mapped address is not keyed as its IPv4 address")
	}

	a := newAdmission(maxPendingHandshakes, maxPendingPerIP)
	for i := range maxPendingPerIP {
		host := key("[2001:db8::" + strconv.FormatInt(int64(i+1), 16) + "]:443")
		if _, ok := a.TryAcquire(host); !ok {
			t.Fatalf("address %d of one /64 refused below the per-source limit", i+1)
		}
	}
	if _, ok := a.TryAcquire(key("[2001:db8::ff]:443")); ok {
		t.Fatal("a further address of the same /64 was admitted past the limit")
	}
	if _, ok := a.TryAcquire(key("[2001:db8:0:1::1]:443")); !ok {
		t.Fatal("an address of another /64 was refused")
	}
}

// TestPreAuthLimitsMatchFinalDesign pins the pre-auth limits to FINAL.md, which
// sets a pool of 1024 and 32 per source. A larger per-source limit lets one
// source reach the refusal sooner, and the refusal is visible to a prober.
func TestPreAuthLimitsMatchFinalDesign(t *testing.T) {
	if maxPendingHandshakes != 1024 || maxPendingPerIP != 32 {
		t.Fatalf("pre-auth limits = %d total, %d per source; FINAL.md sets 1024 and 32",
			maxPendingHandshakes, maxPendingPerIP)
	}

	adm := newAdmission(maxPendingHandshakes, maxPendingPerIP)
	const one = "203.0.113.40"
	for i := 0; i < 32; i++ {
		if _, ok := adm.TryAcquire(one); !ok {
			t.Fatalf("slot %d from one source refused below the per-source limit", i+1)
		}
	}
	if _, ok := adm.TryAcquire(one); ok {
		t.Fatal("33rd connection from one source admitted")
	}

	// Thirty-two sources of 32 slots fill the pool exactly.
	for h := 0; adm.pendingCount() < maxPendingHandshakes; h++ {
		if _, ok := adm.TryAcquire("198.51.100." + strconv.Itoa(h)); !ok {
			t.Fatalf("source %d refused below the total limit", h)
		}
	}
	if _, ok := adm.TryAcquire("192.0.2.1"); ok {
		t.Fatal("connection past the total limit admitted")
	}
}
