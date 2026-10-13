package raywire

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// The timing tests separate two reactions, at once and at the deadline, with budgets
// of hundreds of milliseconds. Each bound lies well away from the reaction it does
// not expect, so a loaded host does not turn one of them into a failure.

// TestTagFailureRelaysAtByte50 checks that a head with a bad tag reaches the decoy as
// soon as its 50 bytes arrive, and not at the pre-auth deadline.
func TestTagFailureRelaysAtByte50(t *testing.T) {
	setPreAuthTimeout(t, 2*time.Second)
	arrived := make(chan time.Time, 1)
	decoy := startDecoy(t, func(c net.Conn) {
		got := make([]byte, hsHeadLen)
		if _, err := io.ReadFull(c, got); err != nil {
			return
		}
		arrived <- time.Now()
	})
	srv := newProbeServer(t, decoy)
	server, prober := tcpPair(t)
	go func() {
		_, _ = srv.handlePreAuth(context.Background(), server, srv.pad)
	}()

	sent := time.Now()
	if _, err := prober.Write(randomHead(t, hsHeadLen)); err != nil {
		t.Fatal(err)
	}
	select {
	case at := <-arrived:
		if d := at.Sub(sent); d > 500*time.Millisecond {
			t.Fatalf("the decoy got the head %v after it was sent, want at once", d)
		}
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("the decoy got no head before the pre-auth deadline")
	}
}

// TestShortHeadWaitsForDeadline checks that a silent head of 49 bytes reaches the decoy
// only at the pre-auth deadline. A 49-byte head is one byte short of the tag, so the
// server cannot decide before the budget ends (residual R1).
func TestShortHeadWaitsForDeadline(t *testing.T) {
	setPreAuthTimeout(t, 600*time.Millisecond)
	arrived := make(chan time.Time, 1)
	decoy := startDecoy(t, func(c net.Conn) {
		got := make([]byte, 49)
		if _, err := io.ReadFull(c, got); err != nil {
			return
		}
		arrived <- time.Now()
	})
	srv := newProbeServer(t, decoy)
	server, prober := tcpPair(t)
	go func() {
		_, _ = srv.handlePreAuth(context.Background(), server, srv.pad)
	}()

	sent := time.Now()
	if _, err := prober.Write(randomHead(t, 49)); err != nil {
		t.Fatal(err)
	}
	select {
	case at := <-arrived:
		if d := at.Sub(sent); d < 400*time.Millisecond {
			t.Fatalf("the decoy got the 49 bytes %v after they were sent, want at the 600 ms deadline", d)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the decoy got no bytes")
	}
	_ = prober.Close()
}

// TestTLSDecoyTimingBand pins residual R1 with a crypto/tls decoy. Silent probes of 1,
// 5, 33 and 49 bytes reach the decoy only at the deadline. A 50-byte head with a bad tag
// reaches it at once.
func TestTLSDecoyTimingBand(t *testing.T) {
	setPreAuthTimeout(t, 600*time.Millisecond)
	for _, c := range []struct {
		name       string
		n          int
		atDeadline bool
	}{
		{"silent 1 byte", 1, true},
		{"silent 5 bytes", 5, true},
		{"silent 33 bytes", 33, true},
		{"silent 49 bytes", 49, true},
		{"50 bytes with a bad tag", hsHeadLen, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			arrived := make(chan time.Time, 1)
			srv := newProbeServer(t, startTLSDecoy(t, arrived))
			server, prober := tcpPair(t)
			done := make(chan error, 1)
			go func() {
				_, err := srv.handlePreAuth(context.Background(), server, srv.pad)
				done <- err
			}()

			sent := time.Now()
			if _, err := prober.Write(randomHead(t, c.n)); err != nil {
				t.Fatal(err)
			}
			select {
			case at := <-arrived:
				d := at.Sub(sent)
				if c.atDeadline && d < 400*time.Millisecond {
					t.Fatalf("the decoy got the bytes %v after they were sent, want at the deadline", d)
				}
				if !c.atDeadline && d > 300*time.Millisecond {
					t.Fatalf("the decoy got the bytes %v after they were sent, want at once", d)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("the decoy got no bytes")
			}
			_ = prober.Close()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("pre-auth stage did not return")
			}
		})
	}
}

// TestRelayIdleFromLastByte checks that the relay's idle clock starts at the last byte
// read. A silent 3-byte probe is decided at the 2 s deadline, when its idle time has
// used up the 2 s inactivity limit, so it is closed at once and not 2 s later (9.8).
// The decoy only reads. A decoy that writes, even an echo of the consumed bytes, moves
// bytes on the relay, and each byte moved resets the idle clock.
func TestRelayIdleFromLastByte(t *testing.T) {
	setPreAuthTimeout(t, 2*time.Second)
	setRelayTimers(t, 2*time.Second, time.Minute)
	sink := startDecoy(t, func(c net.Conn) {
		_, _ = io.Copy(io.Discard, c)
	})
	srv := newProbeServer(t, sink)
	server, prober := tcpPair(t)
	go func() {
		_, _ = srv.handlePreAuth(context.Background(), server, srv.pad)
	}()

	if _, err := prober.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := prober.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(prober); err != nil {
		t.Fatalf("read: %v", err)
	}
	if d := time.Since(start); d >= 3*time.Second {
		t.Fatalf("the silent probe was closed %v after its last byte, want within 2 s", d)
	}
}

// TestRelayIdleFromLaterByte checks the idle clock when the last byte comes after the
// first one, and well after accept (8.3, 9.8). The prober sends two bytes at accept and
// one at 1 s, then goes silent. The budget ends at 2 s and the relay is closed 2 s after
// the last byte, at about 3 s. A clock that starts at the relay (the decision, 2 s) would
// close the relay 3 s after the last byte, and a clock that never moves past accept would
// close it at 2 s, 1 s after the last byte. The bounds lie 0.4 s from each of those.
func TestRelayIdleFromLaterByte(t *testing.T) {
	const (
		budget   = 2 * time.Second
		lastByte = time.Second
		idle     = 2 * time.Second
	)
	setPreAuthTimeout(t, budget)
	setRelayTimers(t, idle, time.Minute)
	sink := startDecoy(t, func(c net.Conn) {
		_, _ = io.Copy(io.Discard, c)
	})
	srv := newProbeServer(t, sink)
	server, prober := tcpPair(t)
	go func() {
		_, _ = srv.handlePreAuth(context.Background(), server, srv.pad)
	}()

	if _, err := prober.Write([]byte("ab")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(lastByte)
	sent := time.Now()
	if _, err := prober.Write([]byte("c")); err != nil {
		t.Fatal(err)
	}
	readAllWithin(t, prober, 10*time.Second)
	after := time.Since(sent)
	if after < idle-400*time.Millisecond || after > idle+400*time.Millisecond {
		t.Fatalf("the relay closed %v after the last byte, want about %v", after, idle)
	}
}
