package raywire

import (
	"errors"
	"io"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
)

// TestRelayPassesDecoyResetToProber checks that a decoy reset reaches the prober
// as a reset. A direct connection shows one. A FIN would tell a prober that the
// connection went through raywire.
func TestRelayPassesDecoyResetToProber(t *testing.T) {
	setRelayTimers(t, 5*time.Second, time.Minute)
	const probe = "probe"
	dest := startDecoy(t, func(c net.Conn) {
		got := make([]byte, len(probe))
		if _, err := io.ReadFull(c, got); err != nil {
			return
		}
		// A zero linger makes Close send RST.
		c.(*net.TCPConn).SetLinger(0)
	})

	prober, external := tcpPair(t)
	done := startRelay(prober, []byte(probe), dest)

	if err := external.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, err := external.Read(make([]byte, 1))
	if !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("prober read after decoy reset = %v, want a reset", err)
	}
	waitRelay(t, done, 2*time.Second)
}

// TestDecoyDownLogIsRateLimited checks that a flood of probes against an
// unreachable decoy produces one error-level line, not one per probe.
func TestDecoyDownLogIsRateLimited(t *testing.T) {
	logs := captureLogs(t)
	countDials(t, errors.New("connection refused"))
	dest := xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), 9)

	const probes = 300
	for i := 0; i < probes; i++ {
		prober, peer := net.Pipe()
		done := startRelay(prober, []byte("junk"), dest)
		waitRelay(t, done, time.Second)
		peer.Close()
	}

	var errLines int
	for _, m := range logs.lines() {
		if strings.Contains(m, "[Error]") && strings.Contains(m, "decoy unreachable") {
			errLines++
		}
	}
	if errLines != 1 {
		t.Fatalf("%d error lines for %d failed dials, want 1", errLines, probes)
	}
}
