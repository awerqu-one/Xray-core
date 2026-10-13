//go:build linux

package raywire

import (
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// queuedBytes returns the bytes waiting in the receive queue of c, as FIONREAD
// reports them.
func queuedBytes(t *testing.T, c *net.TCPConn) int {
	t.Helper()
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var n int32
	var errno syscall.Errno
	if err := raw.Control(func(fd uintptr) {
		_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCINQ, uintptr(unsafe.Pointer(&n)))
	}); err != nil {
		t.Fatal(err)
	}
	if errno != 0 {
		t.Fatal(errno)
	}
	return int(n)
}

// specDrainLimit is drainLimit as spec 9.7 and R13 give it: 256 KiB.
const specDrainLimit = 256 << 10

// rcvBuf returns the receive buffer size that the kernel gives c. The kernel caps a
// requested size at rmem_max and then doubles it, so the value can differ from the
// request.
func rcvBuf(t *testing.T, c *net.TCPConn) int {
	t.Helper()
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var size int
	var serr error
	if err := raw.Control(func(fd uintptr) {
		size, serr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	}); err != nil {
		t.Fatal(err)
	}
	if serr != nil {
		t.Fatal(serr)
	}
	return size
}

// waitQueued waits until more than limit bytes are queued on c, or until the queue
// stops growing for stall, or until ten seconds pass. It returns the queued count
// at that point. A queue that stops growing has reached the kernel's buffer limit.
func waitQueued(t *testing.T, c *net.TCPConn, limit int, stall time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	last, lastChange := -1, time.Now()
	for {
		n := queuedBytes(t, c)
		if n > limit {
			return n
		}
		if n != last {
			last, lastChange = n, time.Now()
		}
		// A queue that is still empty is not a full buffer. It is waited for, not
		// settled.
		settled := n > 0 && time.Since(lastChange) >= stall
		if settled || time.Now().After(deadline) {
			return n
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestDrainLimit documents residual R13. When more than drainLimit bytes are queued,
// the drain stops before the queue is empty, so the close resets the connection.
//
// The queue cannot hold more than the kernel's receive buffer, and the kernel caps
// that buffer at rmem_max. The test asks for 4 MiB and measures what the kernel
// holds. When the queue stops short of drainLimit, the case cannot be built on
// this host, so the test skips and names the buffer size. It does not fail.
func TestDrainLimit(t *testing.T) {
	// The spec value is fixed here, so a changed limit fails this test and does not
	// turn it into a skip (spec 9.7).
	if drainLimit != specDrainLimit {
		t.Fatalf("drainLimit = %d, spec 9.7 gives %d", drainLimit, specDrainLimit)
	}
	server, prober := tcpPair(t)
	// The default buffer holds about 64 KiB of payload, below the limit, so the
	// buffer is raised as far as the kernel allows before any byte arrives.
	if err := server.SetReadBuffer(4 << 20); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, specDrainLimit+64<<10)
	go func() {
		_, _ = prober.Write(payload)
	}()

	queued := waitQueued(t, server, specDrainLimit, 500*time.Millisecond)
	if queued == 0 {
		t.Fatal("no bytes were queued, so the test proves nothing")
	}
	if queued <= specDrainLimit {
		t.Skipf("the kernel holds %d queued bytes (SO_RCVBUF %d), not more than the drain limit %d, "+
			"so the R13 case cannot be built on this host; the kernel caps the buffer at rmem_max",
			queued, rcvBuf(t, server), specDrainLimit)
	}
	closeAfterDrain(server)

	time.Sleep(100 * time.Millisecond)
	_, err := prober.Write([]byte{0})
	if !errors.Is(err, syscall.ECONNRESET) && !errors.Is(err, syscall.EPIPE) {
		t.Fatalf("write after the close = %v, want a reset: more than drainLimit bytes were queued", err)
	}
}

// TestDrainBeyondOneChunk checks that the drain reads on after its first chunk. A
// drain that stops after one read of drainChunk leaves the rest of the queue, and the
// close then resets the connection. The probe is 32 KiB, eight chunks, and it fits in
// the default receive buffer on any Linux host, so the test does not depend on rmem_max.
func TestDrainBeyondOneChunk(t *testing.T) {
	const size = 32 << 10
	server, prober := tcpPair(t)
	go func() {
		_, _ = prober.Write(make([]byte, size))
	}()
	if got := waitQueued(t, server, size-1, 500*time.Millisecond); got < size {
		t.Fatalf("only %d bytes queued, want %d before the close", got, size)
	}
	closeAfterDrain(server)
	requireFIN(t, prober)
}
