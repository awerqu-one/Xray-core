//go:build unix

package raywire

import "syscall"

// drainQueued reads and discards the bytes queued on the socket, up to drainLimit.
// It is one pass of non-blocking read(2) calls. The caller must clear the read
// deadline first: RawRead returns at once on a deadline in the past, without
// calling the function, so the queue would not be read.
func drainQueued(sc syscall.Conn) {
	raw, err := sc.SyscallConn()
	if err != nil {
		return
	}
	buf := make([]byte, drainChunk)
	discarded := 0
	_ = raw.Read(func(fd uintptr) bool {
		for discarded < drainLimit {
			n, err := syscall.Read(int(fd), buf)
			if err == syscall.EINTR {
				continue
			}
			// EAGAIN ends the queue, and 0 is the end of the stream.
			if err != nil || n <= 0 {
				break
			}
			discarded += n
		}
		return true
	})
}
