//go:build !unix

package raywire

import "syscall"

// drainQueued does nothing on platforms without the Unix read path. A close there
// may reset the connection when bytes are unread (R13).
func drainQueued(syscall.Conn) {}
