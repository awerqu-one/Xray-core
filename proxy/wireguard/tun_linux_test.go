//go:build linux

package wireguard

import (
	"testing"
	"unsafe"
)

func TestCapUserDataV3Size(t *testing.T) {
	data := capUserDataV3()
	if got := unsafe.Sizeof(data); got != 24 {
		t.Fatalf("version 3 cap buffer is %d bytes", got)
	}
	if len(data) != 2 || unsafe.Sizeof(data[0]) != 12 {
		t.Fatalf("version 3 cap buffer is %d records of %d bytes", len(data), unsafe.Sizeof(data[0]))
	}
}
