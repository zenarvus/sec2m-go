//go:build !android && !linux && !darwin && !ios && !windows

package securemem

import (
	"fmt"
)

// Setup is a no-op on generic platforms. We cannot reliably disable core dumps without OS-specific APIs.
func Setup() error { return nil }

// LockMemory is a no-op on generic platforms.
func LockMemory(b []byte) error {
	return nil
}

// UnlockMemory is a no-op on generic platforms.
func UnlockMemory(b []byte) error { return nil }

// Alloc requests standard heap memory from the Go runtime.
// On unsupported platforms, this memory cannot be locked to RAM and may be written to swap files by the operating system.
func Alloc(size int, opts ...Option) ([]byte, func(), error) {
	if size <= 0 { return nil, func() {}, fmt.Errorf("invalid allocation size: %d", size) }

	// We still parse options so they don't cause unused variable errors, 
	cfg := &config{lock: false}
	for _, opt := range opts { opt(cfg) }

	// Allocate a standard Go byte slice on the heap.
	b := make([]byte, size)

	return b, func() { dealloc(b) }, nil
}

// dealloc zeros out the contents before letting the Go garbage collector reclaim it.
func dealloc(b []byte) error {
	if len(b) == 0 { return nil }

	// Wipe memory contents completely to minimize exposure
	// before the GC eventually frees or reuses the backing array.
	ZeroBytes(b)

	return nil
}
