//go:build !android && !linux && !darwin && !ios && !windows

package securemem

import (
	"fmt"
)

// Setup is a no-op on generic platforms. We cannot reliably disable core dumps without OS-specific APIs.
func Setup() error { return nil }

// LockMemory is a no-op on generic platforms.
func LockMemory(b *ByteSlice) error {
	return nil
}

// UnlockMemory is a no-op on generic platforms.
func UnlockMemory(b *ByteSlice) error { return nil }

// Alloc requests standard heap memory from the Go runtime.
// On unsupported platforms, this memory cannot be locked to RAM and may be written to swap files by the operating system.
func Alloc(size int, opts ...Option) (*ByteSlice, error) {
	if size <= 0 { return &ByteSlice{}, fmt.Errorf("invalid allocation size: %d", size) }

	// We still parse options so they don't cause unused variable errors, 
	cfg := &config{lock: false}
	for _, opt := range opts { opt(cfg) }

	// Allocate a standard Go byte slice on the heap.
	b := make([]byte, size)

	slice := &ByteSlice{
		Bytes: b,
		freed: false,
	}
	slice.Dealloc = func()error{ return dealloc(slice) }

	return slice, nil
}

// dealloc zeros out the contents before letting the Go garbage collector reclaim it.
func dealloc(b *ByteSlice) error {
	if b == nil || b.freed {return nil}
	if len(b.Bytes) == 0 { b.freed = true; return nil }

	// Wipe memory contents completely to minimize exposure
	// before the GC eventually frees or reuses the backing array.
	ZeroBytes(b.Bytes)

	b.freed = true

	return nil
}
