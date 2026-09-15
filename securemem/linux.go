//go:build android || linux

// Use this only for core linux and android like operating systems.

package securemem

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// Disables core dumps and ptrace attachment for the app
func Setup() error {
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}

// LockMemory manually locks an existing slice in physical RAM.
func LockMemory(b *ByteSlice) error {
	if len(b.Bytes) == 0 { return nil }
	return unix.Mlock(b.Bytes)
}

// UnlockMemory unlocks a previously locked slice.
func UnlockMemory(b *ByteSlice) error {
	if len(b.Bytes) == 0 { return nil }
	return unix.Munlock(b.Bytes)
}

// Alloc requests raw memory pages from the OS using mmap.
// It applies madvise flags to prevent dumping/swapping behavior where possible.
// Returns a deallocator function that should be used to free the allocated memory
func Alloc(size int, opts ...Option) (*ByteSlice, error) {
	if size <= 0 { return &ByteSlice{
		Dealloc:func() error {return nil},
	}, fmt.Errorf("invalid allocation size: %d", size) }

	cfg := &config{lock: false}
	// Apply the modifications provided as opts to the cfg
	for _, opt := range opts { opt(cfg) }

	// Allocate anonymous, private read/write memory directly from the kernel
	b, err := unix.Mmap(
		-1,0,
		size,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS,
	)
	if err != nil { return &ByteSlice{Dealloc:func()error{return nil}}, fmt.Errorf("mmap failed: %w", err) }

	// Advise kernel to exclude this memory region from coredumps
	_ = unix.Madvise(b, unix.MADV_DONTDUMP)
	// Advise kernel to release pages eagerly when freed
	_ = unix.Madvise(b, unix.MADV_NOHUGEPAGE)

	// Lock to the RAM if it's enabled
	if cfg.lock {
		if err := unix.Mlock(b); err != nil {
			// Unmap before returning to avoid leaking memory if locking fails
			_ = unix.Munmap(b)
			return &ByteSlice{Dealloc:func()error{return nil}}, fmt.Errorf("mlock failed (check RLIMIT_MEMLOCK): %w", err)
		}
	}

	slice := &ByteSlice{
		Bytes: b,
		freed: false,
	}
	slice.Dealloc = func()error{ return dealloc(slice) }

	return slice, nil
}

// dealloc zeros out the sensitive contents, unlocks, and unmaps the buffer.
func dealloc(b *ByteSlice) error {
	if b == nil || b.freed {return nil}
	if len(b.Bytes) == 0 { b.freed = true; return nil }

	// Wipe memory contents completely before freeing
	ZeroBytes(b.Bytes)

	// Best-effort unlock (will fail silently if it wasn't locked)
	_ = unix.Munlock(b.Bytes)

	// Instruct kernel to drop these pages immediately
	_ = unix.Madvise(b.Bytes, unix.MADV_DONTNEED)

	// Return memory back to system
	if err := unix.Munmap(b.Bytes); err != nil { return fmt.Errorf("munmap failed: %w", err) }

	b.freed = true

	return nil
}
