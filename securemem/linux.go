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
func LockMemory(b []byte) error {
	if len(b) == 0 { return nil }
	return unix.Mlock(b)
}

// UnlockMemory unlocks a previously locked slice.
func UnlockMemory(b []byte) error {
	if len(b) == 0 { return nil }
	return unix.Munlock(b)
}

// Alloc requests raw memory pages from the OS using mmap.
// It applies madvise flags to prevent dumping/swapping behavior where possible.
// Returns a deallocator function that should be used and called at somewhere
func Alloc(size int, opts ...Option) ([]byte, func(), error) {
	if size <= 0 { return nil,func(){}, fmt.Errorf("invalid allocation size: %d", size) }

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
	if err != nil { return nil, func(){}, fmt.Errorf("mmap failed: %w", err) }

	// Advise kernel to exclude this memory region from coredumps
	_ = unix.Madvise(b, unix.MADV_DONTDUMP)
	// Advise kernel to release pages eagerly when freed
	_ = unix.Madvise(b, unix.MADV_NOHUGEPAGE)

	// Lock to the RAM if it's explicitly enabled
	if cfg.lock {
		if err := unix.Mlock(b); err != nil {
			// Unmap before returning to avoid leaking memory if locking fails
			_ = unix.Munmap(b)
			return nil, func(){}, fmt.Errorf("mlock failed (check RLIMIT_MEMLOCK): %w", err)
		}
	}

	return b, func(){dealloc(b)}, nil
}

// dealloc zeros out the sensitive contents, unlocks, and unmaps the buffer.
func dealloc(b []byte) error {
	if len(b) == 0 { return nil }

	// Wipe memory contents completely before freeing
	ZeroBytes(b)

	// Best-effort unlock (will fail silently if it wasn't locked)
	_ = unix.Munlock(b)

	// Instruct kernel to drop these pages immediately
	_ = unix.Madvise(b, unix.MADV_DONTNEED)

	// Return memory back to system
	if err := unix.Munmap(b); err != nil { return fmt.Errorf("munmap failed: %w", err) }

	return nil
}
