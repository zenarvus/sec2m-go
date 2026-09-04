//go:build android || linux

// Use this only for core linux and android like operating systems.

package platforms

import "golang.org/x/sys/unix"

// LockMemory locks the given bytes to RAM to prevent swapping.
func LockMemory(b []byte) error {
	if len(b) == 0 { return nil }
	return unix.Mlock(b)
}

// Disable core dumps and ptrace attachment
func DisableCoreDump() error {
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}

// Allocate a buffer from the RAM
func Alloc(len int) ([]byte, error)

// Deallocate a buffer from the RAM
func Dealloc(b []byte) (error)
