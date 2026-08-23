//go:build !linux && !android

package platforms

import "fmt"

// LockMemory locks the given bytes to RAM to prevent swapping.
func LockMemory(b []byte) error {
	fmt.Println("platform does not support locking to memory")
	return nil
}

// Disable core dumps and ptrace attachment
func DisableCoreDump() error {
	fmt.Println("platform does not support disabling core dumps")
	return nil
}
