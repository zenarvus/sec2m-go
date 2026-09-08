//go:build windows

package securemem

import (
    "fmt"
    "unsafe"
    "golang.org/x/sys/windows"
)

// Setup on Windows returns nil as there is no direct prctl equivalent for core dumps.
func Setup() error {
    return nil
}

func LockMemory(b []byte) error {
    if len(b) == 0 { return nil }
    return windows.VirtualLock(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
}

func UnlockMemory(b []byte) error {
    if len(b) == 0 { return nil }
    return windows.VirtualUnlock(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
}

func Alloc(size int, opts ...Option) ([]byte, func(), error) {
    if size <= 0 { return nil, func(){}, fmt.Errorf("invalid allocation size: %d", size) }

    cfg := &config{lock: false}
    for _, opt := range opts { opt(cfg) }

    addr, err := windows.VirtualAlloc(
        0, 
        uintptr(size), 
        windows.MEM_COMMIT|windows.MEM_RESERVE, 
        windows.PAGE_READWRITE,
    )
    if err != nil { return nil, func(){}, fmt.Errorf("VirtualAlloc failed: %w", err) }

    // Convert raw pointer into a Go byte slice
    b := unsafe.Slice((*byte)(unsafe.Pointer(addr)), size)

    if cfg.lock {
        if err := windows.VirtualLock(addr, uintptr(size)); err != nil {
            _ = windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
            return nil, func(){}, fmt.Errorf("VirtualLock failed (requires SeLockMemoryPrivilege): %w", err)
        }
    }

    return b, func() { dealloc(b, addr) }, nil
}

func dealloc(b []byte, addr uintptr) error {
    if len(b) == 0 { return nil }

    ZeroBytes(b)
    _ = windows.VirtualUnlock(addr, uintptr(len(b)))

    if err := windows.VirtualFree(addr, 0, windows.MEM_RELEASE); err != nil {
        return fmt.Errorf("VirtualFree failed: %w", err)
    }
    return nil
}
