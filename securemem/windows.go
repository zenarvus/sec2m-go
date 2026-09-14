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

func LockMemory(b ByteSlice) error {
    if len(b.Bytes) == 0 { return nil }
    return windows.VirtualLock(uintptr(unsafe.Pointer(&b.Bytes[0])), uintptr(len(b.Bytes)))
}

func UnlockMemory(b ByteSlice) error {
    if len(b.Bytes) == 0 { return nil }
    return windows.VirtualUnlock(uintptr(unsafe.Pointer(&b.Bytes[0])), uintptr(len(b.Bytes)))
}

func Alloc(size int, opts ...Option) (ByteSlice, error) {
    if size <= 0 { return ByteSlice{Dealloc:func()error{return nil}}, fmt.Errorf("invalid allocation size: %d", size) }

    cfg := &config{lock: false}
    for _, opt := range opts { opt(cfg) }

    addr, err := windows.VirtualAlloc(
        0, 
        uintptr(size), 
        windows.MEM_COMMIT|windows.MEM_RESERVE, 
        windows.PAGE_READWRITE,
    )
    if err != nil { return ByteSlice{Dealloc:func()error{return nil}}, fmt.Errorf("VirtualAlloc failed: %w", err) }

    // Convert raw pointer into a Go byte slice
    b := unsafe.Slice((*byte)(unsafe.Pointer(addr)), size)

    if cfg.lock {
        if err := windows.VirtualLock(addr, uintptr(size)); err != nil {
            _ = windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
            return ByteSlice{Dealloc:func()error{return nil}}, fmt.Errorf("VirtualLock failed (requires SeLockMemoryPrivilege): %w", err)
        }
    }

	slice := &ByteSlice{
		Bytes: b,
		freed: false,
	}
	slice.Dealloc = func()error{ return dealloc(slice, addr) }

	return *slice, nil
}

func dealloc(b *ByteSlice, addr uintptr) error {
	if b == nil || b.freed { return nil }
    if len(b.Bytes) == 0 { b.freed = true; return nil }

    ZeroBytes(b.Bytes)
    _ = windows.VirtualUnlock(addr, uintptr(len(b.Bytes)))

    if err := windows.VirtualFree(addr, 0, windows.MEM_RELEASE); err != nil {
        return fmt.Errorf("VirtualFree failed: %w", err)
    }

	b.freed = true

    return nil
}
