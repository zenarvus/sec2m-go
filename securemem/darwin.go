//go:build darwin || ios

package securemem

import (
    "fmt"
    "golang.org/x/sys/unix"
)

// Setup on Darwin returns nil. (Disabling dumps globally via PT_DENY_ATTACH usually requires CGO).
func Setup() error {
    return nil
}

func LockMemory(b []byte) error {
    if len(b) == 0 { return nil }
    return unix.Mlock(b)
}

func UnlockMemory(b []byte) error {
    if len(b) == 0 { return nil }
    return unix.Munlock(b)
}

func Alloc(size int, opts ...Option) ([]byte, func(), error) {
    if size <= 0 { return nil, func(){}, fmt.Errorf("invalid allocation size: %d", size) }

    cfg := &config{lock: false}
    for _, opt := range opts { opt(cfg) }

    // MAP_ANON is used on Darwin instead of MAP_ANONYMOUS
    b, err := unix.Mmap(
        -1, 0,
        size,
        unix.PROT_READ|unix.PROT_WRITE,
        unix.MAP_PRIVATE|unix.MAP_ANON,
    )
    if err != nil { return nil, func(){}, fmt.Errorf("mmap failed: %w", err) }

    if cfg.lock {
        if err := unix.Mlock(b); err != nil {
            _ = unix.Munmap(b)
            return nil, func(){}, fmt.Errorf("mlock failed: %w", err)
        }
    }

    return b, func() { dealloc(b) }, nil
}

func dealloc(b []byte) error {
    if len(b) == 0 { return nil }

    ZeroBytes(b)
    _ = unix.Munlock(b)
    _ = unix.Madvise(b, unix.MADV_DONTNEED)

    if err := unix.Munmap(b); err != nil { 
        return fmt.Errorf("munmap failed: %w", err) 
    }
    return nil
}
