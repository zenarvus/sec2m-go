//go:build darwin || ios

package securemem

import (
    "fmt"
    "golang.org/x/sys/unix"
)

func Setup() error { return nil }

func LockMemory(b ByteSlice) error {
    if len(b.Bytes) == 0 { return nil }
    return unix.Mlock(b.Bytes)
}

func UnlockMemory(b ByteSlice) error {
    if len(b.Bytes) == 0 { return nil }
    return unix.Munlock(b.Bytes)
}

func Alloc(size int, opts ...Option) (ByteSlice, error) {
    if size <= 0 { return ByteSlice{}, fmt.Errorf("invalid allocation size: %d", size) }

    cfg := &config{lock: false}
    for _, opt := range opts { opt(cfg) }

    // MAP_ANON is used on Darwin instead of MAP_ANONYMOUS
    b, err := unix.Mmap(
        -1, 0,
        size,
        unix.PROT_READ|unix.PROT_WRITE,
        unix.MAP_PRIVATE|unix.MAP_ANON,
    )
    if err != nil { return ByteSlice{}, fmt.Errorf("mmap failed: %w", err) }

    if cfg.lock {
        if err := unix.Mlock(b); err != nil {
            _ = unix.Munmap(b)
            return ByteSlice{}, fmt.Errorf("mlock failed: %w", err)
        }
    }

	slice := &ByteSlice{
		Bytes: b,
		freed: false,
	}
	slice.Dealloc = func()error{ return dealloc(slice) }

	return *slice, nil
}

func dealloc(b *ByteSlice) error {
	if b == nil || b.freed {return nil}
    if len(b.Bytes) == 0 { b.freed = true; return nil }

    ZeroBytes(b.Bytes)
    _ = unix.Munlock(b.Bytes)
    _ = unix.Madvise(b.Bytes, unix.MADV_DONTNEED)

    if err := unix.Munmap(b.Bytes); err != nil { 
        return fmt.Errorf("munmap failed: %w", err) 
    }

	b.freed = true

    return nil
}
