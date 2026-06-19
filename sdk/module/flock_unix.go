//go:build unix

package module

import (
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// lockFile acquires an exclusive advisory lock on a sibling .lock file.
// The returned io.Closer releases the lock but intentionally leaves the
// lockfile on disk: unlinking it on release lets a waiter holding the old
// inode coexist with a new process that re-creates a fresh inode at the
// same path, defeating mutual exclusion. A persistent 0600 sidecar is
// reused, not leaked. Blocks until the lock is acquired (no timeout — the
// critical section inside WriteReceipt is sub-millisecond, so contention
// resolves fast).
func lockFile(path string) (io.Closer, error) {
	lockPath := path + ".lock"
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &fileLock{f: f}, nil
}

type fileLock struct {
	f *os.File
}

func (l *fileLock) Close() error {
	_ = unix.Flock(int(l.f.Fd()), unix.LOCK_UN)
	return l.f.Close()
}
