//go:build !unix

package module

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

const (
	dirLockTimeout  = 5 * time.Second
	dirLockInterval = 50 * time.Millisecond
	// dirLockStale is how long a held lock dir may persist before a waiter
	// treats it as abandoned by a crashed holder and attempts reclaim. The
	// WriteReceipt critical section is sub-millisecond; this threshold is
	// orders of magnitude larger so a live holder is never reclaimed.
	dirLockStale = 5 * time.Minute
)

const dirLockOwnerFile = "owner"

// lockFile acquires a directory-based lock (mkdir is atomic on all
// platforms). Spins with backoff until the lock is acquired or timeout.
// This is the fallback for non-unix platforms (Windows) where flock(2)
// is unavailable. Not a true advisory lock, but prevents the most common
// collision pattern. A crashed holder leaves the lock dir on disk; rather
// than wedging every future writer forever, a waiter that times out tries
// to reclaim a lock dir older than dirLockStale via an atomic
// rename-then-remove, which only one racer can win.
func lockFile(path string) (io.Closer, error) {
	lockPath := path + ".lock"
	deadline := time.Now().Add(dirLockTimeout)
	for {
		err := os.Mkdir(lockPath, 0o700)
		if err == nil {
			writeLockOwner(lockPath)
			return &dirLock{path: lockPath}, nil
		}
		if !os.IsExist(err) {
			return nil, err
		}
		if time.Now().After(deadline) {
			if reclaimStaleLock(lockPath) {
				deadline = time.Now().Add(dirLockTimeout)
				continue
			}
			return nil, fmt.Errorf("lock timeout: could not acquire %s; if no other agenthound process is running, a prior run may have crashed — remove %s manually", lockPath, lockPath)
		}
		time.Sleep(dirLockInterval)
	}
}

// writeLockOwner stamps the lock dir with the acquire time so a later
// waiter can decide whether the lock is stale. Best-effort: if the stamp
// can't be written the lock still holds; the waiter just won't reclaim it
// and will fail closed with the manual-removal hint instead.
func writeLockOwner(lockPath string) {
	owner := filepath.Join(lockPath, dirLockOwnerFile)
	_ = os.WriteFile(owner, []byte(strconv.FormatInt(time.Now().UnixNano(), 10)), 0o600)
}

// reclaimStaleLock attempts to take over a lock dir abandoned by a crashed
// holder. It returns true only if it successfully removed a dir it proved
// stale, so the caller should retry acquisition. The rename is the atomic
// arbiter: if two waiters race, each renames to a distinct unique name and
// only the one whose source still exists at lockPath wins; the loser's
// rename fails with ENOENT and it simply retries the acquire loop.
func reclaimStaleLock(lockPath string) bool {
	if !lockIsStale(lockPath) {
		return false
	}
	staged := fmt.Sprintf("%s.reclaim.%d", lockPath, time.Now().UnixNano())
	if err := os.Rename(lockPath, staged); err != nil {
		// Someone else won the rename (ENOENT) or the dir vanished — let
		// the caller retry the acquire loop either way.
		return false
	}
	_ = os.RemoveAll(staged)
	return true
}

// lockIsStale reports whether the lock dir's owner stamp is older than
// dirLockStale. A dir with no readable stamp is treated as NOT stale: we
// refuse to reclaim a lock we can't prove abandoned, preferring the
// fail-closed manual-removal error over racing a possibly-live holder.
func lockIsStale(lockPath string) bool {
	data, err := os.ReadFile(filepath.Join(lockPath, dirLockOwnerFile))
	if err != nil {
		return false
	}
	ns, err := strconv.ParseInt(string(data), 10, 64)
	if err != nil {
		return false
	}
	return time.Since(time.Unix(0, ns)) > dirLockStale
}

type dirLock struct {
	path string
}

func (l *dirLock) Close() error {
	if err := os.RemoveAll(l.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
