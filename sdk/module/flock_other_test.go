//go:build !unix

package module

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestDirLockReclaimsStaleLock verifies a lock dir abandoned by a crashed
// holder (owner stamp older than dirLockStale) is reclaimed rather than
// wedging the writer forever.
func TestDirLockReclaimsStaleLock(t *testing.T) {
	tmp := t.TempDir()
	target := filepath.Join(tmp, "ENG.json")
	lockPath := target + ".lock"

	if err := os.Mkdir(lockPath, 0o700); err != nil {
		t.Fatalf("seed lock dir: %v", err)
	}
	stale := time.Now().Add(-2 * dirLockStale).UnixNano()
	owner := filepath.Join(lockPath, dirLockOwnerFile)
	if err := os.WriteFile(owner, []byte(strconv.FormatInt(stale, 10)), 0o600); err != nil {
		t.Fatalf("seed owner stamp: %v", err)
	}

	closer, err := lockFile(target)
	if err != nil {
		t.Fatalf("lockFile should reclaim a stale lock, got error: %v", err)
	}
	if err := closer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Errorf("lock dir should be gone after Close, stat err = %v", err)
	}
}

// TestDirLockFailsClosedOnFreshLock verifies a live (recently stamped) lock
// dir is NOT reclaimed; the waiter fails closed with an actionable error
// naming the lock path.
func TestDirLockFailsClosedOnFreshLock(t *testing.T) {
	tmp := t.TempDir()
	target := filepath.Join(tmp, "ENG.json")
	lockPath := target + ".lock"

	if err := os.Mkdir(lockPath, 0o700); err != nil {
		t.Fatalf("seed lock dir: %v", err)
	}
	fresh := time.Now().UnixNano()
	owner := filepath.Join(lockPath, dirLockOwnerFile)
	if err := os.WriteFile(owner, []byte(strconv.FormatInt(fresh, 10)), 0o600); err != nil {
		t.Fatalf("seed owner stamp: %v", err)
	}

	_, err := lockFile(target)
	if err == nil {
		t.Fatal("expected timeout error for a fresh (live) lock dir")
	}
	if !strings.Contains(err.Error(), lockPath) {
		t.Errorf("error should name the lock path %q for the operator, got: %v", lockPath, err)
	}
	if _, statErr := os.Stat(lockPath); statErr != nil {
		t.Errorf("live lock dir must not be removed, stat err = %v", statErr)
	}
}

// TestDirLockNoStampNotReclaimed verifies a lock dir with no readable owner
// stamp is treated as live (fail-closed), never reclaimed — we refuse to
// race a holder we cannot prove crashed.
func TestDirLockNoStampNotReclaimed(t *testing.T) {
	tmp := t.TempDir()
	target := filepath.Join(tmp, "ENG.json")
	lockPath := target + ".lock"

	if err := os.Mkdir(lockPath, 0o700); err != nil {
		t.Fatalf("seed lock dir: %v", err)
	}

	if _, err := lockFile(target); err == nil {
		t.Fatal("expected timeout error for a lock dir with no owner stamp")
	}
	if _, statErr := os.Stat(lockPath); statErr != nil {
		t.Errorf("unstamped lock dir must not be removed, stat err = %v", statErr)
	}
}

// TestDirLockAcquireWriteStamp verifies the happy path stamps owner metadata
// so a future waiter can reason about staleness.
func TestDirLockAcquireWriteStamp(t *testing.T) {
	tmp := t.TempDir()
	target := filepath.Join(tmp, "ENG.json")

	closer, err := lockFile(target)
	if err != nil {
		t.Fatalf("lockFile: %v", err)
	}
	stamp := filepath.Join(target+".lock", dirLockOwnerFile)
	if _, err := os.Stat(stamp); err != nil {
		t.Errorf("expected owner stamp at %s, stat err = %v", stamp, err)
	}
	if err := closer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
