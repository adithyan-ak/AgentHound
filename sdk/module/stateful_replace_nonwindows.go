//go:build !windows

package module

import (
	"fmt"
	"os"
	"runtime"
)

func durableReplaceReceipt(tmpPath, path, dirPath string) error {
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("atomic rename: %w", err)
	}
	switch runtime.GOOS {
	case "aix", "android", "darwin", "dragonfly", "freebsd", "illumos", "ios", "linux", "netbsd", "openbsd", "solaris":
	default:
		return nil
	}
	dir, err := os.Open(dirPath)
	if err != nil {
		return fmt.Errorf("open receipt directory for sync: %w", err)
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return fmt.Errorf("sync receipt directory: %w", err)
	}
	if err := dir.Close(); err != nil {
		return fmt.Errorf("close receipt directory after sync: %w", err)
	}
	return nil
}
