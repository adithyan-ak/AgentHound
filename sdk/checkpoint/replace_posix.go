//go:build !windows

package checkpoint

import (
	"fmt"
	"os"
)

func replace(tmpPath, path, dirPath string) error {
	if err := os.Rename(tmpPath, path); err != nil {
		return checkpointError(Replace, false, fmt.Errorf("atomic rename: %w", err))
	}

	dir, err := os.Open(dirPath)
	if err != nil {
		return checkpointError(Durability, true, fmt.Errorf("open parent directory for sync: %w", err))
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return checkpointError(Durability, true, fmt.Errorf("sync parent directory: %w", err))
	}
	if err := dir.Close(); err != nil {
		return checkpointError(Durability, true, fmt.Errorf("close parent directory after sync: %w", err))
	}
	return nil
}
