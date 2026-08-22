//go:build windows

package checkpoint

import (
	"fmt"

	"golang.org/x/sys/windows"
)

func replace(tmpPath, path, _ string) error {
	from, err := windows.UTF16PtrFromString(tmpPath)
	if err != nil {
		return checkpointError(Replace, false, fmt.Errorf("encode temporary path: %w", err))
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return checkpointError(Replace, false, fmt.Errorf("encode destination path: %w", err))
	}
	flags := uint32(windows.MOVEFILE_REPLACE_EXISTING | windows.MOVEFILE_WRITE_THROUGH)
	if err := windows.MoveFileEx(from, to, flags); err != nil {
		return checkpointError(Replace, false, fmt.Errorf("MoveFileExW replacement: %w", err))
	}
	return nil
}
