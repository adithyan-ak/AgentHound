//go:build windows

package module

import (
	"fmt"

	"golang.org/x/sys/windows"
)

func durableReplaceReceipt(tmpPath, path, _ string) error {
	from, err := windows.UTF16PtrFromString(tmpPath)
	if err != nil {
		return fmt.Errorf("encode temporary receipt path: %w", err)
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("encode receipt path: %w", err)
	}
	flags := uint32(windows.MOVEFILE_REPLACE_EXISTING | windows.MOVEFILE_WRITE_THROUGH)
	if err := windows.MoveFileEx(from, to, flags); err != nil {
		return fmt.Errorf("durable receipt replacement: %w", err)
	}
	return nil
}
