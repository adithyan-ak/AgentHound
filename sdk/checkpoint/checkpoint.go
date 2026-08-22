// Package checkpoint provides durable, atomic replacement of a single file.
package checkpoint

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type stagedFile interface {
	Name() string
	Write([]byte) (int, error)
	Sync() error
	Chmod(os.FileMode) error
	Close() error
}

var (
	createStagedFile = func(dir, pattern string) (stagedFile, error) {
		return os.CreateTemp(dir, pattern)
	}
	replaceStagedFile = replace
)

// ErrorStage identifies where a checkpoint write failed.
type ErrorStage string

const (
	// Stage means the temporary file could not be completely written and
	// synchronized. The destination was not changed.
	Stage ErrorStage = "stage"
	// Replace means the atomic replacement failed. The destination was not
	// changed by this Write call.
	Replace ErrorStage = "replace"
	// Durability means replacement committed, but its directory entry could
	// not be confirmed durable.
	Durability ErrorStage = "durability"
)

// CheckpointError reports both the failing phase and whether the new bytes
// became visible at path. Committed is true only for a post-replacement
// durability failure.
type CheckpointError struct {
	Phase     string
	Committed bool
	Err       error
}

func (e *CheckpointError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("checkpoint %s (committed=%t): %v", e.Phase, e.Committed, e.Err)
}

func (e *CheckpointError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// Write atomically replaces path with data. The temporary file is created in
// the destination directory, synchronized, and then replaced in one operation.
// No backup or sidecar is retained. New files are private to the current user.
func Write(path string, data []byte) (retErr error) {
	if path == "" {
		return checkpointError(Stage, false, errors.New("path is required"))
	}
	dir := filepath.Dir(path)
	tmp, err := createStagedFile(dir, "."+filepath.Base(path)+".checkpoint-*")
	if err != nil {
		return checkpointError(Stage, false, fmt.Errorf("create same-directory temporary file: %w", err))
	}
	tmpPath := tmp.Name()
	defer func() {
		if tmp != nil {
			_ = tmp.Close()
		}
		if retErr != nil {
			_ = os.Remove(tmpPath)
		}
	}()

	written, err := tmp.Write(data)
	if err != nil {
		return checkpointError(Stage, false, fmt.Errorf("write temporary file: %w", err))
	}
	if written != len(data) {
		return checkpointError(Stage, false, fmt.Errorf("write temporary file: short write: wrote %d of %d bytes", written, len(data)))
	}
	if err := tmp.Sync(); err != nil {
		return checkpointError(Stage, false, fmt.Errorf("synchronize temporary file: %w", err))
	}
	if err := tmp.Chmod(0o600); err != nil {
		return checkpointError(Stage, false, fmt.Errorf("set temporary file permissions: %w", err))
	}
	if err := tmp.Close(); err != nil {
		return checkpointError(Stage, false, fmt.Errorf("close temporary file: %w", err))
	}
	tmp = nil

	if err := replaceStagedFile(tmpPath, path, dir); err != nil {
		return err
	}
	return nil
}

func checkpointError(stage ErrorStage, committed bool, err error) *CheckpointError {
	return &CheckpointError{Phase: string(stage), Committed: committed, Err: err}
}
