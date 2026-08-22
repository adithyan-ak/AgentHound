package checkpoint

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type failingStagedFile struct {
	file  *os.File
	stage string
}

func (f *failingStagedFile) Name() string { return f.file.Name() }
func (f *failingStagedFile) Write(data []byte) (int, error) {
	switch f.stage {
	case "write":
		return 0, errors.New("injected write failure")
	case "short-write":
		return len(data) / 2, nil
	default:
		return f.file.Write(data)
	}
}
func (f *failingStagedFile) Sync() error {
	if f.stage == "sync" {
		return errors.New("injected sync failure")
	}
	return f.file.Sync()
}
func (f *failingStagedFile) Chmod(mode os.FileMode) error {
	if f.stage == "chmod" {
		return errors.New("injected chmod failure")
	}
	return f.file.Chmod(mode)
}
func (f *failingStagedFile) Close() error {
	err := f.file.Close()
	if f.stage == "close" {
		return errors.New("injected close failure")
	}
	return err
}

func TestWriteCreatesAndReplacesOneFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "artifact.json")

	if err := Write(path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, []byte("second")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "second" {
		t.Fatalf("artifact = %q, want second", got)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "artifact.json" {
		t.Fatalf("checkpoint left sidecars: %+v", entries)
	}
}

func TestWriteStageFailureIsUncommitted(t *testing.T) {
	err := Write(filepath.Join(t.TempDir(), "missing", "artifact.json"), []byte("data"))
	var checkpointErr *CheckpointError
	if !errors.As(err, &checkpointErr) {
		t.Fatalf("error = %T %v, want CheckpointError", err, err)
	}
	if checkpointErr.Phase != string(Stage) || checkpointErr.Committed {
		t.Fatalf("checkpoint error = %+v, want stage/uncommitted", checkpointErr)
	}
}

func TestWriteReplaceFailureIsUncommittedAndCleansTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "artifact.json")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}

	err := Write(target, []byte("data"))
	var checkpointErr *CheckpointError
	if !errors.As(err, &checkpointErr) {
		t.Fatalf("error = %T %v, want CheckpointError", err, err)
	}
	if checkpointErr.Phase != string(Replace) || checkpointErr.Committed {
		t.Fatalf("checkpoint error = %+v, want replace/uncommitted", checkpointErr)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "artifact.json" {
		t.Fatalf("failed checkpoint left sidecars: %+v", entries)
	}
}

func TestCheckpointErrorUnwraps(t *testing.T) {
	cause := errors.New("cause")
	err := checkpointError(Durability, true, cause)
	if !errors.Is(err, cause) || err.Phase != string(Durability) || !err.Committed {
		t.Fatalf("error does not preserve cause and commit state: %+v", err)
	}
}

func TestWritePreCommitFailuresPreservePreviousOrAbsentDestination(t *testing.T) {
	originalCreate := createStagedFile
	originalReplace := replaceStagedFile
	defer func() {
		createStagedFile = originalCreate
		replaceStagedFile = originalReplace
	}()

	for _, stage := range []string{"write", "short-write", "sync", "chmod", "close", "replace"} {
		for _, existing := range []bool{false, true} {
			t.Run(stage+map[bool]string{false: "/first", true: "/existing"}[existing], func(t *testing.T) {
				dir := t.TempDir()
				path := filepath.Join(dir, "artifact.json")
				if existing {
					if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
						t.Fatal(err)
					}
				}

				createStagedFile = func(dir, pattern string) (stagedFile, error) {
					file, err := os.CreateTemp(dir, pattern)
					if err != nil {
						return nil, err
					}
					return &failingStagedFile{file: file, stage: stage}, nil
				}
				replaceStagedFile = originalReplace
				if stage == "replace" {
					replaceStagedFile = func(string, string, string) error {
						return checkpointError(Replace, false, errors.New("injected replace failure"))
					}
				}

				err := Write(path, []byte("new-complete-json"))
				var checkpointErr *CheckpointError
				if !errors.As(err, &checkpointErr) || checkpointErr.Committed {
					t.Fatalf("error = %#v, want uncommitted CheckpointError", err)
				}
				got, readErr := os.ReadFile(path)
				if existing {
					if readErr != nil || string(got) != "old" {
						t.Fatalf("destination = %q, %v; want old bytes", got, readErr)
					}
				} else if !errors.Is(readErr, os.ErrNotExist) {
					t.Fatalf("first destination exists or read failed unexpectedly: %q, %v", got, readErr)
				}
				entries, readDirErr := os.ReadDir(dir)
				if readDirErr != nil {
					t.Fatal(readDirErr)
				}
				if len(entries) != map[bool]int{false: 0, true: 1}[existing] {
					t.Fatalf("failed checkpoint left temporary files: %+v", entries)
				}
			})
		}
	}
}

func TestWriteCommittedDurabilityFailureLeavesNewCompleteDestination(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "artifact.json")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	originalReplace := replaceStagedFile
	defer func() { replaceStagedFile = originalReplace }()
	replaceStagedFile = func(tmpPath, destination, dirPath string) error {
		if err := originalReplace(tmpPath, destination, dirPath); err != nil {
			return err
		}
		return checkpointError(Durability, true, errors.New("injected directory sync failure"))
	}

	err := Write(path, []byte("new-complete-json"))
	var checkpointErr *CheckpointError
	if !errors.As(err, &checkpointErr) || !checkpointErr.Committed || checkpointErr.Phase != string(Durability) {
		t.Fatalf("error = %#v, want committed durability error", err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil || string(got) != "new-complete-json" {
		t.Fatalf("destination = %q, %v; want new complete bytes", got, readErr)
	}
}
