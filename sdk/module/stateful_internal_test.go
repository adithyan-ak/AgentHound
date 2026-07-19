package module

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPersistReceiptFileCleansTemporaryFileAfterRenameFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "receipt.json")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := persistReceiptFile(path, []byte("[]")); err == nil {
		t.Fatal("expected rename failure")
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".receipt.json.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary receipt files remain after failure: %v", matches)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		t.Fatal("failed replacement changed the existing destination")
	}
}
