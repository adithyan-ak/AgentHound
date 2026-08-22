package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveInstructionRecursion(t *testing.T) {
	if root, deep, err := resolveInstructionRecursion(false); err != nil || root != "" || deep {
		t.Fatalf("default resolution = (%q, %v, %v), want no deep root", root, deep, err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home dir: %v", err)
	}
	want, err := filepath.Abs(home)
	if err != nil {
		t.Fatal(err)
	}
	root, deep, err := resolveInstructionRecursion(true)
	if err != nil {
		t.Fatal(err)
	}
	if root != filepath.Clean(want) || !deep {
		t.Fatalf("deep resolution = (%q, %v), want canonical home %q", root, deep, filepath.Clean(want))
	}
}
