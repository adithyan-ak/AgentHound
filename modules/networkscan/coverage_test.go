package networkscan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLogicalTargetSetIdentityTracksExpandedFileContents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.txt")
	writeTargets := func(contents string) TargetSetIdentity {
		t.Helper()
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatalf("write targets: %v", err)
		}
		hosts, err := Expand("@"+path, ExpandOptions{})
		if err != nil {
			t.Fatalf("expand targets: %v", err)
		}
		return LogicalTargetSetIdentity(hosts)
	}

	first := writeTargets("10.0.0.1\n10.0.0.2\n")
	reordered := writeTargets("10.0.0.2\n10.0.0.1\n10.0.0.1\n")
	if first != reordered {
		t.Fatalf("reordered duplicate targets changed identity: first=%+v reordered=%+v",
			first, reordered)
	}

	changed := writeTargets("10.0.0.1\n10.0.0.3\n")
	if first == changed {
		t.Fatalf("changed contents retained target identity: %+v", first)
	}
}

func TestLogicalTargetSetIdentityPreservesHostnames(t *testing.T) {
	first := LogicalTargetSetIdentity([]string{"internal.example", "10.0.0.1"})
	second := LogicalTargetSetIdentity([]string{"10.0.0.1", "internal.example"})
	if first != second {
		t.Fatalf("hostname identity depends on order: first=%+v second=%+v",
			first, second)
	}
	if first.Count != 2 {
		t.Fatalf("target count = %d, want 2", first.Count)
	}
}
