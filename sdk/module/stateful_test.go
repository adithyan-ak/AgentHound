package module_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/module"
)

func setStateRoot(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("AGENTHOUND_STATE_DIR", dir)
}

func TestFileStatefulModule_WriteReadRoundTrip(t *testing.T) {
	tmp := t.TempDir()
	setStateRoot(t, tmp)

	s := module.NewFileStatefulModule("mcp.poison")
	r := &action.PoisonReceipt{
		ModuleID:        "mcp.poison",
		EngagementID:    "DC35-DEMO",
		TargetID:        "tool-id-123",
		OriginalContent: "Original tool description",
		InjectedContent: "PWNED",
		Mode:            "replace",
		AppliedAt:       time.Now().UTC(),
		DryRun:          false,
	}
	path, err := s.WriteReceipt("DC35-DEMO", r)
	if err != nil {
		t.Fatalf("WriteReceipt: %v", err)
	}
	wantPath := filepath.Join(tmp, "mcp.poison", "DC35-DEMO.json")
	if path != wantPath {
		t.Errorf("path = %q, want %q", path, wantPath)
	}

	got, err := s.ReadReceipts("DC35-DEMO")
	if err != nil {
		t.Fatalf("ReadReceipts: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 receipt, got %d", len(got))
	}
	rec, ok := got[0].(*action.PoisonReceipt)
	if !ok {
		t.Fatalf("expected *PoisonReceipt, got %T", got[0])
	}
	if rec.OriginalContent != "Original tool description" {
		t.Errorf("OriginalContent round-trip mismatch: %q", rec.OriginalContent)
	}
	if rec.TargetID != "tool-id-123" {
		t.Errorf("TargetID round-trip mismatch: %q", rec.TargetID)
	}
}

func TestFileStatefulModule_AppendsMultipleReceipts(t *testing.T) {
	tmp := t.TempDir()
	setStateRoot(t, tmp)

	s := module.NewFileStatefulModule("mcp.poison")
	for i := 0; i < 3; i++ {
		r := &action.PoisonReceipt{
			ModuleID:     "mcp.poison",
			EngagementID: "ENG-1",
			TargetID:     "tool-" + string(rune('a'+i)),
			Mode:         "replace",
			AppliedAt:    time.Now().UTC(),
		}
		if _, err := s.WriteReceipt("ENG-1", r); err != nil {
			t.Fatalf("WriteReceipt[%d]: %v", i, err)
		}
	}
	got, err := s.ReadReceipts("ENG-1")
	if err != nil {
		t.Fatalf("ReadReceipts: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("expected 3 receipts, got %d", len(got))
	}
}

func TestFileStatefulModule_RejectsTraversalEngagementID(t *testing.T) {
	tmp := t.TempDir()
	setStateRoot(t, tmp)

	s := module.NewFileStatefulModule("mcp.poison")
	r := &action.PoisonReceipt{ModuleID: "mcp.poison"}
	for _, bad := range []string{"../escape", "engagement/with/slash", "..", "with space", ""} {
		if _, err := s.WriteReceipt(bad, r); err == nil {
			t.Errorf("expected error for engagement-id %q", bad)
		}
	}
}

func TestFileStatefulModule_ReadMissingEngagement(t *testing.T) {
	tmp := t.TempDir()
	setStateRoot(t, tmp)

	s := module.NewFileStatefulModule("mcp.poison")
	got, err := s.ReadReceipts("never-written")
	if err != nil {
		t.Fatalf("ReadReceipts on missing: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 receipts, got %d", len(got))
	}
}

func TestDefaultStateDir_RejectsBadModuleID(t *testing.T) {
	for _, bad := range []string{"../escape", "with space", "Capitalized", "weird$chars"} {
		if _, err := module.DefaultStateDir(bad); err == nil {
			t.Errorf("expected error for module ID %q", bad)
		}
	}
}
