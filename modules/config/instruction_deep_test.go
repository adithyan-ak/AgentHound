package config

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

func writeInstrRule(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func traversalOutcome(outcomes []ingest.CollectionOutcome) *ingest.CollectionOutcome {
	for i := range outcomes {
		if outcomes[i].Method == "cursor_rule_traversal" {
			return &outcomes[i]
		}
	}
	return nil
}

// A host-level scan (no --project-dir, no --deep) must NEVER run the recursive
// .cursor/rules walk — that is the wedge fix.
func TestDiscoverInstructionsRecursionGating(t *testing.T) {
	project := t.TempDir()
	writeInstrRule(t, filepath.Join(project, ".cursor", "rules", "root.mdc"), "rule")
	engine := testInstrEngine(t)

	none := DiscoverInstructions(context.Background(), "", project, InstructionScan{}, engine)
	for _, oc := range none.Outcomes {
		if strings.HasPrefix(oc.Method, "cursor_rule") {
			t.Fatalf("recursion ran without an explicit root: %+v", oc)
		}
	}
	if !none.InstructionCoverageComplete {
		t.Fatal("no-walk mode must report instruction coverage complete")
	}

	strict := DiscoverInstructions(context.Background(), "", project, InstructionScan{RecursiveRoot: project}, engine)
	trav := traversalOutcome(strict.Outcomes)
	if trav == nil {
		t.Fatal("strict recursion did not run for an explicit project root")
	}
	if trav.Advisory {
		t.Fatalf("strict --project-dir traversal must not be advisory: %+v", trav)
	}

	deep := DiscoverInstructions(context.Background(), "", project, InstructionScan{RecursiveRoot: project, Deep: true}, engine)
	for _, oc := range deep.Outcomes {
		if strings.HasPrefix(oc.Method, "cursor_rule") && !oc.Advisory {
			t.Fatalf("deep-mode recursive outcome must be advisory: %+v", oc)
		}
	}
}

// Deep truncation is advisory + coverage-incomplete; strict truncation is
// non-advisory + coverage-incomplete.
func TestDiscoverInstructionsTruncationAdvisory(t *testing.T) {
	project := t.TempDir()
	for i := 0; i < 12; i++ {
		writeInstrRule(t, filepath.Join(project, "d"+strconv.Itoa(i), "f.txt"), "x")
	}
	writeInstrRule(t, filepath.Join(project, ".cursor", "rules", "root.mdc"), "rule")
	engine := testInstrEngine(t)

	oldDeep := deepInstructionEntryLimit
	deepInstructionEntryLimit = 3
	t.Cleanup(func() { deepInstructionEntryLimit = oldDeep })
	deep := DiscoverInstructions(context.Background(), "", project, InstructionScan{RecursiveRoot: project, Deep: true}, engine)
	trav := traversalOutcome(deep.Outcomes)
	if trav == nil || trav.State != ingest.OutcomeTruncated || !trav.Advisory {
		t.Fatalf("deep traversal = %+v, want truncated + advisory", trav)
	}
	if deep.InstructionCoverageComplete {
		t.Fatal("deep truncation must report instruction coverage incomplete")
	}

	oldStrict := instructionTraversalEntryLimit
	instructionTraversalEntryLimit = 3
	t.Cleanup(func() { instructionTraversalEntryLimit = oldStrict })
	strict := DiscoverInstructions(context.Background(), "", project, InstructionScan{RecursiveRoot: project}, engine)
	strictTrav := traversalOutcome(strict.Outcomes)
	if strictTrav == nil || strictTrav.State != ingest.OutcomeTruncated {
		t.Fatalf("strict traversal = %+v, want truncated", strictTrav)
	}
	if strictTrav.Advisory {
		t.Fatalf("strict truncation must not be advisory: %+v", strictTrav)
	}
	if strict.InstructionCoverageComplete {
		t.Fatal("strict truncation must report instruction coverage incomplete")
	}
}

func TestInstructionWalkPrunesJunkDirs(t *testing.T) {
	project := t.TempDir()
	writeInstrRule(t, filepath.Join(project, "node_modules", ".cursor", "rules", "junk.mdc"), "junk")
	writeInstrRule(t, filepath.Join(project, ".Trash", ".cursor", "rules", "trash.mdc"), "trash")
	writeInstrRule(t, filepath.Join(project, ".cursor", "rules", "real.mdc"), "real")
	engine := testInstrEngine(t)

	d := DiscoverInstructions(context.Background(), "", project, InstructionScan{RecursiveRoot: project}, engine)
	var sawReal bool
	for _, obs := range d.Observations {
		if strings.Contains(obs.Info.Path, "node_modules") || strings.Contains(obs.Info.Path, ".Trash") {
			t.Fatalf("collected a rule from a pruned dir: %s", obs.Info.Path)
		}
		if strings.HasSuffix(obs.Info.Path, "real.mdc") {
			sawReal = true
		}
	}
	if !sawReal {
		t.Fatal("did not collect the non-pruned rule")
	}
}
