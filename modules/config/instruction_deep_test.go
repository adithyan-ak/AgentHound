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

// A tree that truncates (here, the shared rule limit) must contribute ZERO
// observations — property-incomplete nodes would poison the graph-wide
// publication gate and wedge every future scan. Coverage still records the
// truncation.
func TestDiscoverInstructionsTruncatedTreeEmitsNoObservations(t *testing.T) {
	project := t.TempDir()
	writeInstrRule(t, filepath.Join(project, ".cursor", "rules", "a.mdc"), "rule a")
	writeInstrRule(t, filepath.Join(project, ".cursor", "rules", "b.mdc"), "rule b")
	engine := testInstrEngine(t)

	oldLimit := instructionRuleLimit
	instructionRuleLimit = 1
	t.Cleanup(func() { instructionRuleLimit = oldLimit })

	d := DiscoverInstructions(context.Background(), "", project, InstructionScan{RecursiveRoot: project, Deep: true}, engine)

	var treeState ingest.OutcomeState
	for _, oc := range d.Outcomes {
		if oc.Method == "cursor_rule_tree" {
			treeState = oc.State
		}
	}
	if treeState != ingest.OutcomeTruncated {
		t.Fatalf("tree state = %q, want truncated", treeState)
	}
	if len(d.Observations) != 0 {
		t.Fatalf("truncated tree emitted %d observations, want 0 (property-incomplete nodes wedge publication)", len(d.Observations))
	}
}

// The depth cap was removed: a legitimately deep .cursor/rules tree must be
// found and must NOT silently certify complete coverage while omitting it.
func TestDiscoverInstructionsDeepNestingNotSilentlySkipped(t *testing.T) {
	project := t.TempDir()
	deepDir := project
	for i := 0; i < 30; i++ {
		deepDir = filepath.Join(deepDir, "d")
	}
	writeInstrRule(t, filepath.Join(deepDir, ".cursor", "rules", "deep.mdc"), "deep rule")
	engine := testInstrEngine(t)

	d := DiscoverInstructions(context.Background(), "", project, InstructionScan{RecursiveRoot: project}, engine)
	var found bool
	for _, obs := range d.Observations {
		if strings.HasSuffix(obs.Info.Path, "deep.mdc") {
			found = true
		}
	}
	if !found {
		t.Fatal("deeply nested rule was silently skipped")
	}
	if !d.InstructionCoverageComplete {
		t.Fatal("coverage falsely reported incomplete for a fully-walked deep tree")
	}
}

// Junk pruning must apply to subdirectories, never to the explicitly-selected
// root itself.
func TestDiscoverInstructionsDoesNotPruneSelectedRoot(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "vendor") // a pruned NAME, but it is the selected root
	writeInstrRule(t, filepath.Join(root, ".cursor", "rules", "r.mdc"), "rule")
	engine := testInstrEngine(t)

	d := DiscoverInstructions(context.Background(), "", root, InstructionScan{RecursiveRoot: root}, engine)
	var found bool
	for _, obs := range d.Observations {
		if strings.HasSuffix(obs.Info.Path, "r.mdc") {
			found = true
		}
	}
	if !found {
		t.Fatal("explicitly selected root named 'vendor' was pruned and returned nothing")
	}
}

// Trash is pruned cross-OS: macOS .Trash, the freedesktop XDG home trash
// (a dir named Trash), and per-mount .Trash-<uid>.
func TestInstructionWalkPrunesCrossOSTrash(t *testing.T) {
	project := t.TempDir()
	writeInstrRule(t, filepath.Join(project, ".local", "share", "Trash", "files", "gone", ".cursor", "rules", "x.mdc"), "deleted")
	writeInstrRule(t, filepath.Join(project, ".Trash-1000", "files", "gone", ".cursor", "rules", "y.mdc"), "deleted")
	writeInstrRule(t, filepath.Join(project, ".cursor", "rules", "keep.mdc"), "keep")
	engine := testInstrEngine(t)

	d := DiscoverInstructions(context.Background(), "", project, InstructionScan{RecursiveRoot: project, Deep: true}, engine)
	var sawKeep bool
	for _, obs := range d.Observations {
		// x.mdc / y.mdc live inside the trash trees; keep.mdc does not.
		if strings.HasSuffix(obs.Info.Path, "x.mdc") || strings.HasSuffix(obs.Info.Path, "y.mdc") {
			t.Fatalf("collected a rule from a trash directory: %s", obs.Info.Path)
		}
		if strings.HasSuffix(obs.Info.Path, "keep.mdc") {
			sawKeep = true
		}
	}
	if !sawKeep {
		t.Fatal("did not collect the non-trash rule")
	}
}

// The search budget counts directories, not files: a folder with many files but
// few subdirectories must not exhaust the budget and truncate the search.
func TestInstructionWalkBudgetCountsDirectoriesNotFiles(t *testing.T) {
	project := t.TempDir()
	for i := 0; i < 50; i++ {
		writeInstrRule(t, filepath.Join(project, "assets", "f"+strconv.Itoa(i)+".txt"), "x")
	}
	writeInstrRule(t, filepath.Join(project, ".cursor", "rules", "r.mdc"), "rule")
	engine := testInstrEngine(t)

	// A budget of 10 would truncate if the 50 files were counted; only ~3
	// directories are descended, so the search must complete.
	oldLimit := instructionTraversalEntryLimit
	instructionTraversalEntryLimit = 10
	t.Cleanup(func() { instructionTraversalEntryLimit = oldLimit })

	d := DiscoverInstructions(context.Background(), "", project, InstructionScan{RecursiveRoot: project}, engine)
	trav := traversalOutcome(d.Outcomes)
	if trav == nil || trav.State != ingest.OutcomeComplete {
		t.Fatalf("traversal = %+v, want complete (files must not consume the directory budget)", trav)
	}
	var found bool
	for _, obs := range d.Observations {
		if strings.HasSuffix(obs.Info.Path, "r.mdc") {
			found = true
		}
	}
	if !found {
		t.Fatal("did not find the cursor rule under a file-heavy tree")
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
