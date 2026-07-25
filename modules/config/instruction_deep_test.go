package config

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

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

func instructionOutcomeForMethod(outcomes []ingest.CollectionOutcome, method string) *ingest.CollectionOutcome {
	for i := range outcomes {
		if outcomes[i].Method == method {
			return &outcomes[i]
		}
	}
	return nil
}

func TestInstructionRegistryContractMatchesSDK(t *testing.T) {
	got := instructionRegistryContract()
	want := ingest.CurrentInstructionRegistryContract()
	if !got.Equal(want) {
		t.Fatalf("config registry contract = %+v, SDK/server contract = %+v", got, want)
	}
}

func TestInstructionOwnerKeysExcludeRegistryContract(t *testing.T) {
	root := canonicalConfigPath(t.TempDir())
	beforeRoot := instructionRootKey(instructionRootDeep, root)
	beforeChild := instructionChildKey(beforeRoot, filepath.Join(root, "repo", "AGENTS.md"))

	// Contract evolution affects comparison eligibility, never lifecycle identity.
	changedContract := ingest.RegistryContract{
		Generation: instructionRegistryGeneration + 1,
		Digest:     "sha256:different",
	}
	if changedContract.Equal(instructionRegistryContract()) {
		t.Fatal("test contract did not change")
	}
	afterRoot := instructionRootKey(instructionRootDeep, root)
	afterChild := instructionChildKey(afterRoot, filepath.Join(root, "repo", "AGENTS.md"))
	if beforeRoot != afterRoot || beforeChild != afterChild {
		t.Fatalf("registry contract changed stable owners: root %q/%q child %q/%q", beforeRoot, afterRoot, beforeChild, afterChild)
	}
}

func TestDiscoverInstructionsExactRegistry(t *testing.T) {
	project := t.TempDir()
	writeInstrRule(t, filepath.Join(project, "AGENTS.md"), "agents")
	writeInstrRule(t, filepath.Join(project, "CLAUDE.md"), "claude")
	writeInstrRule(t, filepath.Join(project, ".claude", "CLAUDE.md"), "claude nested")
	writeInstrRule(t, filepath.Join(project, ".claude", "rules", "team.md"), "claude rule")
	writeInstrRule(t, filepath.Join(project, ".cursorrules"), "cursor")
	writeInstrRule(t, filepath.Join(project, ".cursor", "rules", "team.mdc"), "cursor rule")
	writeInstrRule(t, filepath.Join(project, ".github", "copilot-instructions.md"), "copilot")
	writeInstrRule(t, filepath.Join(project, ".github", "instructions", "team.instructions.md"), "copilot rule")
	writeInstrRule(t, filepath.Join(project, ".github", "instructions", "ignored.md"), "wrong suffix")
	writeInstrRule(t, filepath.Join(project, "nested", "AGENTS.md"), "deep only")

	discovery := DiscoverInstructions(context.Background(), "", project, InstructionScan{}, testInstrEngine(t))
	if len(discovery.Observations) != 8 {
		var paths []string
		for _, observation := range discovery.Observations {
			paths = append(paths, observation.Info.Path)
		}
		t.Fatalf("exact observations = %v, want all 8 registered project sources", paths)
	}
	for _, observation := range discovery.Observations {
		if strings.Contains(observation.Info.Path, filepath.Join("nested", "AGENTS.md")) {
			t.Fatalf("exact scan escaped registered root/subtrees: %s", observation.Info.Path)
		}
	}
	root := instructionOutcomeForMethod(discovery.Outcomes, ingest.InstructionMethodExactProject)
	if root == nil || root.State != ingest.OutcomeComplete {
		t.Fatalf("exact-project root = %+v, want complete", root)
	}
}

func TestDiscoverInstructionsNestedSourcesRequireDeep(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "repo")
	writeInstrRule(t, filepath.Join(home, "AGENTS.md"), "home exact")
	writeInstrRule(t, filepath.Join(project, "AGENTS.md"), "project")
	writeInstrRule(t, filepath.Join(project, ".claude", "rules", "team.md"), "claude")
	writeInstrRule(t, filepath.Join(project, ".cursor", "rules", "team.mdc"), "cursor")
	writeInstrRule(t, filepath.Join(project, ".github", "instructions", "team.instructions.md"), "copilot")

	exact := DiscoverInstructions(context.Background(), home, "", InstructionScan{}, testInstrEngine(t))
	if len(exact.Observations) != 1 {
		t.Fatalf("exact home observations = %d, want only root AGENTS.md", len(exact.Observations))
	}

	deep := DiscoverInstructions(
		context.Background(),
		home,
		"",
		InstructionScan{RecursiveRoot: home, Deep: true},
		testInstrEngine(t),
	)
	deepRoot := instructionRootKey(instructionRootDeep, home)
	var nested int
	for _, observation := range deep.Observations {
		if observation.OwnerKey == deepRoot {
			t.Fatalf("instruction fact owned by root instead of stable child: %+v", observation)
		}
		if strings.HasPrefix(observation.Info.Path, canonicalInstructionRoot(project)+string(filepath.Separator)) {
			nested++
		}
	}
	if nested != 4 {
		t.Fatalf("deep nested observations = %d, want 4", nested)
	}
}

func TestDeepSkipsRootExactTreesWithoutConsumingNestedBudget(t *testing.T) {
	home := t.TempDir()
	writeInstrRule(
		t,
		filepath.Join(home, ".cursor", "rules", "a", "b", "c", "root.mdc"),
		"exact only",
	)
	nested := filepath.Join(home, "repo", "AGENTS.md")
	writeInstrRule(t, nested, "deep")

	oldLimit := deepInstructionEntryLimit
	deepInstructionEntryLimit = 3
	t.Cleanup(func() { deepInstructionEntryLimit = oldLimit })

	discovery := DiscoverInstructions(
		context.Background(),
		home,
		"",
		InstructionScan{RecursiveRoot: home, Deep: true},
		testInstrEngine(t),
	)
	root := instructionOutcomeForMethod(discovery.Outcomes, ingest.InstructionMethodDeep)
	if root == nil || root.State != ingest.OutcomeComplete {
		t.Fatalf("deep root = %+v, want complete", root)
	}
	deepRoot := instructionRootKey(instructionRootDeep, home)
	foundNested := false
	for _, observation := range discovery.Observations {
		if observation.OwnerKey != deepRoot &&
			observation.Info.Path == filepath.Join(canonicalInstructionRoot(home), "repo", "AGENTS.md") {
			foundNested = true
		}
	}
	if !foundNested {
		t.Fatalf("nested source missing from deep observations: %+v", discovery.Observations)
	}
}

func TestDiscoverInstructionsHomeProjectOverlapKeepsDistinctOwners(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "CLAUDE.md")
	writeInstrRule(t, source, "shared")
	canonicalSource := filepath.Join(canonicalInstructionRoot(root), "CLAUDE.md")

	discovery := DiscoverInstructions(context.Background(), root, root, InstructionScan{}, testInstrEngine(t))
	var owners []string
	for _, observation := range discovery.Observations {
		if observation.Info.Path == canonicalSource {
			owners = append(owners, observation.OwnerKey)
		}
	}
	if len(owners) != 2 || owners[0] == owners[1] {
		t.Fatalf("CWD=home owners = %v, want independent exact-user and exact-project children", owners)
	}
	wantUser := instructionChildKey(instructionRootKey(instructionRootExactUser, root), canonicalSource)
	wantProject := instructionChildKey(instructionRootKey(instructionRootExactProject, root), canonicalSource)
	if !containsString(owners, wantUser) || !containsString(owners, wantProject) {
		t.Fatalf("owners = %v, want %q and %q", owners, wantUser, wantProject)
	}
}

func TestDiscoverInstructionsTruncatedDeepRetainsCompleteChildren(t *testing.T) {
	home := t.TempDir()
	writeInstrRule(t, filepath.Join(home, "a", "AGENTS.md"), "complete")
	writeInstrRule(t, filepath.Join(home, "z", ".cursor", "rules", "a.mdc"), "first")
	writeInstrRule(t, filepath.Join(home, "z", ".cursor", "rules", "b.mdc"), "second")

	oldLimit := instructionRuleLimit
	instructionRuleLimit = 2
	t.Cleanup(func() { instructionRuleLimit = oldLimit })

	discovery := DiscoverInstructions(
		context.Background(),
		home,
		"",
		InstructionScan{RecursiveRoot: home, Deep: true},
		testInstrEngine(t),
	)
	root := instructionOutcomeForMethod(discovery.Outcomes, ingest.InstructionMethodDeep)
	if root == nil || root.State != ingest.OutcomeTruncated {
		t.Fatalf("deep root = %+v, want truncated", root)
	}
	if len(discovery.Observations) != 1 || !strings.HasSuffix(discovery.Observations[0].Info.Path, "AGENTS.md") {
		t.Fatalf("truncated deep observations = %+v, want prior complete child only", discovery.Observations)
	}
}

func TestDiscoverInstructionsPartialDeepEmitsNoFacts(t *testing.T) {
	home := t.TempDir()
	source := filepath.Join(home, "a", "AGENTS.md")
	unreadable := filepath.Join(home, "b", "CLAUDE.md")
	writeInstrRule(t, source, "complete")
	writeInstrRule(t, unreadable, "unreadable")

	originalOpen := openConfigFile
	canonicalUnreadable := filepath.Join(canonicalInstructionRoot(home), "b", "CLAUDE.md")
	openConfigFile = func(path string) (*os.File, error) {
		if canonicalConfigPath(path) == canonicalUnreadable {
			return nil, os.ErrPermission
		}
		return os.Open(path)
	}
	t.Cleanup(func() { openConfigFile = originalOpen })

	discovery := DiscoverInstructions(
		context.Background(),
		home,
		"",
		InstructionScan{RecursiveRoot: home, Deep: true},
		testInstrEngine(t),
	)
	root := instructionOutcomeForMethod(discovery.Outcomes, ingest.InstructionMethodDeep)
	if root == nil || root.State != ingest.OutcomePartial {
		t.Fatalf("deep root = %+v, want partial", root)
	}
	if len(discovery.Observations) != 0 {
		t.Fatalf("partial deep emitted facts: %+v", discovery.Observations)
	}
}

func TestDiscoverInstructionsUnreadableUnrelatedDeepDirectoryRetainsCompleteChildren(t *testing.T) {
	home := t.TempDir()
	readable := filepath.Join(home, "a-readable", "AGENTS.md")
	blocked := filepath.Join(home, "z-blocked")
	writeInstrRule(t, readable, "complete")
	if err := os.MkdirAll(blocked, 0o700); err != nil {
		t.Fatal(err)
	}

	originalOpen := openInstructionDirectory
	canonicalBlocked := filepath.Join(canonicalInstructionRoot(home), "z-blocked")
	openInstructionDirectory = func(path string) (*os.File, error) {
		if canonicalConfigPath(path) == canonicalBlocked {
			return nil, os.ErrPermission
		}
		return os.Open(path)
	}
	t.Cleanup(func() { openInstructionDirectory = originalOpen })

	discovery := DiscoverInstructions(
		context.Background(),
		home,
		"",
		InstructionScan{RecursiveRoot: home, Deep: true},
		testInstrEngine(t),
	)
	root := instructionOutcomeForMethod(discovery.Outcomes, ingest.InstructionMethodDeep)
	if root == nil || root.State != ingest.OutcomeTruncated {
		t.Fatalf("deep root = %+v, want truncated", root)
	}
	if len(discovery.Observations) != 1 ||
		discovery.Observations[0].Info.Path != filepath.Join(
			canonicalInstructionRoot(home),
			"a-readable",
			"AGENTS.md",
		) {
		t.Fatalf("truncated deep observations = %+v, want readable child", discovery.Observations)
	}
	foundRoot := false
	for _, authoritative := range discovery.AuthoritativeRoots {
		if authoritative.CoverageKey == root.CoverageKey {
			foundRoot = true
			if len(authoritative.ChildCoverageKeys) != 1 {
				t.Fatalf("truncated deep root children = %+v, want readable child", authoritative)
			}
		}
	}
	if !foundRoot {
		t.Fatalf("deep root %q missing from authoritative roots", root.CoverageKey)
	}
}

func TestDeepInstructionTraversalCancelsBetweenDirectoryBatches(t *testing.T) {
	home := t.TempDir()
	bulk := filepath.Join(home, "bulk")
	if err := os.MkdirAll(bulk, 0o755); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 100; index++ {
		path := filepath.Join(bulk, "irrelevant-"+strconv.Itoa(index)+".txt")
		if err := os.WriteFile(path, []byte("ignored"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	oldBatchSize := instructionReadDirBatchSize
	oldBatchHook := instructionWalkBatchHook
	instructionReadDirBatchSize = 7
	bulkEntriesRead := 0
	canonicalBulk := filepath.Join(canonicalInstructionRoot(home), "bulk")
	instructionWalkBatchHook = func(path string, entries int) {
		if canonicalConfigPath(path) == canonicalBulk {
			bulkEntriesRead += entries
			cancel()
		}
	}
	t.Cleanup(func() {
		instructionReadDirBatchSize = oldBatchSize
		instructionWalkBatchHook = oldBatchHook
		cancel()
	})

	discovery := DiscoverInstructions(
		ctx,
		home,
		"",
		InstructionScan{RecursiveRoot: home, Deep: true},
		testInstrEngine(t),
	)
	root := instructionOutcomeForMethod(discovery.Outcomes, ingest.InstructionMethodDeep)
	if root == nil || root.State != ingest.OutcomePartial {
		t.Fatalf("deep root = %+v, want partial cancellation", root)
	}
	if bulkEntriesRead != 7 {
		t.Fatalf("bulk entries read = %d, want one bounded batch of 7", bulkEntriesRead)
	}
}

func TestInstructionTraversalSkipAllStopsQueuedSiblingDirectories(t *testing.T) {
	root := t.TempDir()
	for _, sibling := range []string{"first", "second"} {
		writeInstrRule(t, filepath.Join(root, sibling, "irrelevant.txt"), "ignored")
	}

	oldBatchHook := instructionWalkBatchHook
	openedChildren := make(map[string]bool)
	instructionWalkBatchHook = func(path string, _ int) {
		if canonicalConfigPath(path) != canonicalConfigPath(root) {
			openedChildren[canonicalConfigPath(path)] = true
		}
	}
	t.Cleanup(func() { instructionWalkBatchHook = oldBatchHook })

	err := walkInstructionDirectory(
		context.Background(),
		root,
		func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry != nil && !entry.IsDir() {
				return filepath.SkipAll
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("walkInstructionDirectory() error = %v", err)
	}
	if len(openedChildren) != 1 {
		t.Fatalf("opened child directories after SkipAll = %v, want exactly one", openedChildren)
	}
}

func TestDiscoverInstructionsPartialExactRootEmitsNoFacts(t *testing.T) {
	project := t.TempDir()
	readable := filepath.Join(project, "AGENTS.md")
	unreadable := filepath.Join(project, "CLAUDE.md")
	writeInstrRule(t, readable, "complete")
	writeInstrRule(t, unreadable, "unreadable")

	originalOpen := openConfigFile
	canonicalUnreadable := filepath.Join(canonicalInstructionRoot(project), "CLAUDE.md")
	openConfigFile = func(path string) (*os.File, error) {
		if canonicalConfigPath(path) == canonicalUnreadable {
			return nil, os.ErrPermission
		}
		return os.Open(path)
	}
	t.Cleanup(func() { openConfigFile = originalOpen })

	discovery := DiscoverInstructions(
		context.Background(),
		"",
		project,
		InstructionScan{},
		testInstrEngine(t),
	)
	root := instructionOutcomeForMethod(
		discovery.Outcomes,
		ingest.InstructionMethodExactProject,
	)
	if root == nil || root.State != ingest.OutcomePartial {
		t.Fatalf("exact project root = %+v, want partial", root)
	}
	if len(discovery.Observations) != 0 {
		t.Fatalf("partial exact root emitted facts: %+v", discovery.Observations)
	}
	for _, authoritative := range discovery.AuthoritativeRoots {
		if authoritative.CoverageKey == root.CoverageKey &&
			len(authoritative.ChildCoverageKeys) != 0 {
			t.Fatalf("partial exact root retained children: %+v", authoritative)
		}
	}
}

func TestDiscoverInstructionsFailedDeepRootEmitsNoFacts(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	discovery := DiscoverInstructions(
		context.Background(),
		"",
		"",
		InstructionScan{RecursiveRoot: missing, Deep: true},
		testInstrEngine(t),
	)
	root := instructionOutcomeForMethod(discovery.Outcomes, ingest.InstructionMethodDeep)
	if root == nil || root.State != ingest.OutcomeFailed {
		t.Fatalf("missing deep root = %+v, want failed", root)
	}
	if len(discovery.Observations) != 0 {
		t.Fatalf("failed deep emitted facts: %+v", discovery.Observations)
	}
}

func TestDiscoverInstructionsCanonicalizesExactProjectSymlinkRoot(t *testing.T) {
	base := t.TempDir()
	physical := filepath.Join(base, "physical-project")
	writeInstrRule(t, filepath.Join(physical, "CLAUDE.md"), "project")
	symlink := filepath.Join(base, "project-link")
	if err := os.Symlink(physical, symlink); err != nil {
		t.Fatal(err)
	}

	discovery := DiscoverInstructions(context.Background(), "", symlink, InstructionScan{}, testInstrEngine(t))
	if len(discovery.Observations) != 1 {
		t.Fatalf("symlinked exact project observations = %+v, want one", discovery.Observations)
	}
	if got := discovery.Observations[0].Info.Path; got != filepath.Join(canonicalInstructionRoot(physical), "CLAUDE.md") {
		t.Fatalf("instruction path = %q, want canonical physical path", got)
	}
	wantRoot := instructionRootKey(instructionRootExactProject, physical)
	if root := instructionOutcomeForMethod(discovery.Outcomes, ingest.InstructionMethodExactProject); root == nil || root.CoverageKey != wantRoot {
		t.Fatalf("exact-project root = %+v, want canonical physical owner %q", root, wantRoot)
	}
}

func TestDiscoverInstructionsCanonicalizesDeepSymlinkRoot(t *testing.T) {
	base := t.TempDir()
	physical := filepath.Join(base, "physical-home")
	writeInstrRule(t, filepath.Join(physical, "repo", "AGENTS.md"), "nested")
	symlink := filepath.Join(base, "home-link")
	if err := os.Symlink(physical, symlink); err != nil {
		t.Fatal(err)
	}

	discovery := DiscoverInstructions(
		context.Background(),
		"",
		"",
		InstructionScan{RecursiveRoot: symlink, Deep: true},
		testInstrEngine(t),
	)
	if len(discovery.Observations) != 1 {
		t.Fatalf("symlinked deep observations = %+v, want one", discovery.Observations)
	}
	wantRoot := instructionRootKey(instructionRootDeep, physical)
	if root := instructionOutcomeForMethod(discovery.Outcomes, ingest.InstructionMethodDeep); root == nil || root.CoverageKey != wantRoot {
		t.Fatalf("deep root = %+v, want canonical physical owner %q", root, wantRoot)
	}
}

func TestDiscoverInstructionsDoesNotFollowSymlinks(t *testing.T) {
	home := t.TempDir()
	outside := t.TempDir()
	writeInstrRule(t, filepath.Join(outside, "AGENTS.md"), "outside")
	if err := os.Symlink(outside, filepath.Join(home, "linked-repo")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "AGENTS.md"), filepath.Join(home, "CLAUDE.md")); err != nil {
		t.Fatal(err)
	}
	discovery := DiscoverInstructions(
		context.Background(),
		home,
		home,
		InstructionScan{RecursiveRoot: home, Deep: true},
		testInstrEngine(t),
	)
	if len(discovery.Observations) != 0 {
		t.Fatalf("symlink sources were followed: %+v", discovery.Observations)
	}
}

func TestInstructionWalkPrunesCrossOSTrash(t *testing.T) {
	home := t.TempDir()
	writeInstrRule(t, filepath.Join(home, ".local", "share", "Trash", "files", "gone", "AGENTS.md"), "deleted")
	writeInstrRule(t, filepath.Join(home, ".Trash-1000", "gone", "CLAUDE.md"), "deleted")
	writeInstrRule(t, filepath.Join(home, "keep", "AGENTS.md"), "keep")

	discovery := DiscoverInstructions(
		context.Background(),
		home,
		"",
		InstructionScan{RecursiveRoot: home, Deep: true},
		testInstrEngine(t),
	)
	if len(discovery.Observations) != 1 || !strings.Contains(discovery.Observations[0].Info.Path, "keep") {
		t.Fatalf("trash pruning observations = %+v", discovery.Observations)
	}
}

func TestInstructionWalkBudgetCountsDirectoriesNotFiles(t *testing.T) {
	home := t.TempDir()
	for i := 0; i < 1_000; i++ {
		writeInstrRule(t, filepath.Join(home, "assets", "f"+strconv.Itoa(i)+".txt"), "x")
	}
	writeInstrRule(t, filepath.Join(home, "repo", "AGENTS.md"), "rule")

	oldLimit := deepInstructionEntryLimit
	deepInstructionEntryLimit = 10
	t.Cleanup(func() { deepInstructionEntryLimit = oldLimit })

	discovery := DiscoverInstructions(
		context.Background(),
		home,
		"",
		InstructionScan{RecursiveRoot: home, Deep: true},
		testInstrEngine(t),
	)
	root := instructionOutcomeForMethod(discovery.Outcomes, ingest.InstructionMethodDeep)
	if root == nil || root.State != ingest.OutcomeComplete {
		t.Fatalf("file-heavy deep root = %+v, want complete", root)
	}
	if len(discovery.Observations) != 1 {
		t.Fatalf("file-heavy tree observations = %+v", discovery.Observations)
	}
}

func TestInstructionWalkDirectoryLimitStillBoundsDeep(t *testing.T) {
	home := t.TempDir()
	for i := 0; i < 12; i++ {
		writeInstrRule(t, filepath.Join(home, "d"+strconv.Itoa(i), "irrelevant.txt"), "x")
	}

	oldLimit := deepInstructionEntryLimit
	deepInstructionEntryLimit = 3
	t.Cleanup(func() { deepInstructionEntryLimit = oldLimit })

	discovery := DiscoverInstructions(
		context.Background(),
		home,
		"",
		InstructionScan{RecursiveRoot: home, Deep: true},
		testInstrEngine(t),
	)
	root := instructionOutcomeForMethod(discovery.Outcomes, ingest.InstructionMethodDeep)
	if root == nil || root.State != ingest.OutcomeTruncated || !strings.Contains(root.Error, "directory limit") {
		t.Fatalf("deep root = %+v, want directory-limit truncation", root)
	}
}

func TestInstructionWalkTimeoutStillBoundsDeep(t *testing.T) {
	home := t.TempDir()
	writeInstrRule(t, filepath.Join(home, "repo", "AGENTS.md"), "rule")

	oldBudget := deepInstructionWalkBudget
	deepInstructionWalkBudget = time.Nanosecond
	t.Cleanup(func() { deepInstructionWalkBudget = oldBudget })

	discovery := DiscoverInstructions(
		context.Background(),
		home,
		"",
		InstructionScan{RecursiveRoot: home, Deep: true},
		testInstrEngine(t),
	)
	root := instructionOutcomeForMethod(discovery.Outcomes, ingest.InstructionMethodDeep)
	if root == nil ||
		root.State != ingest.OutcomePartial ||
		(!strings.Contains(root.Error, "canceled") &&
			!strings.Contains(root.Error, "budget")) {
		t.Fatalf("deep root = %+v, want timeout partial", root)
	}
}

func TestDeepInstructionBudgetReturnsWhileDirectoryOpenIsBlocked(t *testing.T) {
	home := t.TempDir()
	canonicalHome := canonicalInstructionRoot(home)
	entered := make(chan struct{})
	release := make(chan struct{})
	openReturned := make(chan struct{})

	originalOpen := openInstructionDirectory
	openInstructionDirectory = func(path string) (*os.File, error) {
		if canonicalConfigPath(path) == canonicalHome {
			close(entered)
			<-release
			defer close(openReturned)
		}
		return os.Open(path)
	}
	released := false
	t.Cleanup(func() {
		if !released {
			close(release)
		}
		select {
		case <-openReturned:
		case <-time.After(time.Second):
			t.Error("blocked directory-open hook did not return")
		}
		openInstructionDirectory = originalOpen
	})

	oldBudget := deepInstructionWalkBudget
	deepInstructionWalkBudget = 20 * time.Millisecond
	t.Cleanup(func() { deepInstructionWalkBudget = oldBudget })

	start := time.Now()
	discovery := DiscoverInstructions(
		context.Background(),
		home,
		"",
		InstructionScan{RecursiveRoot: home, Deep: true},
		testInstrEngine(t),
	)
	elapsed := time.Since(start)
	select {
	case <-entered:
	default:
		t.Fatal("deep worker did not enter the blocking directory open")
	}
	if elapsed >= time.Second {
		t.Fatalf("deep discovery returned after %s, want caller-visible deadline", elapsed)
	}
	root := instructionOutcomeForMethod(
		discovery.Outcomes,
		ingest.InstructionMethodDeep,
	)
	if root == nil ||
		root.State != ingest.OutcomePartial ||
		!strings.Contains(root.Error, "budget") {
		t.Fatalf("deep root = %+v, want budget-exceeded partial", root)
	}
	var activeChildren []string
	for _, authoritative := range discovery.AuthoritativeRoots {
		if authoritative.CoverageKey == root.CoverageKey {
			activeChildren = authoritative.ChildCoverageKeys
			break
		}
	}
	if len(activeChildren) != 0 || len(discovery.Observations) != 0 {
		t.Fatalf("timed-out deep discovery leaked worker facts: %+v", discovery)
	}

	close(release)
	released = true
	select {
	case <-openReturned:
	case <-time.After(time.Second):
		t.Fatal("blocked directory-open hook did not return after release")
	}
}
