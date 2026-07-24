package config

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/sdk/rules"
)

const (
	maxInstructionFileBytes int64 = 4 << 20
	// deepInstructionWalkBudget bounds worst-case wall time for a --deep sweep
	// (slow paths such as network homes or cloud-sync placeholder hydration do
	// not correspond to many entries, so the entry cap alone is insufficient).
	deepInstructionWalkBudget = 60 * time.Second
)

var (
	// instructionTraversalEntryLimit caps the strict --project-dir walk. The
	// deep sweep uses deepInstructionEntryLimit instead.
	instructionTraversalEntryLimit = 100_000
	deepInstructionEntryLimit      = 1_000_000
	instructionRuleLimit           = 10_000
)

// instructionPrunedDirNames are directory names skipped during the recursive
// instruction walk. They are junk/cache/VCS/trash trees that never hold authored
// .cursor/rules and would otherwise burn the entry budget (e.g. node_modules)
// or, in the reported incident, a bloated trash directory. Trash coverage is
// cross-OS: `.Trash`/`.Trashes` (macOS), `Trash` (the freedesktop XDG home
// trash, normally ~/.local/share/Trash on Linux), `$Recycle.Bin` (Windows), and
// the per-mount `.Trash-<uid>` variants matched by prefix in instructionPrunedDir.
// Absolute pseudo-filesystem roots (/proc, /sys) and mount boundaries are
// deferred to a later hardening pass; the entry cap plus wall-clock budget bound
// the worst case meanwhile.
var instructionPrunedDirNames = map[string]bool{
	".git":          true,
	".svn":          true,
	".hg":           true,
	"node_modules":  true,
	"vendor":        true,
	".cache":        true,
	"Caches":        true,
	".Trash":        true,
	".Trashes":      true,
	"Trash":         true,
	"$Recycle.Bin":  true,
	".venv":         true,
	"venv":          true,
	".tox":          true,
	".mypy_cache":   true,
	".pytest_cache": true,
	"__pycache__":   true,
	".terraform":    true,
}

func instructionPrunedDir(entry os.DirEntry) bool {
	if entry == nil || !entry.IsDir() {
		return false
	}
	name := entry.Name()
	// Per-mount freedesktop trash directories are named .Trash-<uid>.
	return instructionPrunedDirNames[name] || strings.HasPrefix(name, ".Trash-")
}

type InstructionFileInfo struct {
	Path         string
	Type         string
	Hash         string
	IsSuspicious bool
	Patterns     []common.PatternMatch
}

type InstructionObservation struct {
	Info     InstructionFileInfo
	OwnerKey string
}

type InstructionDiscovery struct {
	Observations []InstructionObservation
	CoverageKeys []string
	Outcomes     []ingest.CollectionOutcome
	// InstructionCoverageComplete is false only when a recursive walk ran and
	// did not finish (truncated/partial). It is true when no recursive walk was
	// requested or the walk completed. It surfaces as the AgentInstance
	// instruction_coverage_complete property so risk scoring can degrade a
	// partially-covered agent to "unassessed" instead of "clean".
	InstructionCoverageComplete bool
}

// InstructionScan configures the recursive .cursor/rules walk. A zero value
// (RecursiveRoot == "") disables recursion entirely; only fixed single-file
// instruction targets are read.
type InstructionScan struct {
	// RecursiveRoot is the directory the recursive walk starts from. Empty
	// disables the walk.
	RecursiveRoot string
	// Deep selects best-effort mode: a larger entry cap, a wall-clock budget,
	// and advisory coverage outcomes (truncation publishes instead of wedging).
	Deep bool
}

type instructionTarget struct {
	relPath  string
	fileType string
}

var projectTargets = []instructionTarget{
	{"AGENTS.md", "agents.md"},
	{"CLAUDE.md", "claude.md"},
	{".cursorrules", "cursorrules"},
	{filepath.Join(".github", "copilot-instructions.md"), "copilot-instructions"},
}

var userTargets = []instructionTarget{
	{filepath.Join(".claude", "CLAUDE.md"), "claude.md"},
}

func instructionTraversalKey(projectRoot string) string {
	return ingest.CanonicalCoverageKey("config", "instruction-traversal", projectRoot)
}

func instructionTreeKey(path string) string {
	return ingest.CanonicalCoverageKey("config", "instruction-tree", canonicalConfigPath(path))
}

func instructionFileKey(path string) string {
	return ingest.CanonicalCoverageKey("config", "instruction-file", canonicalConfigPath(path))
}

// DiscoverInstructions returns graph observations plus lifecycle metadata.
// Cursor rule nodes are owned only by their stable rules-tree domain; dynamic
// per-file keys are diagnostics and never become additive graph owners.
func DiscoverInstructions(
	ctx context.Context,
	homeDir, projectRoot string,
	scan InstructionScan,
	engine *rules.Engine,
) InstructionDiscovery {
	var result InstructionDiscovery
	result.InstructionCoverageComplete = true
	addStatic := func(path, fileType string) {
		path = canonicalConfigPath(path)
		key := configCoverageKey(path)
		result.CoverageKeys = append(result.CoverageKeys, key)
		data, state, errText := readBoundedInstruction(path)
		items := 0
		if data != nil && state == ingest.OutcomeComplete {
			info := AnalyzeInstructionFile(path, data, fileType, engine)
			result.Observations = append(result.Observations, InstructionObservation{Info: info, OwnerKey: key})
			items = 1
		}
		result.Outcomes = append(result.Outcomes, collectionOutcome(key, path, "instruction_discovery", state, items, errText))
	}
	if projectRoot != "" {
		for _, target := range projectTargets {
			addStatic(filepath.Join(projectRoot, target.relPath), target.fileType)
		}
	}
	if homeDir != "" {
		for _, target := range userTargets {
			addStatic(filepath.Join(homeDir, target.relPath), target.fileType)
		}
	}

	if scan.RecursiveRoot != "" {
		walkCtx := ctx
		if scan.Deep {
			var cancel context.CancelFunc
			walkCtx, cancel = context.WithTimeout(ctx, deepInstructionWalkBudget)
			defer cancel()
		}
		discoverCursorRuleTrees(walkCtx, scan.RecursiveRoot, scan.Deep, engine, &result)
	}
	sort.Slice(result.Observations, func(i, j int) bool {
		return result.Observations[i].Info.Path < result.Observations[j].Info.Path
	})
	result.CoverageKeys = uniqueSorted(result.CoverageKeys)
	sort.Slice(result.Outcomes, func(i, j int) bool {
		if result.Outcomes[i].CoverageKey == result.Outcomes[j].CoverageKey {
			return result.Outcomes[i].Method < result.Outcomes[j].Method
		}
		return result.Outcomes[i].CoverageKey < result.Outcomes[j].CoverageKey
	})
	return result
}

func discoverCursorRuleTrees(
	ctx context.Context,
	projectRoot string,
	deep bool,
	engine *rules.Engine,
	result *InstructionDiscovery,
) {
	entryLimit := instructionTraversalEntryLimit
	if deep {
		entryLimit = deepInstructionEntryLimit
	}
	traversalKey := instructionTraversalKey(projectRoot)
	result.CoverageKeys = append(result.CoverageKeys, traversalKey)
	traversalState := ingest.OutcomeComplete
	traversalError := ""
	entries := 0
	rulesSeen := 0

	err := filepath.WalkDir(projectRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			traversalState = ingest.OutcomePartial
			traversalError = "collection canceled"
			return filepath.SkipAll
		}
		// Prune junk/cache/trash trees, but never the explicitly-selected root
		// itself — an operator who names `--project-dir /path/to/vendor` (or a
		// repo literally named .cache, venv, Trash) still expects it scanned.
		if path != projectRoot && instructionPrunedDir(entry) {
			return filepath.SkipDir
		}
		if walkErr != nil {
			traversalState = ingest.OutcomePartial
			traversalError = "project traversal incomplete"
			if entry != nil && entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if path != projectRoot {
			entries++
			if entries > entryLimit {
				traversalState = ingest.OutcomeTruncated
				traversalError = fmt.Sprintf("project traversal exceeds %d entry limit", entryLimit)
				return filepath.SkipAll
			}
		}
		if !entry.IsDir() || entry.Name() != "rules" || filepath.Base(filepath.Dir(path)) != ".cursor" {
			return nil
		}
		treeState, treeErr := discoverCursorRuleTree(ctx, path, deep, entryLimit, engine, &entries, &rulesSeen, result)
		if treeState != ingest.OutcomeComplete && traversalState == ingest.OutcomeComplete {
			traversalState = treeState
			traversalError = treeErr
		}
		if entries > entryLimit {
			return filepath.SkipAll
		}
		return filepath.SkipDir
	})
	if err != nil && traversalState == ingest.OutcomeComplete {
		traversalState = ingest.OutcomePartial
		traversalError = "project traversal incomplete"
	}
	if traversalState != ingest.OutcomeComplete {
		result.InstructionCoverageComplete = false
	}
	result.Outcomes = append(result.Outcomes, instructionOutcome(
		traversalKey, projectRoot, "cursor_rule_traversal", traversalState, rulesSeen, traversalError, deep,
	))
}

func discoverCursorRuleTree(
	ctx context.Context,
	treePath string,
	deep bool,
	entryLimit int,
	engine *rules.Engine,
	entries, rulesSeen *int,
	result *InstructionDiscovery,
) (ingest.OutcomeState, string) {
	treePath = canonicalConfigPath(treePath)
	treeKey := instructionTreeKey(treePath)
	result.CoverageKeys = append(result.CoverageKeys, treeKey)
	state := ingest.OutcomeComplete
	errText := ""
	items := 0
	// A truncated/partial tree must not contribute graph nodes: the writer would
	// mark them observation_properties_complete=false (their owning tree domain
	// is not certified complete), which fails the graph-wide observation gate and
	// wedges every future publication. Buffer the observation count and roll back
	// this tree's observations unless it completes. Coverage outcomes are still
	// recorded so partiality stays visible.
	observationsBefore := len(result.Observations)

	err := filepath.WalkDir(treePath, func(path string, entry os.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			state, errText = ingest.OutcomePartial, "collection canceled"
			return filepath.SkipAll
		}
		// A nested rules tree is still part of the project traversal boundary.
		// Prune junk/VCS/trash trees before counting them (but never treePath
		// itself, an explicitly-reached .cursor/rules root).
		if path != treePath && instructionPrunedDir(entry) {
			return filepath.SkipDir
		}
		if walkErr != nil {
			state, errText = ingest.OutcomePartial, "rules tree traversal incomplete"
			if entry != nil && entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if path == treePath {
			return nil
		}
		(*entries)++
		if *entries > entryLimit {
			state = ingest.OutcomeTruncated
			errText = fmt.Sprintf("project traversal exceeds %d entry limit", entryLimit)
			return filepath.SkipAll
		}
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".mdc") {
			return nil
		}
		if *rulesSeen >= instructionRuleLimit {
			state = ingest.OutcomeTruncated
			errText = fmt.Sprintf("rule discovery exceeds %d file limit", instructionRuleLimit)
			return filepath.SkipAll
		}
		(*rulesSeen)++
		filePath := canonicalConfigPath(path)
		fileKey := instructionFileKey(filePath)
		result.CoverageKeys = append(result.CoverageKeys, fileKey)
		data, fileState, fileErr := readBoundedInstruction(filePath)
		fileItems := 0
		if data != nil && fileState == ingest.OutcomeComplete {
			info := AnalyzeInstructionFile(filePath, data, "cursor-rule", engine)
			result.Observations = append(result.Observations, InstructionObservation{Info: info, OwnerKey: treeKey})
			fileItems, items = 1, items+1
			if state == ingest.OutcomeFailed {
				state = ingest.OutcomePartial
			}
		} else {
			switch {
			case fileState == ingest.OutcomeFailed:
				state = ingest.OutcomePartial
			case fileState == ingest.OutcomeTruncated && state == ingest.OutcomeComplete:
				state = ingest.OutcomeTruncated
			}
			errText = fileErr
		}
		result.Outcomes = append(result.Outcomes, instructionOutcome(
			fileKey, filePath, "cursor_rule_read", fileState, fileItems, fileErr, deep,
		))
		return nil
	})
	if err != nil && state == ingest.OutcomeComplete {
		state, errText = ingest.OutcomePartial, "rules tree traversal incomplete"
	}
	// Discard this tree's observations unless it fully enumerated. Nodes owned by
	// a non-complete domain would poison the graph-wide publication gate; a
	// best-effort sweep keeps every complete tree and records the rest as
	// truncated coverage rather than emitting property-incomplete facts.
	if state != ingest.OutcomeComplete {
		result.Observations = result.Observations[:observationsBefore]
	}
	result.Outcomes = append(result.Outcomes, instructionOutcome(
		treeKey, treePath, "cursor_rule_tree", state, items, errText, deep,
	))
	return state, errText
}

func collectionOutcome(
	key, target, method string,
	state ingest.OutcomeState,
	items int,
	errText string,
) ingest.CollectionOutcome {
	return ingest.CollectionOutcome{
		Collector: "config", CoverageKey: key, Target: target, Method: method,
		State: state, Items: items, Error: errText,
	}
}

// instructionOutcome builds a recursive-walk outcome. In deep mode the outcome
// is marked advisory so a truncated best-effort sweep publishes instead of
// wedging the projection; the strict --project-dir walk leaves it non-advisory
// (truncation still blocks, as an operator-scoped tree is expected to finish).
func instructionOutcome(
	key, target, method string,
	state ingest.OutcomeState,
	items int,
	errText string,
	advisory bool,
) ingest.CollectionOutcome {
	outcome := collectionOutcome(key, target, method, state, items, errText)
	outcome.Advisory = advisory
	return outcome
}

func readBoundedInstruction(path string) ([]byte, ingest.OutcomeState, string) {
	data, state, errText := readBoundedConfig(path)
	if state == ingest.OutcomeTruncated {
		return nil, state, fmt.Sprintf("file exceeds %d byte limit", maxInstructionFileBytes)
	}
	return data, state, errText
}

func AnalyzeInstructionFile(path string, data []byte, fileType string, engine *rules.Engine) InstructionFileInfo {
	text := string(data)
	var patterns []common.PatternMatch
	matches := engine.EvaluateAll("config", map[string]string{"instruction.content": text})
	for _, match := range matches {
		if match.Emit.FindingType != "has_injection_patterns" {
			continue
		}
		label := match.RuleID
		if len(match.Labels) > 0 {
			label = match.Labels[0]
		}
		patterns = append(patterns, common.PatternMatch{
			Name: label, Severity: match.Severity, Offset: match.Offset, Text: match.Text,
		})
	}
	return InstructionFileInfo{
		Path: path, Type: fileType, Hash: common.HashSHA256(text),
		IsSuspicious: len(patterns) > 0, Patterns: patterns,
	}
}

// DiscoverInstructionFiles is retained for SDK compatibility; collection code
// uses DiscoverInstructions so coverage failures are not discarded.
func DiscoverInstructionFiles(homeDir, projectDir string, engine *rules.Engine) []InstructionFileInfo {
	result := DiscoverInstructions(
		context.Background(),
		homeDir,
		projectDir,
		InstructionScan{RecursiveRoot: projectDir},
		engine,
	)
	infos := make([]InstructionFileInfo, 0, len(result.Observations))
	for _, observation := range result.Observations {
		infos = append(infos, observation.Info)
	}
	return infos
}

func uniqueSorted(values []string) []string {
	sort.Strings(values)
	out := values[:0]
	for _, value := range values {
		if value == "" || len(out) > 0 && out[len(out)-1] == value {
			continue
		}
		out = append(out, value)
	}
	return out
}
