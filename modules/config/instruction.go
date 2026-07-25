package config

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
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
	maxInstructionFileBytes       int64 = 4 << 20
	instructionRegistryGeneration       = 1
)

var (
	instructionTraversalEntryLimit = 100_000
	deepInstructionEntryLimit      = 1_000_000
	instructionRuleLimit           = 10_000
	deepInstructionWalkBudget      = 60 * time.Second
	instructionReadDirBatchSize    = 256
	instructionWalkBatchHook       func(string, int)
	openInstructionDirectory       = os.Open
)

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

type instructionSource struct {
	relPath  string
	fileType string
	tree     bool
	suffix   string
}

var instructionRegistry = []instructionSource{
	{relPath: "AGENTS.md", fileType: "agents.md"},
	{relPath: "CLAUDE.md", fileType: "claude.md"},
	{relPath: filepath.Join(".claude", "CLAUDE.md"), fileType: "claude.md"},
	{relPath: filepath.Join(".claude", "rules"), fileType: "claude-rule", tree: true, suffix: ".md"},
	{relPath: ".cursorrules", fileType: "cursorrules"},
	{relPath: filepath.Join(".cursor", "rules"), fileType: "cursor-rule", tree: true, suffix: ".mdc"},
	{relPath: filepath.Join(".github", "copilot-instructions.md"), fileType: "copilot-instructions"},
	{relPath: filepath.Join(".github", "instructions"), fileType: "copilot-instruction", tree: true, suffix: ".instructions.md"},
}

// instructionRegistryManifest is the canonical comparison contract for the
// registry. Ownership keys intentionally exclude it: changing the recognized
// source set must refresh the same owners so removed evidence can be retired.
const instructionRegistryManifest = "agenthound-instruction-registry/v1\n" +
	"source:file:AGENTS.md:agents.md\n" +
	"source:file:CLAUDE.md:claude.md\n" +
	"source:file:.claude/CLAUDE.md:claude.md\n" +
	"source:tree:.claude/rules:**/*.md:claude-rule\n" +
	"source:file:.cursorrules:cursorrules\n" +
	"source:tree:.cursor/rules:**/*.mdc:cursor-rule\n" +
	"source:file:.github/copilot-instructions.md:copilot-instructions\n" +
	"source:tree:.github/instructions:**/*.instructions.md:copilot-instruction\n" +
	"roots:exact_user,exact_project,deep\n" +
	"deep:canonical-home:nested-only\n" +
	"symlinks:root-resolved,descendants-excluded\n" +
	"files:regular-only\n" +
	"deep:unreadable-unmatched-descendant=truncated\n" +
	"limits:file=4194304,rule=10000,exact_dirs=100000,deep_dirs=1000000,deep_timeout=60s\n" +
	"prune:$Recycle.Bin,.Trash,.Trash-*,.Trashes,.cache,.git,.hg,.mypy_cache,.pytest_cache,.svn,.terraform,.tox,.venv,Caches,Trash,__pycache__,node_modules,vendor,venv\n"

func instructionRegistryDigest() string {
	sum := sha256.Sum256([]byte(instructionRegistryManifest))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func instructionPrunedDir(entry os.DirEntry) bool {
	if entry == nil || !entry.IsDir() {
		return false
	}
	name := entry.Name()
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
	Observations       []InstructionObservation
	CoverageKeys       []string
	AuthoritativeRoots []ingest.CoverageRoot
	Outcomes           []ingest.CollectionOutcome
}

type InstructionScan struct {
	// RecursiveRoot is retained as the collector option boundary. It is used
	// only when Deep is true and must be the canonical user home.
	RecursiveRoot string
	Deep          bool
}

type instructionRootMode string

const (
	instructionRootExactUser    instructionRootMode = "exact_user"
	instructionRootExactProject instructionRootMode = "exact_project"
	instructionRootDeep         instructionRootMode = "deep"
)

func instructionRootKey(mode instructionRootMode, root string) string {
	scopeKind := ""
	switch mode {
	case instructionRootExactUser:
		scopeKind = "instruction-exact-user"
	case instructionRootExactProject:
		scopeKind = "instruction-exact-project"
	case instructionRootDeep:
		scopeKind = "instruction-deep"
	default:
		return ""
	}
	return ingest.CanonicalCoverageKey("config", scopeKind, canonicalInstructionRoot(root))
}

func instructionChildKey(rootKey, boundary string) string {
	return ingest.CanonicalCoverageKey(
		"config",
		"instruction-source",
		rootKey+"\x00"+canonicalConfigPath(boundary),
	)
}

func instructionRootMethod(mode instructionRootMode) string {
	switch mode {
	case instructionRootExactUser:
		return ingest.InstructionMethodExactUser
	case instructionRootExactProject:
		return ingest.InstructionMethodExactProject
	case instructionRootDeep:
		return ingest.InstructionMethodDeep
	default:
		return "instruction_discovery"
	}
}

func instructionRegistryContract() ingest.RegistryContract {
	return ingest.RegistryContract{
		Generation: instructionRegistryGeneration,
		Digest:     instructionRegistryDigest(),
	}
}

// DiscoverInstructions scans the complete bounded registry at the canonical
// home and project roots. Deep mode additionally searches nested sources below
// home; it never changes exact ownership or reclassifies root-level sources.
func DiscoverInstructions(
	ctx context.Context,
	homeDir, projectRoot string,
	scan InstructionScan,
	engine *rules.Engine,
) InstructionDiscovery {
	var result InstructionDiscovery
	if homeDir != "" {
		discoverExactInstructionRoot(ctx, canonicalInstructionRoot(homeDir), instructionRootExactUser, engine, &result)
	}
	if projectRoot != "" {
		discoverExactInstructionRoot(ctx, canonicalInstructionRoot(projectRoot), instructionRootExactProject, engine, &result)
	}
	if scan.Deep && scan.RecursiveRoot != "" {
		walkCtx, cancel := context.WithTimeout(ctx, deepInstructionWalkBudget)
		defer cancel()
		discoverDeepInstructionRoot(walkCtx, canonicalInstructionRoot(scan.RecursiveRoot), engine, &result)
	}
	sort.Slice(result.Observations, func(i, j int) bool {
		if result.Observations[i].Info.Path == result.Observations[j].Info.Path {
			return result.Observations[i].OwnerKey < result.Observations[j].OwnerKey
		}
		return result.Observations[i].Info.Path < result.Observations[j].Info.Path
	})
	result.CoverageKeys = uniqueSorted(result.CoverageKeys)
	sort.Slice(result.AuthoritativeRoots, func(i, j int) bool {
		return result.AuthoritativeRoots[i].CoverageKey < result.AuthoritativeRoots[j].CoverageKey
	})
	sort.Slice(result.Outcomes, func(i, j int) bool {
		if result.Outcomes[i].CoverageKey == result.Outcomes[j].CoverageKey {
			return result.Outcomes[i].Method < result.Outcomes[j].Method
		}
		return result.Outcomes[i].CoverageKey < result.Outcomes[j].CoverageKey
	})
	return result
}

func canonicalInstructionRoot(root string) string {
	root = canonicalConfigPath(root)
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return root
	}
	return canonicalConfigPath(resolved)
}

func discoverExactInstructionRoot(
	ctx context.Context,
	root string,
	mode instructionRootMode,
	engine *rules.Engine,
	result *InstructionDiscovery,
) {
	rootKey := instructionRootKey(mode, root)
	result.CoverageKeys = append(result.CoverageKeys, rootKey)
	if state, errText := validateInstructionRoot(root); state != ingest.OutcomeComplete {
		result.Outcomes = append(result.Outcomes, collectionOutcome(
			rootKey, root, instructionRootMethod(mode), state, 0, errText,
		))
		appendInstructionCoverageRoot(result, rootKey, nil)
		return
	}
	observationsBefore := len(result.Observations)
	coverageBefore := len(result.CoverageKeys)
	outcomesBefore := len(result.Outcomes)
	var childStates []ingest.CollectionOutcome
	var activeChildren []string
	rulesSeen, directories := 0, 0

	for _, source := range instructionRegistry {
		if err := ctx.Err(); err != nil {
			childStates = append(childStates, collectionOutcome(
				rootKey, root, instructionRootMethod(mode), ingest.OutcomePartial, 0, "collection canceled",
			))
			break
		}
		boundary := canonicalConfigPath(filepath.Join(root, source.relPath))
		if instructionPathHasSymlink(root, boundary) {
			continue
		}
		entry, err := os.Lstat(boundary)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			child := instructionChildKey(rootKey, boundary)
			outcome := instructionChildOutcome(child, rootKey, boundary, ingest.InstructionMethodSource, ingest.OutcomeFailed, 0, "instruction source unavailable")
			childStates = append(childStates, outcome)
			continue
		}
		if entry.Mode()&os.ModeSymlink != 0 {
			continue
		}

		child := instructionChildKey(rootKey, boundary)
		var state ingest.OutcomeState
		var items int
		var errText string
		if source.tree {
			if !entry.IsDir() {
				state, errText = ingest.OutcomeFailed, "registered instruction tree is not a directory"
			} else {
				state, items, errText = discoverInstructionTree(
					ctx, boundary, source, child, instructionTraversalEntryLimit, &directories, &rulesSeen, engine, result,
				)
			}
		} else {
			if !entry.Mode().IsRegular() {
				state, errText = ingest.OutcomeFailed, "registered instruction source is not a regular file"
			} else {
				state, items, errText = discoverInstructionFile(boundary, source.fileType, child, engine, result)
				if items > 0 {
					rulesSeen++
				}
			}
		}
		method := ingest.InstructionMethodSource
		outcome := instructionChildOutcome(child, rootKey, boundary, method, state, items, errText)
		childStates = append(childStates, outcome)
		if state == ingest.OutcomeComplete {
			result.CoverageKeys = append(result.CoverageKeys, child)
			result.Outcomes = append(result.Outcomes, outcome)
			activeChildren = append(activeChildren, child)
		}
	}

	rootState := ingest.OutcomeComplete
	if len(childStates) > 0 {
		rootState = ingest.AggregateOutcomeState(childStates)
	}
	if rootState != ingest.OutcomeComplete {
		result.Observations = result.Observations[:observationsBefore]
		result.CoverageKeys = result.CoverageKeys[:coverageBefore]
		result.Outcomes = result.Outcomes[:outcomesBefore]
		activeChildren = nil
	}
	result.Outcomes = append(result.Outcomes, collectionOutcome(
		rootKey, root, instructionRootMethod(mode), rootState, len(activeChildren), firstOutcomeError(childStates),
	))
	appendInstructionCoverageRoot(result, rootKey, activeChildren)
}

func discoverDeepInstructionRoot(
	ctx context.Context,
	root string,
	engine *rules.Engine,
	result *InstructionDiscovery,
) {
	rootKey := instructionRootKey(instructionRootDeep, root)
	result.CoverageKeys = append(result.CoverageKeys, rootKey)
	if state, errText := validateInstructionRoot(root); state != ingest.OutcomeComplete {
		result.Outcomes = append(result.Outcomes, collectionOutcome(
			rootKey, root, instructionRootMethod(instructionRootDeep), state, 0, errText,
		))
		appendInstructionCoverageRoot(result, rootKey, nil)
		return
	}
	observationsBefore := len(result.Observations)
	coverageBefore := len(result.CoverageKeys)
	outcomesBefore := len(result.Outcomes)
	var childStates []ingest.CollectionOutcome
	var activeChildren []string
	seenBoundaries := make(map[string]bool)
	directories, rulesSeen := 0, 0
	rootState := ingest.OutcomeComplete
	rootError := ""

	err := walkInstructionDirectory(ctx, root, func(path string, entry os.DirEntry, walkErr error) error {
		if ctx.Err() != nil {
			rootState, rootError = ingest.OutcomePartial, "collection canceled"
			return filepath.SkipAll
		}
		if path != root && instructionPrunedDir(entry) {
			return filepath.SkipDir
		}
		if walkErr != nil {
			if path == root {
				rootState, rootError = ingest.OutcomePartial, "instruction traversal incomplete"
			} else if rootState == ingest.OutcomeComplete {
				rootState, rootError = ingest.OutcomeTruncated, "instruction traversal incomplete"
			}
			if entry != nil && entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry == nil {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() && path != root {
			directories++
			if directories > deepInstructionEntryLimit {
				rootState = ingest.OutcomeTruncated
				rootError = fmt.Sprintf("instruction traversal exceeds %d directory limit", deepInstructionEntryLimit)
				return filepath.SkipAll
			}
			if isExactInstructionTreeBoundary(root, path) {
				return filepath.SkipDir
			}
		}

		source, matched := deepInstructionSource(root, path, entry)
		if !matched {
			return nil
		}
		boundary := canonicalConfigPath(path)
		if seenBoundaries[boundary] {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		seenBoundaries[boundary] = true
		child := instructionChildKey(rootKey, boundary)

		var state ingest.OutcomeState
		var items int
		var errText string
		if source.tree {
			state, items, errText = discoverInstructionTree(
				ctx, boundary, source, child, deepInstructionEntryLimit, &directories, &rulesSeen, engine, result,
			)
		} else {
			if fileState, fileErr := validateInstructionEntry(entry); fileState != ingest.OutcomeComplete {
				state, errText = fileState, fileErr
			} else if rulesSeen >= instructionRuleLimit {
				state = ingest.OutcomeTruncated
				errText = fmt.Sprintf("instruction discovery exceeds %d file limit", instructionRuleLimit)
			} else {
				rulesSeen++
				state, items, errText = discoverInstructionFile(boundary, source.fileType, child, engine, result)
			}
		}
		method := ingest.InstructionMethodSource
		outcome := instructionChildOutcome(child, rootKey, boundary, method, state, items, errText)
		childStates = append(childStates, outcome)
		if state == ingest.OutcomeComplete {
			result.CoverageKeys = append(result.CoverageKeys, child)
			result.Outcomes = append(result.Outcomes, outcome)
			activeChildren = append(activeChildren, child)
		} else if state == ingest.OutcomePartial || state == ingest.OutcomeFailed {
			rootState, rootError = ingest.OutcomePartial, errText
		} else if state == ingest.OutcomeTruncated && rootState == ingest.OutcomeComplete {
			rootState, rootError = ingest.OutcomeTruncated, errText
		}
		if source.tree {
			return filepath.SkipDir
		}
		if rootState == ingest.OutcomeTruncated && strings.Contains(rootError, "file limit") {
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil && rootState == ingest.OutcomeComplete {
		rootState, rootError = ingest.OutcomePartial, "instruction traversal incomplete"
	}
	if rootState == ingest.OutcomePartial || rootState == ingest.OutcomeFailed {
		result.Observations = result.Observations[:observationsBefore]
		result.CoverageKeys = result.CoverageKeys[:coverageBefore]
		result.Outcomes = result.Outcomes[:outcomesBefore]
		activeChildren = nil
	}
	result.Outcomes = append(result.Outcomes, collectionOutcome(
		rootKey, root, instructionRootMethod(instructionRootDeep), rootState, len(activeChildren), rootError,
	))
	appendInstructionCoverageRoot(result, rootKey, activeChildren)
}

func validateInstructionRoot(root string) (ingest.OutcomeState, string) {
	entry, err := os.Lstat(root)
	if err != nil {
		return ingest.OutcomeFailed, "instruction root unavailable"
	}
	if entry.Mode()&os.ModeSymlink != 0 {
		return ingest.OutcomeFailed, "instruction root is a symlink"
	}
	if !entry.IsDir() {
		return ingest.OutcomeFailed, "instruction root is not a directory"
	}
	return ingest.OutcomeComplete, ""
}

func deepInstructionSource(root, path string, entry os.DirEntry) (instructionSource, bool) {
	if path == root || entry == nil {
		return instructionSource{}, false
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return instructionSource{}, false
	}
	rel = filepath.Clean(rel)
	for _, source := range instructionRegistry {
		if rel == source.relPath {
			return instructionSource{}, false
		}
	}
	for _, source := range instructionRegistry {
		if source.tree {
			if entry.IsDir() && hasPathSuffix(rel, source.relPath) {
				return source, true
			}
			continue
		}
		if entry.IsDir() {
			continue
		}
		switch source.relPath {
		case "AGENTS.md", "CLAUDE.md", ".cursorrules":
			if entry.Name() == source.relPath {
				return source, true
			}
		default:
			if hasPathSuffix(rel, source.relPath) {
				return source, true
			}
		}
	}
	return instructionSource{}, false
}

func isExactInstructionTreeBoundary(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	rel = filepath.Clean(rel)
	for _, source := range instructionRegistry {
		if source.tree && rel == source.relPath {
			return true
		}
	}
	return false
}

func hasPathSuffix(path, suffix string) bool {
	pathParts := strings.Split(filepath.Clean(path), string(filepath.Separator))
	suffixParts := strings.Split(filepath.Clean(suffix), string(filepath.Separator))
	if len(pathParts) < len(suffixParts) {
		return false
	}
	offset := len(pathParts) - len(suffixParts)
	for i := range suffixParts {
		if pathParts[offset+i] != suffixParts[i] {
			return false
		}
	}
	return true
}

func instructionPathHasSymlink(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return true
	}
	current := root
	if entry, statErr := os.Lstat(current); statErr == nil && entry.Mode()&os.ModeSymlink != 0 {
		return true
	}
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		entry, statErr := os.Lstat(current)
		if statErr != nil {
			return false
		}
		if entry.Mode()&os.ModeSymlink != 0 {
			return true
		}
	}
	return false
}

func discoverInstructionTree(
	ctx context.Context,
	treePath string,
	source instructionSource,
	ownerKey string,
	directoryLimit int,
	directories, rulesSeen *int,
	engine *rules.Engine,
	result *InstructionDiscovery,
) (ingest.OutcomeState, int, string) {
	state := ingest.OutcomeComplete
	errText := ""
	items := 0
	observationsBefore := len(result.Observations)

	err := walkInstructionDirectory(ctx, treePath, func(path string, entry os.DirEntry, walkErr error) error {
		if ctx.Err() != nil {
			state, errText = ingest.OutcomePartial, "collection canceled"
			return filepath.SkipAll
		}
		if path != treePath && instructionPrunedDir(entry) {
			return filepath.SkipDir
		}
		if walkErr != nil {
			state, errText = ingest.OutcomePartial, "instruction tree traversal incomplete"
			if entry != nil && entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry == nil || path == treePath {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			(*directories)++
			if *directories > directoryLimit {
				state = ingest.OutcomeTruncated
				errText = fmt.Sprintf("instruction tree exceeds %d directory limit", directoryLimit)
				return filepath.SkipAll
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), source.suffix) {
			return nil
		}
		if fileState, fileErr := validateInstructionEntry(entry); fileState != ingest.OutcomeComplete {
			state = ingest.OutcomePartial
			errText = fileErr
			return nil
		}
		if *rulesSeen >= instructionRuleLimit {
			state = ingest.OutcomeTruncated
			errText = fmt.Sprintf("instruction discovery exceeds %d file limit", instructionRuleLimit)
			return filepath.SkipAll
		}
		(*rulesSeen)++
		data, fileState, fileErr := readBoundedInstruction(canonicalConfigPath(path))
		if fileState != ingest.OutcomeComplete {
			if fileState == ingest.OutcomeFailed {
				state = ingest.OutcomePartial
			} else if state == ingest.OutcomeComplete {
				state = fileState
			}
			errText = fileErr
			return nil
		}
		info := AnalyzeInstructionFile(canonicalConfigPath(path), data, source.fileType, engine)
		result.Observations = append(result.Observations, InstructionObservation{Info: info, OwnerKey: ownerKey})
		items++
		return nil
	})
	if err != nil && state == ingest.OutcomeComplete {
		state, errText = ingest.OutcomePartial, "instruction tree traversal incomplete"
	}
	if state != ingest.OutcomeComplete {
		result.Observations = result.Observations[:observationsBefore]
		items = 0
	}
	return state, items, errText
}

func walkInstructionDirectory(
	ctx context.Context,
	root string,
	visit fs.WalkDirFunc,
) error {
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return err
	}
	rootEntry := fs.FileInfoToDirEntry(rootInfo)
	switch err := visit(root, rootEntry, nil); err {
	case nil:
	case filepath.SkipDir, filepath.SkipAll:
		return nil
	default:
		return err
	}

	type pendingDirectory struct {
		path  string
		entry fs.DirEntry
	}
	queue := []pendingDirectory{{path: root, entry: rootEntry}}
	for queueIndex := 0; queueIndex < len(queue); queueIndex++ {
		current := queue[queueIndex]
		if ctx.Err() != nil {
			if err := visit(current.path, current.entry, ctx.Err()); err == filepath.SkipAll {
				return nil
			}
			return ctx.Err()
		}
		directory, openErr := openInstructionDirectory(current.path)
		if openErr != nil {
			switch err := visit(current.path, current.entry, openErr); err {
			case nil, filepath.SkipDir:
				continue
			case filepath.SkipAll:
				return nil
			default:
				return err
			}
		}

		skipDirectory := false
		stopAll := false
		for {
			if ctx.Err() != nil {
				if err := visit(current.path, current.entry, ctx.Err()); err == filepath.SkipAll {
					skipDirectory = true
					stopAll = true
					break
				}
				_ = directory.Close()
				return ctx.Err()
			}
			entries, readErr := directory.ReadDir(instructionReadDirBatchSize)
			if instructionWalkBatchHook != nil && len(entries) > 0 {
				instructionWalkBatchHook(current.path, len(entries))
			}
			for _, entry := range entries {
				path := filepath.Join(current.path, entry.Name())
				if ctx.Err() != nil {
					if err := visit(path, entry, ctx.Err()); err == filepath.SkipAll {
						skipDirectory = true
						stopAll = true
						break
					}
					_ = directory.Close()
					return ctx.Err()
				}
				visitErr := visit(path, entry, nil)
				switch visitErr {
				case nil:
					if entry.IsDir() {
						queue = append(queue, pendingDirectory{path: path, entry: entry})
					}
				case filepath.SkipDir:
				case filepath.SkipAll:
					skipDirectory = true
					stopAll = true
				default:
					_ = directory.Close()
					return visitErr
				}
				if skipDirectory {
					break
				}
			}
			if skipDirectory || readErr == io.EOF {
				break
			}
			if readErr != nil {
				switch err := visit(current.path, current.entry, readErr); err {
				case nil, filepath.SkipDir:
					skipDirectory = true
				case filepath.SkipAll:
					skipDirectory = true
					stopAll = true
				default:
					_ = directory.Close()
					return err
				}
				break
			}
			if len(entries) == 0 {
				break
			}
		}
		if closeErr := directory.Close(); closeErr != nil && !skipDirectory {
			switch err := visit(current.path, current.entry, closeErr); err {
			case nil, filepath.SkipDir:
			case filepath.SkipAll:
				return nil
			default:
				return err
			}
		}
		if stopAll || skipDirectory && ctx.Err() != nil {
			return nil
		}
	}
	return nil
}

func discoverInstructionFile(
	path, fileType, ownerKey string,
	engine *rules.Engine,
	result *InstructionDiscovery,
) (ingest.OutcomeState, int, string) {
	data, state, errText := readBoundedInstruction(path)
	if state != ingest.OutcomeComplete {
		return state, 0, errText
	}
	info := AnalyzeInstructionFile(path, data, fileType, engine)
	result.Observations = append(result.Observations, InstructionObservation{Info: info, OwnerKey: ownerKey})
	return ingest.OutcomeComplete, 1, ""
}

func appendInstructionCoverageRoot(result *InstructionDiscovery, rootKey string, children []string) {
	children = uniqueSorted(append([]string(nil), children...))
	contract := instructionRegistryContract()
	result.AuthoritativeRoots = append(result.AuthoritativeRoots, ingest.CoverageRoot{
		CoverageKey:       rootKey,
		ChildCoverageKeys: children,
		RegistryContract:  &contract,
	})
}

func instructionChildOutcome(
	key, parent, target, method string,
	state ingest.OutcomeState,
	items int,
	errText string,
) ingest.CollectionOutcome {
	outcome := collectionOutcome(key, target, method, state, items, errText)
	outcome.ParentCoverageKey = parent
	return outcome
}

func firstOutcomeError(outcomes []ingest.CollectionOutcome) string {
	for _, outcome := range outcomes {
		if outcome.Error != "" {
			return outcome.Error
		}
	}
	return ""
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

func readBoundedInstruction(path string) ([]byte, ingest.OutcomeState, string) {
	if state, errText := validateInstructionFile(path); state != ingest.OutcomeComplete {
		return nil, state, errText
	}
	data, state, errText := readBoundedConfig(path)
	if data == nil && state == ingest.OutcomeComplete {
		return nil, ingest.OutcomeFailed, "instruction source changed during discovery"
	}
	if state == ingest.OutcomeTruncated {
		return nil, state, fmt.Sprintf("file exceeds %d byte limit", maxInstructionFileBytes)
	}
	return data, state, errText
}

func validateInstructionEntry(entry os.DirEntry) (ingest.OutcomeState, string) {
	if entry == nil {
		return ingest.OutcomeFailed, "instruction source unavailable"
	}
	info, err := entry.Info()
	if err != nil {
		return ingest.OutcomeFailed, "instruction source unavailable"
	}
	if !info.Mode().IsRegular() {
		return ingest.OutcomeFailed, "registered instruction source is not a regular file"
	}
	return ingest.OutcomeComplete, ""
}

func validateInstructionFile(path string) (ingest.OutcomeState, string) {
	info, err := os.Lstat(path)
	if err != nil {
		return ingest.OutcomeFailed, "instruction source unavailable"
	}
	if !info.Mode().IsRegular() {
		return ingest.OutcomeFailed, "registered instruction source is not a regular file"
	}
	return ingest.OutcomeComplete, ""
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

func DiscoverInstructionFiles(homeDir, projectDir string, engine *rules.Engine) []InstructionFileInfo {
	result := DiscoverInstructions(context.Background(), homeDir, projectDir, InstructionScan{}, engine)
	byPath := make(map[string]InstructionFileInfo)
	for _, observation := range result.Observations {
		byPath[observation.Info.Path] = observation.Info
	}
	paths := make([]string, 0, len(byPath))
	for path := range byPath {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	infos := make([]InstructionFileInfo, 0, len(paths))
	for _, path := range paths {
		infos = append(infos, byPath[path])
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
