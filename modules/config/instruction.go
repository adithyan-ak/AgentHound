package config

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/sdk/rules"
)

const maxInstructionFileBytes int64 = 4 << 20

var (
	instructionTraversalEntryLimit = 100_000
	instructionRuleLimit           = 10_000
)

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
	engine *rules.Engine,
) InstructionDiscovery {
	var result InstructionDiscovery
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

	if projectRoot != "" {
		discoverCursorRuleTrees(ctx, projectRoot, engine, &result)
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
	engine *rules.Engine,
	result *InstructionDiscovery,
) {
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
		if entry != nil && entry.IsDir() && entry.Name() == ".git" {
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
			if entries > instructionTraversalEntryLimit {
				traversalState = ingest.OutcomeTruncated
				traversalError = fmt.Sprintf("project traversal exceeds %d entry limit", instructionTraversalEntryLimit)
				return filepath.SkipAll
			}
		}
		if !entry.IsDir() || entry.Name() != "rules" || filepath.Base(filepath.Dir(path)) != ".cursor" {
			return nil
		}
		treeState, treeErr := discoverCursorRuleTree(ctx, path, engine, &entries, &rulesSeen, result)
		if treeState != ingest.OutcomeComplete && traversalState == ingest.OutcomeComplete {
			traversalState = treeState
			traversalError = treeErr
		}
		if entries > instructionTraversalEntryLimit {
			return filepath.SkipAll
		}
		return filepath.SkipDir
	})
	if err != nil && traversalState == ingest.OutcomeComplete {
		traversalState = ingest.OutcomePartial
		traversalError = "project traversal incomplete"
	}
	result.Outcomes = append(result.Outcomes, collectionOutcome(
		traversalKey, projectRoot, "cursor_rule_traversal", traversalState, rulesSeen, traversalError,
	))
}

func discoverCursorRuleTree(
	ctx context.Context,
	treePath string,
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

	err := filepath.WalkDir(treePath, func(path string, entry os.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			state, errText = ingest.OutcomePartial, "collection canceled"
			return filepath.SkipAll
		}
		// A nested rules tree is still part of the project traversal boundary.
		// Prune repository metadata before counting it, even when a .git
		// directory happens to exist below .cursor/rules.
		if entry != nil && entry.IsDir() && entry.Name() == ".git" {
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
		if entry.IsDir() && entry.Type()&os.ModeSymlink != 0 {
			return filepath.SkipDir
		}
		(*entries)++
		if *entries > instructionTraversalEntryLimit {
			state = ingest.OutcomeTruncated
			errText = fmt.Sprintf("project traversal exceeds %d entry limit", instructionTraversalEntryLimit)
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
		result.Outcomes = append(result.Outcomes, collectionOutcome(
			fileKey, filePath, "cursor_rule_read", fileState, fileItems, fileErr,
		))
		return nil
	})
	if err != nil && state == ingest.OutcomeComplete {
		state, errText = ingest.OutcomePartial, "rules tree traversal incomplete"
	}
	result.Outcomes = append(result.Outcomes, collectionOutcome(
		treeKey, treePath, "cursor_rule_tree", state, items, errText,
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
	result := DiscoverInstructions(context.Background(), homeDir, projectDir, engine)
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
