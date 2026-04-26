package config

import (
	"os"
	"path/filepath"

	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/rules"
)

type InstructionFileInfo struct {
	Path         string
	Type         string // "agents.md", "claude.md", "memory.md", "cursorrules", "copilot-instructions"
	Hash         string
	IsSuspicious bool
	Patterns     []common.PatternMatch
}

type instructionTarget struct {
	relPath  string
	fileType string
}

var projectTargets = []instructionTarget{
	{"AGENTS.md", "agents.md"},
	{"CLAUDE.md", "claude.md"},
	{".cursorrules", "cursorrules"},
	{".copilot-instructions.md", "copilot-instructions"},
	{filepath.Join(".github", "copilot-instructions.md"), "copilot-instructions"},
}

var userTargets = []instructionTarget{
	{filepath.Join(".claude", "CLAUDE.md"), "claude.md"},
}

func DiscoverInstructionFiles(homeDir, projectDir string, engine *rules.Engine) []InstructionFileInfo {
	var results []InstructionFileInfo

	if projectDir != "" {
		for _, t := range projectTargets {
			fullPath := filepath.Join(projectDir, t.relPath)
			if info := tryReadAndAnalyze(fullPath, t.fileType, engine); info != nil {
				results = append(results, *info)
			}
		}
	}

	if homeDir != "" {
		for _, t := range userTargets {
			fullPath := filepath.Join(homeDir, t.relPath)
			if info := tryReadAndAnalyze(fullPath, t.fileType, engine); info != nil {
				results = append(results, *info)
			}
		}
	}

	return results
}

func AnalyzeInstructionFile(path string, data []byte, fileType string, engine *rules.Engine) InstructionFileInfo {
	text := string(data)

	var patterns []common.PatternMatch
	matches := engine.EvaluateAll("config", map[string]string{
		"instruction.content": text,
	})
	for _, m := range matches {
		if m.Emit.FindingType == "has_injection_patterns" {
			label := ""
			if len(m.Labels) > 0 {
				label = m.Labels[0]
			} else {
				label = m.RuleID
			}
			patterns = append(patterns, common.PatternMatch{
				Name:     label,
				Severity: m.Severity,
				Offset:   m.Offset,
				Text:     m.Text,
			})
		}
	}

	return InstructionFileInfo{
		Path:         path,
		Type:         fileType,
		Hash:         common.HashSHA256(text),
		IsSuspicious: len(patterns) > 0,
		Patterns:     patterns,
	}
}

func tryReadAndAnalyze(path, fileType string, engine *rules.Engine) *InstructionFileInfo {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	info := AnalyzeInstructionFile(path, data, fileType, engine)
	return &info
}
