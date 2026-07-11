package rules

import (
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed builtin
var builtinFS embed.FS

func loadBuiltinRules() ([]Rule, error) {
	rules, failures, err := loadBuiltinRulesWithFailures()
	for _, failure := range failures {
		slog.Warn("failed to load builtin rule", "error", failure)
	}
	return rules, err
}

func loadBuiltinRulesWithFailures() ([]Rule, []string, error) {
	return loadRulesFromFSWithFailures(builtinFS, "builtin", "builtin")
}

func loadRulesFromFSWithFailures(
	fsys fs.FS,
	root string,
	source string,
) ([]Rule, []string, error) {
	var rules []Rule
	var failures []string
	entries, err := fs.ReadDir(fsys, root)
	if err != nil {
		return nil, nil, fmt.Errorf("reading %s directory: %w", root, err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		data, err := fs.ReadFile(fsys, filepath.Join(root, entry.Name()))
		if err != nil {
			failures = append(
				failures,
				fmt.Sprintf("read rule %s: %v", entry.Name(), err),
			)
			continue
		}
		r, err := parseRuleFile(data, source)
		if err != nil {
			failures = append(
				failures,
				fmt.Sprintf("parse rule %s: %v", entry.Name(), err),
			)
			continue
		}
		rules = append(rules, *r)
	}
	return rules, failures, nil
}

func loadCustomRules(dir string) ([]Rule, error) {
	rules, failures, err := loadCustomRulesWithFailures(dir)
	for _, failure := range failures {
		slog.Warn("failed to load custom rule", "error", failure)
	}
	return rules, err
}

func loadCustomRulesWithFailures(dir string) ([]Rule, []string, error) {
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("stat custom rules dir: %w", err)
	}
	if !info.IsDir() {
		return nil, nil, fmt.Errorf("custom rules path is not a directory: %s", dir)
	}

	var rules []Rule
	var failures []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("reading custom rules dir: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			failures = append(
				failures,
				fmt.Sprintf("read custom rule %s: %v", path, err),
			)
			continue
		}
		r, err := parseRuleFile(data, path)
		if err != nil {
			failures = append(
				failures,
				fmt.Sprintf("parse custom rule %s: %v", path, err),
			)
			continue
		}
		rules = append(rules, *r)
	}
	return rules, failures, nil
}

func parseRuleFile(data []byte, source string) (*Rule, error) {
	var r Rule
	if err := yaml.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("yaml unmarshal: %w", err)
	}
	r.Source = source
	if r.Version == 0 {
		r.Version = 1
	}
	if !r.yamlHasEnabled(data) {
		r.Enabled = true
	}
	return &r, nil
}

func (r *Rule) yamlHasEnabled(data []byte) bool {
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return false
	}
	_, ok := raw["enabled"]
	return ok
}
