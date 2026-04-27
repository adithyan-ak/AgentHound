package rules

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// builtinTestsDir is the source-only path holding inline test
// fixtures for the runtime-embedded builtin rules. The fixtures are
// kept on disk (not embedded) so that strings like "https://evil.com"
// and "TOKEN_HERE" never ship in the production binary, which would
// otherwise look like AV bait.
const builtinTestsDir = "builtin_tests"

// loadBuiltinTestsFromDisk reads sdk/rules/builtin_tests/<id>.yaml and
// returns the inline test cases for that rule. The file contains only
// a top-level `tests:` block; everything else (id, matcher, etc.) is
// loaded from the embedded builtin/<id>.yaml at runtime.
//
// Test-only helper: the production rules engine intentionally does
// not look at this directory.
func loadBuiltinTestsFromDisk(id string) ([]TestCase, error) {
	path := filepath.Join(builtinTestsDir, id+".yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read builtin tests for %s: %w", id, err)
	}
	var wrapper struct {
		Tests []TestCase `yaml:"tests"`
	}
	if err := yaml.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("parse builtin tests for %s: %w", id, err)
	}
	return wrapper.Tests, nil
}
