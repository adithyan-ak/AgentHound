package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadBuiltinRules(t *testing.T) {
	rules, err := loadBuiltinRules()
	if err != nil {
		t.Fatalf("loadBuiltinRules: %v", err)
	}
	if len(rules) == 0 {
		t.Error("expected builtin rules to be loaded")
	}
	for _, r := range rules {
		if r.Source != "builtin" {
			t.Errorf("rule %q source = %q, want %q", r.ID, r.Source, "builtin")
		}
	}
}

func TestBuiltinRules_AllValidate(t *testing.T) {
	rules, err := loadBuiltinRules()
	if err != nil {
		t.Fatalf("loadBuiltinRules: %v", err)
	}
	for _, r := range rules {
		t.Run(r.ID, func(t *testing.T) {
			errs := ValidateRule(r)
			if len(errs) > 0 {
				t.Errorf("validation errors: %v", errs)
			}
		})
	}
}

// TestBuiltinRules_AllPassInlineTests verifies that every builtin rule
// passes its inline test cases. Test fixtures live in
// sdk/rules/builtin_tests/<id>.yaml (NOT embedded in the runtime
// binary) so that AV-bait strings like "https://evil.com" and
// "TOKEN_HERE" never ship in the shipped artifact.
func TestBuiltinRules_AllPassInlineTests(t *testing.T) {
	rules, err := loadBuiltinRules()
	if err != nil {
		t.Fatalf("loadBuiltinRules: %v", err)
	}
	for _, r := range rules {
		t.Run(r.ID, func(t *testing.T) {
			tests, err := loadBuiltinTestsFromDisk(r.ID)
			if err != nil {
				t.Fatalf("load tests for %s: %v", r.ID, err)
			}
			if len(tests) == 0 {
				t.Skipf("no inline tests defined for %s", r.ID)
			}
			// Re-attach tests for the duration of this assertion;
			// production loading deliberately leaves r.Tests empty.
			r.Tests = tests
			failures := RunTests(r)
			for _, f := range failures {
				t.Errorf("test %d (%s): expected match=%v got match=%v input=%q",
					f.TestIndex, f.Description, f.Expected, f.Got, f.Input)
			}
		})
	}
}

// TestBuiltinRules_NoInlineTestsInProductionYAML is a defense-in-depth
// regression. The production-embedded YAMLs MUST NOT contain `tests:`
// blocks — otherwise AV-bait fixture strings re-enter the runtime
// binary and trip EDRs.
func TestBuiltinRules_NoInlineTestsInProductionYAML(t *testing.T) {
	rules, err := loadBuiltinRules()
	if err != nil {
		t.Fatalf("loadBuiltinRules: %v", err)
	}
	for _, r := range rules {
		if len(r.Tests) > 0 {
			t.Errorf("rule %q has %d inline tests in production YAML; move to builtin_tests/%s.yaml",
				r.ID, len(r.Tests), r.ID)
		}
	}
}

func TestLoadCustomRules_MissingDir(t *testing.T) {
	rules, err := loadCustomRules("/nonexistent/path/to/rules")
	if err != nil {
		t.Fatalf("expected nil error for missing dir, got %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(rules))
	}
}

func TestLoadCustomRules_ValidRule(t *testing.T) {
	dir := t.TempDir()
	ruleYAML := `
id: custom-test-rule
name: Custom Test
description: a custom rule
version: 1
severity: medium
scope:
  collector: mcp
  targets: [tool.description]
matcher:
  type: keyword
  keywords: [test]
  case_insensitive: true
emit:
  finding_type: test_finding
`
	if err := os.WriteFile(filepath.Join(dir, "custom.yaml"), []byte(ruleYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	rules, err := loadCustomRules(dir)
	if err != nil {
		t.Fatalf("loadCustomRules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].ID != "custom-test-rule" {
		t.Errorf("ID = %q, want %q", rules[0].ID, "custom-test-rule")
	}
	if rules[0].Source != filepath.Join(dir, "custom.yaml") {
		t.Errorf("Source = %q, want %q", rules[0].Source, filepath.Join(dir, "custom.yaml"))
	}
	if !rules[0].Enabled {
		t.Error("Enabled should default to true when not specified")
	}
}

func TestLoadCustomRules_InvalidYAMLSkipped(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte("{{invalid yaml"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "good.yaml"), []byte(`
id: good-rule-test
name: Good Rule
version: 1
severity: low
scope:
  collector: all
  targets: [tool.name]
matcher:
  type: keyword
  keywords: [good]
emit:
  finding_type: test
`), 0o644); err != nil {
		t.Fatal(err)
	}

	rules, err := loadCustomRules(dir)
	if err != nil {
		t.Fatalf("loadCustomRules: %v", err)
	}
	if len(rules) != 1 {
		t.Errorf("expected 1 rule (bad yaml skipped), got %d", len(rules))
	}
}

func TestLoadCustomRules_NonYAMLSkipped(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("not a rule"), 0o644); err != nil {
		t.Fatal(err)
	}

	rules, err := loadCustomRules(dir)
	if err != nil {
		t.Fatalf("loadCustomRules: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(rules))
	}
}

func TestParseRuleFile_EnabledDefault(t *testing.T) {
	yaml := `
id: test-enabled-default
name: Test
severity: low
scope:
  collector: mcp
  targets: [tool.name]
matcher:
  type: keyword
  keywords: [test]
emit:
  finding_type: test
`
	r, err := parseRuleFile([]byte(yaml), "test")
	if err != nil {
		t.Fatalf("parseRuleFile: %v", err)
	}
	if !r.Enabled {
		t.Error("Enabled should default to true when field is absent")
	}
}

func TestParseRuleFile_EnabledExplicitFalse(t *testing.T) {
	yaml := `
id: test-disabled
name: Test Disabled
enabled: false
severity: low
scope:
  collector: mcp
  targets: [tool.name]
matcher:
  type: keyword
  keywords: [test]
emit:
  finding_type: test
`
	r, err := parseRuleFile([]byte(yaml), "test")
	if err != nil {
		t.Fatalf("parseRuleFile: %v", err)
	}
	if r.Enabled {
		t.Error("Enabled should be false when explicitly set to false")
	}
}

func TestParseRuleFile_VersionDefault(t *testing.T) {
	yaml := `
id: test-version-default
name: Test
severity: low
scope:
  collector: mcp
  targets: [tool.name]
matcher:
  type: keyword
  keywords: [test]
emit:
  finding_type: test
`
	r, err := parseRuleFile([]byte(yaml), "test")
	if err != nil {
		t.Fatalf("parseRuleFile: %v", err)
	}
	if r.Version != 1 {
		t.Errorf("Version = %d, want 1 (default)", r.Version)
	}
}
