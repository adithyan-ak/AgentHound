package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

const validRuleYAML = `
id: valid-rule
name: Valid rule
severity: medium
scope:
  collector: config
  targets:
    - instruction.content
matcher:
  type: keyword
  keywords:
    - ignore previous instructions
tests:
  - input: ignore previous instructions
    should_match: true
`

func TestLoadRulesFromDirReturnsValidRulesAndParseFailures(t *testing.T) {
	dir := writeMixedRuleDirectory(t)

	loaded, failures, err := loadRulesFromDir(dir)
	if err != nil {
		t.Fatalf("loadRulesFromDir: %v", err)
	}
	if len(loaded) != 1 || loaded[0].ID != "valid-rule" {
		t.Fatalf("loaded rules = %+v, want valid-rule only", loaded)
	}
	if len(failures) != 1 ||
		!strings.Contains(failures[0].Error(), "broken.yaml") {
		t.Fatalf("load failures = %v, want broken.yaml parse failure", failures)
	}
}

func TestRulesValidateDirectoryParseFailureExitsNonZero(t *testing.T) {
	if os.Getenv("AGENTHOUND_RULES_VALIDATE_HELPER") == "1" {
		cmd := &cobra.Command{}
		cmd.Flags().Bool("strict", false, "")
		if err := runRulesValidate(
			cmd,
			[]string{os.Getenv("AGENTHOUND_RULES_VALIDATE_DIR")},
		); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		return
	}

	dir := writeMixedRuleDirectory(t)
	cmd := exec.Command(
		os.Args[0],
		"-test.run=^TestRulesValidateDirectoryParseFailureExitsNonZero$",
	)
	cmd.Env = append(
		os.Environ(),
		"AGENTHOUND_RULES_VALIDATE_HELPER=1",
		"AGENTHOUND_RULES_VALIDATE_DIR="+dir,
	)
	output, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("rules validate error = %v, output:\n%s", err, output)
	}

	got := string(output)
	for _, want := range []string{
		"[FAIL] parsing " + filepath.Join(dir, "broken.yaml"),
		"[PASS] valid-rule (1 tests)",
		"1 passed, 1 failed",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rules validate output missing %q:\n%s", want, got)
		}
	}
}

func writeMixedRuleDirectory(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(dir, "valid.yaml"),
		[]byte(validRuleYAML),
		0o600,
	); err != nil {
		t.Fatalf("write valid rule: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(dir, "broken.yaml"),
		[]byte("matcher: ["),
		0o600,
	); err != nil {
		t.Fatalf("write broken rule: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(dir, "README.md"),
		[]byte("ignored"),
		0o600,
	); err != nil {
		t.Fatalf("write ignored file: %v", err)
	}
	return dir
}
