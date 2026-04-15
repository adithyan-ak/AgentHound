package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/adithyan-ak/agenthound/internal/rules"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "Manage detection rules",
}

var rulesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List loaded detection rules",
	RunE:  runRulesList,
}

var rulesValidateCmd = &cobra.Command{
	Use:   "validate [path]",
	Short: "Validate rule definitions",
	Long: `Validate detection rules for correctness.

If path is a file, validates that single rule.
If path is a directory, validates all .yaml files in it.
If no path given, validates all loaded rules (builtin + custom).`,
	Args: cobra.MaximumNArgs(1),
	RunE: runRulesValidate,
}

var rulesTestCmd = &cobra.Command{
	Use:   "test [path]",
	Short: "Run inline test cases for rules",
	Long: `Run the inline test cases defined in each rule.

If path is a file, tests that single rule.
If path is a directory, tests all .yaml files in it.
If no path given, tests all loaded rules (builtin + custom).`,
	Args: cobra.MaximumNArgs(1),
	RunE: runRulesTest,
}

func init() {
	rulesListCmd.Flags().String("format", "table", "Output format: table or json")
	rulesListCmd.Flags().String("collector", "", "Filter by collector: mcp, a2a, config, all")
	rulesListCmd.Flags().String("severity", "", "Filter by severity: critical, high, medium, low, info")
	rulesListCmd.Flags().String("tag", "", "Filter by tag")
	rulesListCmd.Flags().Bool("builtin-only", false, "Show only built-in rules")
	rulesListCmd.Flags().Bool("custom-only", false, "Show only custom rules")

	rulesValidateCmd.Flags().Bool("strict", false, "Treat warnings as errors")

	rulesTestCmd.Flags().String("format", "table", "Output format: table or json")
	rulesTestCmd.Flags().Bool("verbose", false, "Show all test cases, not just failures")

	rulesCmd.AddCommand(rulesListCmd)
	rulesCmd.AddCommand(rulesValidateCmd)
	rulesCmd.AddCommand(rulesTestCmd)
	rootCmd.AddCommand(rulesCmd)
}

func buildRulesEngine() (*rules.Engine, error) {
	customDir := os.Getenv("AGENTHOUND_RULES_DIR")
	if customDir == "" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			customDir = filepath.Join(home, ".agenthound", "rules")
		}
	}
	return rules.NewEngine(rules.LoadOptions{CustomDir: customDir})
}

func runRulesList(cmd *cobra.Command, _ []string) error {
	format, _ := cmd.Flags().GetString("format")
	collector, _ := cmd.Flags().GetString("collector")
	severity, _ := cmd.Flags().GetString("severity")
	tag, _ := cmd.Flags().GetString("tag")
	builtinOnly, _ := cmd.Flags().GetBool("builtin-only")
	customOnly, _ := cmd.Flags().GetBool("custom-only")

	if format != "table" && format != "json" {
		return fmt.Errorf("invalid format %q: must be table or json", format)
	}
	if builtinOnly && customOnly {
		return fmt.Errorf("--builtin-only and --custom-only are mutually exclusive")
	}

	engine, err := buildRulesEngine()
	if err != nil {
		return fmt.Errorf("loading rules: %w", err)
	}

	loaded := engine.Rules()
	var filtered []rules.Rule
	for _, r := range loaded {
		if collector != "" && r.Scope.Collector != collector {
			continue
		}
		if severity != "" && r.Severity != severity {
			continue
		}
		if tag != "" && !containsString(r.Tags, tag) {
			continue
		}
		if builtinOnly && r.Source != "builtin" {
			continue
		}
		if customOnly && r.Source == "builtin" {
			continue
		}
		filtered = append(filtered, r)
	}

	if format == "json" {
		return printJSON(filtered)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ID\tSEVERITY\tCOLLECTOR\tTARGETS\tTAGS\tSOURCE")
	for _, r := range filtered {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			r.ID,
			r.Severity,
			r.Scope.Collector,
			strings.Join(r.Scope.Targets, ","),
			strings.Join(r.Tags, ","),
			r.Source,
		)
	}
	_ = w.Flush()

	builtinCount := 0
	customCount := 0
	for _, r := range loaded {
		if r.Source == "builtin" {
			builtinCount++
		} else {
			customCount++
		}
	}
	_, _ = fmt.Fprintf(os.Stderr, "\n%d rule(s) loaded (%d builtin, %d custom)\n", len(loaded), builtinCount, customCount)

	return nil
}

func runRulesValidate(cmd *cobra.Command, args []string) error {
	strict, _ := cmd.Flags().GetBool("strict")

	loaded, err := loadRulesForCommand(args)
	if err != nil {
		return err
	}

	passed := 0
	failed := 0

	for _, r := range loaded {
		valErrs := rules.ValidateRule(r)

		testFailures := rules.RunTests(r)

		allErrs := make([]string, 0, len(valErrs)+len(testFailures))
		for _, ve := range valErrs {
			allErrs = append(allErrs, ve.Error())
		}
		for _, tf := range testFailures {
			allErrs = append(allErrs, fmt.Sprintf("tests[%d]: expected match=%t, got match=%t", tf.TestIndex, tf.Expected, tf.Got))
		}

		if strict && len(r.Tests) == 0 {
			allErrs = append(allErrs, "no test cases defined (strict mode)")
		}

		if len(allErrs) > 0 {
			fmt.Printf("[FAIL] %s\n", r.ID)
			for _, e := range allErrs {
				fmt.Printf("  - %s\n", e)
			}
			failed++
		} else {
			fmt.Printf("[PASS] %s (%d tests)\n", r.ID, len(r.Tests))
			passed++
		}
	}

	fmt.Printf("\n%d passed, %d failed\n", passed, failed)

	if failed > 0 {
		os.Exit(1)
	}

	return nil
}

func runRulesTest(cmd *cobra.Command, args []string) error {
	format, _ := cmd.Flags().GetString("format")
	verbose, _ := cmd.Flags().GetBool("verbose")

	if format != "table" && format != "json" {
		return fmt.Errorf("invalid format %q: must be table or json", format)
	}

	loaded, err := loadRulesForCommand(args)
	if err != nil {
		return err
	}

	totalCases := 0
	for _, r := range loaded {
		totalCases += len(r.Tests)
	}

	_, _ = fmt.Fprintf(os.Stderr, "Testing %d rule(s), %d test cases...\n\n", len(loaded), totalCases)

	type testResult struct {
		RuleID      string `json:"rule_id"`
		TestIndex   int    `json:"test_index"`
		Description string `json:"description"`
		Passed      bool   `json:"passed"`
		Expected    bool   `json:"expected,omitempty"`
		Got         bool   `json:"got,omitempty"`
	}

	var allResults []testResult
	totalPassed := 0
	totalFailed := 0

	for _, r := range loaded {
		failures := rules.RunTests(r)
		failMap := make(map[int]rules.TestFailure)
		for _, f := range failures {
			failMap[f.TestIndex] = f
		}

		headerPrinted := verbose
		if format == "table" && verbose {
			fmt.Printf("%s:\n", r.ID)
		}

		for i, tc := range r.Tests {
			f, isFail := failMap[i]
			if isFail {
				totalFailed++
				if format == "table" {
					if !headerPrinted {
						fmt.Printf("%s:\n", r.ID)
						headerPrinted = true
					}
					desc := tc.Description
					if desc == "" {
						desc = fmt.Sprintf("test[%d]", i)
					}
					fmt.Printf("  [FAIL] %s (expected match=%t, got match=%t)\n", desc, f.Expected, f.Got)
				}
				allResults = append(allResults, testResult{
					RuleID:      r.ID,
					TestIndex:   i,
					Description: tc.Description,
					Passed:      false,
					Expected:    f.Expected,
					Got:         f.Got,
				})
			} else {
				totalPassed++
				if format == "table" && verbose {
					desc := tc.Description
					if desc == "" {
						desc = fmt.Sprintf("test[%d]", i)
					}
					fmt.Printf("  [PASS] %s\n", desc)
				}
				allResults = append(allResults, testResult{
					RuleID:      r.ID,
					TestIndex:   i,
					Description: tc.Description,
					Passed:      true,
				})
			}
		}

		if format == "table" && verbose {
			fmt.Println()
		}
	}

	if format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(allResults); err != nil {
			return err
		}
	}

	_, _ = fmt.Fprintf(os.Stderr, "%d test cases: %d passed, %d failed\n", totalPassed+totalFailed, totalPassed, totalFailed)

	if totalFailed > 0 {
		os.Exit(1)
	}
	return nil
}

func loadRulesForCommand(args []string) ([]rules.Rule, error) {
	if len(args) == 0 {
		engine, err := buildRulesEngine()
		if err != nil {
			return nil, fmt.Errorf("loading rules: %w", err)
		}
		return engine.Rules(), nil
	}

	path := args[0]
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}

	if info.IsDir() {
		return loadRulesFromDir(path)
	}
	r, err := loadRuleFromFile(path)
	if err != nil {
		return nil, err
	}
	return []rules.Rule{*r}, nil
}

func loadRuleFromFile(path string) (*rules.Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var r rules.Rule
	if err := yaml.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	r.Source = path
	if r.Version == 0 {
		r.Version = 1
	}
	if !yamlHasField(data, "enabled") {
		r.Enabled = true
	}
	return &r, nil
}

func loadRulesFromDir(dir string) ([]rules.Rule, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading directory %s: %w", dir, err)
	}
	var loaded []rules.Rule
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		r, err := loadRuleFromFile(filepath.Join(dir, name))
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "warning: %v\n", err)
			continue
		}
		loaded = append(loaded, *r)
	}
	return loaded, nil
}

func yamlHasField(data []byte, field string) bool {
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return false
	}
	_, ok := raw[field]
	return ok
}

func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
