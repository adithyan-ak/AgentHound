package rules

import (
	"strings"
	"testing"
)

func validRule() Rule {
	return Rule{
		ID:       "test-valid-rule",
		Name:     "Test Valid Rule",
		Version:  1,
		Enabled:  true,
		Severity: "high",
		Scope:    Scope{Collector: "mcp", Targets: []string{"tool.description"}},
		Matcher:  MatcherSpec{Type: "regex", Pattern: `test`},
		Emit:     EmitConfig{FindingType: "test"},
	}
}

func TestValidateRule_Valid(t *testing.T) {
	errs := ValidateRule(validRule())
	if len(errs) > 0 {
		t.Errorf("expected no errors, got %v", errs)
	}
}

func TestValidateRule_InvalidID(t *testing.T) {
	tests := []struct {
		name string
		id   string
	}{
		{"too short", "ab"},
		{"starts with hyphen", "-bad-id"},
		{"ends with hyphen", "bad-id-"},
		{"uppercase", "Bad-Rule"},
		{"spaces", "bad rule"},
		{"too long", strings.Repeat("a", 65)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := validRule()
			r.ID = tc.id
			errs := ValidateRule(r)
			if !hasField(errs, "id") {
				t.Errorf("expected id error for %q, got %v", tc.id, errs)
			}
		})
	}
}

func TestValidateRule_InvalidSeverity(t *testing.T) {
	r := validRule()
	r.Severity = "urgent"
	errs := ValidateRule(r)
	if !hasField(errs, "severity") {
		t.Errorf("expected severity error, got %v", errs)
	}
}

func TestValidateRule_InvalidCollector(t *testing.T) {
	r := validRule()
	r.Scope.Collector = "grpc"
	errs := ValidateRule(r)
	if !hasField(errs, "scope.collector") {
		t.Errorf("expected scope.collector error, got %v", errs)
	}
}

func TestValidateRule_EmptyTargets(t *testing.T) {
	r := validRule()
	r.Scope.Targets = nil
	errs := ValidateRule(r)
	if !hasField(errs, "scope.targets") {
		t.Errorf("expected scope.targets error, got %v", errs)
	}
}

func TestValidateRule_UnknownTarget(t *testing.T) {
	r := validRule()
	r.Scope.Targets = []string{"tool.unknown_field"}
	errs := ValidateRule(r)
	if !hasField(errs, "scope.targets[0]") {
		t.Errorf("expected scope.targets[0] error, got %v", errs)
	}
}

func TestValidateRule_EmptyName(t *testing.T) {
	r := validRule()
	r.Name = ""
	errs := ValidateRule(r)
	if !hasField(errs, "name") {
		t.Errorf("expected name error, got %v", errs)
	}
}

func TestValidateRule_InvalidRegex(t *testing.T) {
	r := validRule()
	r.Matcher = MatcherSpec{Type: "regex", Pattern: "[invalid"}
	errs := ValidateRule(r)
	if !hasField(errs, "matcher.pattern") {
		t.Errorf("expected matcher.pattern error, got %v", errs)
	}
}

func TestValidateRule_RegexTooLong(t *testing.T) {
	r := validRule()
	r.Matcher = MatcherSpec{Type: "regex", Pattern: strings.Repeat("a", 1025)}
	errs := ValidateRule(r)
	if !hasField(errs, "matcher.pattern") {
		t.Errorf("expected matcher.pattern error, got %v", errs)
	}
}

func TestValidateRule_TooManyKeywords(t *testing.T) {
	r := validRule()
	kws := make([]string, 101)
	for i := range kws {
		kws[i] = "kw"
	}
	r.Matcher = MatcherSpec{Type: "keyword", Keywords: kws}
	errs := ValidateRule(r)
	if !hasField(errs, "matcher.keywords") {
		t.Errorf("expected matcher.keywords error, got %v", errs)
	}
}

func TestValidateRule_KeywordTooLong(t *testing.T) {
	r := validRule()
	r.Matcher = MatcherSpec{Type: "keyword", Keywords: []string{strings.Repeat("x", 257)}}
	errs := ValidateRule(r)
	if !hasField(errs, "matcher.keywords[0]") {
		t.Errorf("expected matcher.keywords[0] error, got %v", errs)
	}
}

func TestValidateRule_CompoundNesting(t *testing.T) {
	r := validRule()
	r.Matcher = MatcherSpec{
		Type:     "compound",
		Operator: "and",
		Matchers: []MatcherSpec{
			{Type: "compound", Operator: "or", Matchers: []MatcherSpec{
				{Type: "keyword", Keywords: []string{"test"}},
			}},
		},
	}
	errs := ValidateRule(r)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "nested") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected compound nesting error, got %v", errs)
	}
}

func TestValidateRule_CompoundTooManyChildren(t *testing.T) {
	r := validRule()
	children := make([]MatcherSpec, 11)
	for i := range children {
		children[i] = MatcherSpec{Type: "keyword", Keywords: []string{"test"}}
	}
	r.Matcher = MatcherSpec{Type: "compound", Operator: "and", Matchers: children}
	errs := ValidateRule(r)
	if !hasField(errs, "matcher.matchers") {
		t.Errorf("expected matcher.matchers error, got %v", errs)
	}
}

func TestValidateRule_CompoundBadOperator(t *testing.T) {
	r := validRule()
	r.Matcher = MatcherSpec{
		Type:     "compound",
		Operator: "xor",
		Matchers: []MatcherSpec{{Type: "keyword", Keywords: []string{"test"}}},
	}
	errs := ValidateRule(r)
	if !hasField(errs, "matcher.operator") {
		t.Errorf("expected matcher.operator error, got %v", errs)
	}
}

func TestValidateRule_EntropyBadCharset(t *testing.T) {
	r := validRule()
	r.Matcher = MatcherSpec{Type: "entropy", Charset: "utf8", Threshold: 4.0, MinLength: 8}
	errs := ValidateRule(r)
	if !hasField(errs, "matcher.charset") {
		t.Errorf("expected matcher.charset error, got %v", errs)
	}
}

func TestValidateRule_EntropyBadThreshold(t *testing.T) {
	r := validRule()
	r.Matcher = MatcherSpec{Type: "entropy", Charset: "base64", Threshold: 9.0, MinLength: 8}
	errs := ValidateRule(r)
	if !hasField(errs, "matcher.threshold") {
		t.Errorf("expected matcher.threshold error, got %v", errs)
	}
}

func TestValidateRule_EntropyBadMinLength(t *testing.T) {
	r := validRule()
	r.Matcher = MatcherSpec{Type: "entropy", Charset: "hex", Threshold: 3.0, MinLength: 0}
	errs := ValidateRule(r)
	if !hasField(errs, "matcher.min_length") {
		t.Errorf("expected matcher.min_length error, got %v", errs)
	}
}

func TestValidateRule_PrefixTooMany(t *testing.T) {
	r := validRule()
	prefixes := make([]string, 51)
	for i := range prefixes {
		prefixes[i] = "p"
	}
	r.Matcher = MatcherSpec{Type: "prefix", Prefixes: prefixes}
	errs := ValidateRule(r)
	if !hasField(errs, "matcher.prefixes") {
		t.Errorf("expected matcher.prefixes error, got %v", errs)
	}
}

func TestValidateRule_PrefixTooLong(t *testing.T) {
	r := validRule()
	r.Matcher = MatcherSpec{Type: "prefix", Prefixes: []string{strings.Repeat("x", 257)}}
	errs := ValidateRule(r)
	if !hasField(errs, "matcher.prefixes[0]") {
		t.Errorf("expected matcher.prefixes[0] error, got %v", errs)
	}
}

func TestValidateRule_UnknownMatcherType(t *testing.T) {
	r := validRule()
	r.Matcher = MatcherSpec{Type: "yara"}
	errs := ValidateRule(r)
	if !hasField(errs, "matcher.type") {
		t.Errorf("expected matcher.type error, got %v", errs)
	}
}

func TestValidateRule_TooManyTests(t *testing.T) {
	r := validRule()
	r.Tests = make([]TestCase, 51)
	errs := ValidateRule(r)
	if !hasField(errs, "tests") {
		t.Errorf("expected tests error, got %v", errs)
	}
}

func TestValidateRule_TestInputTooLong(t *testing.T) {
	r := validRule()
	r.Tests = []TestCase{{Input: strings.Repeat("x", 10001), ShouldMatch: true}}
	errs := ValidateRule(r)
	if !hasField(errs, "tests[0].input") {
		t.Errorf("expected tests[0].input error, got %v", errs)
	}
}

func TestRunTests_AllPass(t *testing.T) {
	r := Rule{
		Matcher: MatcherSpec{Type: "regex", Pattern: `<IMPORTANT>`},
		Tests: []TestCase{
			{Input: "<IMPORTANT>", ShouldMatch: true, Description: "matches tag"},
			{Input: "clean", ShouldMatch: false, Description: "no match"},
		},
	}
	failures := RunTests(r)
	if len(failures) != 0 {
		t.Errorf("expected 0 failures, got %d: %v", len(failures), failures)
	}
}

func TestRunTests_Failure(t *testing.T) {
	r := Rule{
		Matcher: MatcherSpec{Type: "regex", Pattern: `<IMPORTANT>`},
		Tests: []TestCase{
			{Input: "clean text", ShouldMatch: true, Description: "should match but won't"},
		},
	}
	failures := RunTests(r)
	if len(failures) != 1 {
		t.Fatalf("expected 1 failure, got %d", len(failures))
	}
	if failures[0].Expected != true || failures[0].Got != false {
		t.Errorf("failure expected=%v got=%v", failures[0].Expected, failures[0].Got)
	}
}

func TestRunTests_InvalidMatcher(t *testing.T) {
	r := Rule{
		Matcher: MatcherSpec{Type: "regex", Pattern: `[invalid`},
		Tests: []TestCase{
			{Input: "test", ShouldMatch: true},
			{Input: "test2", ShouldMatch: false},
		},
	}
	failures := RunTests(r)
	if len(failures) != 2 {
		t.Errorf("expected 2 failures for invalid matcher, got %d", len(failures))
	}
}

func TestValidateRule_AllValidTargets(t *testing.T) {
	targets := []string{
		"tool.description", "tool.name", "tool.input_schema", "tool.combined",
		"skill.description", "resource.uri", "instruction.content",
		"credential.name", "credential.value",
		"server.command", "server.args", "server.env_keys", "server.env_values",
		"server.instructions",
	}
	for _, target := range targets {
		r := validRule()
		r.Scope.Targets = []string{target}
		errs := ValidateRule(r)
		if len(errs) > 0 {
			t.Errorf("target %q should be valid, got errors: %v", target, errs)
		}
	}
}

func TestValidateRule_AllValidSeverities(t *testing.T) {
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		r := validRule()
		r.Severity = sev
		errs := ValidateRule(r)
		if len(errs) > 0 {
			t.Errorf("severity %q should be valid, got errors: %v", sev, errs)
		}
	}
}

func TestRunTestsInstructionCanonicalizationParity(t *testing.T) {
	eligible := Rule{
		ID:       "parity-eligible-rule",
		Name:     "Parity eligible rule",
		Version:  1,
		Enabled:  true,
		Severity: "high",
		Scope:    Scope{Collector: "config", Targets: []string{"instruction.content"}},
		Matcher: MatcherSpec{
			Type:            "regex",
			Pattern:         `\bignore\s+previous\s+instructions\b`,
			CaseInsensitive: true,
		},
		Emit: EmitConfig{FindingType: "has_injection_patterns"},
		Tests: []TestCase{
			{Input: "ｉｇｎｏｒｅ\u200b previous instructions", ShouldMatch: true, Description: "nfkc + zero-width"},
			{Input: "i g n o r e  p r e v i o u s  i n s t r u c t i o n s", ShouldMatch: true, Description: "letter spacing"},
			{Input: "1gn0re previous instructions", ShouldMatch: false, Description: "leetspeak excluded"},
			{Input: "\"ignore, previous instructions\"", ShouldMatch: false, Description: "punctuation not stripped"},
		},
	}
	if failures := RunTests(eligible); len(failures) != 0 {
		t.Fatalf("eligible parity failures: %+v", failures)
	}

	// A non-eligible rule (non-config collector) stays raw-only: canonical-only
	// obfuscation must not match, but raw text still does.
	rawOnly := Rule{
		ID:       "parity-raw-only-rule",
		Name:     "Parity raw-only rule",
		Version:  1,
		Enabled:  true,
		Severity: "medium",
		Scope:    Scope{Collector: "mcp", Targets: []string{"tool.description"}},
		Matcher: MatcherSpec{
			Type:            "regex",
			Pattern:         `\bignore\s+previous\s+instructions\b`,
			CaseInsensitive: true,
		},
		Emit: EmitConfig{FindingType: "has_injection_patterns"},
		Tests: []TestCase{
			{Input: "ｉｇｎｏｒｅ\u200b previous instructions", ShouldMatch: false, Description: "no canonical for non-config collector"},
			{Input: "ignore previous instructions", ShouldMatch: true, Description: "raw still matches"},
		},
	}
	if failures := RunTests(rawOnly); len(failures) != 0 {
		t.Fatalf("raw-only parity failures: %+v", failures)
	}
}

func hasField(errs []ValidationError, field string) bool {
	for _, e := range errs {
		if e.Field == field {
			return true
		}
	}
	return false
}
