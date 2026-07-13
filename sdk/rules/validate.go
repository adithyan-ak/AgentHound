package rules

import (
	"fmt"
	"regexp"
)

type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

var validSeverities = map[string]bool{
	"critical": true, "high": true, "medium": true, "low": true, "info": true,
}

var validCollectors = map[string]bool{
	"mcp": true, "a2a": true, "config": true, "all": true,
}

var validMatcherTypes = map[string]bool{
	"regex": true, "keyword": true, "compound": true, "entropy": true, "prefix": true,
}

var validTargets = map[string]bool{
	"tool.description":    true,
	"tool.name":           true,
	"tool.input_schema":   true,
	"tool.combined":       true,
	"skill.description":   true,
	"resource.uri":        true,
	"instruction.content": true,
	"credential.name":     true,
	"credential.value":    true,
	"server.command":      true,
	"server.args":         true,
	"server.env_keys":     true,
	"server.env_values":   true,
	"server.instructions": true,
}

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$`)

func ValidateRule(r Rule) []ValidationError {
	var errs []ValidationError

	if !idPattern.MatchString(r.ID) {
		errs = append(errs, ValidationError{Field: "id", Message: "must be 3-64 chars, kebab-case, alphanumeric start/end"})
	}
	if r.Name == "" {
		errs = append(errs, ValidationError{Field: "name", Message: "must not be empty"})
	}
	if !validSeverities[r.Severity] {
		errs = append(errs, ValidationError{Field: "severity", Message: fmt.Sprintf("must be critical/high/medium/low/info, got %q", r.Severity)})
	}
	if !validCollectors[r.Scope.Collector] {
		errs = append(errs, ValidationError{Field: "scope.collector", Message: fmt.Sprintf("must be mcp/a2a/config/all, got %q", r.Scope.Collector)})
	}
	if len(r.Scope.Targets) == 0 {
		errs = append(errs, ValidationError{Field: "scope.targets", Message: "must not be empty"})
	}
	for i, t := range r.Scope.Targets {
		if !validTargets[t] {
			errs = append(errs, ValidationError{Field: fmt.Sprintf("scope.targets[%d]", i), Message: fmt.Sprintf("unknown target %q", t)})
		}
	}

	errs = append(errs, validateMatcher("matcher", r.Matcher, false)...)

	if len(r.Tests) > 50 {
		errs = append(errs, ValidationError{Field: "tests", Message: fmt.Sprintf("max 50 test cases, got %d", len(r.Tests))})
	}
	for i, tc := range r.Tests {
		if len(tc.Input) > 10000 {
			errs = append(errs, ValidationError{Field: fmt.Sprintf("tests[%d].input", i), Message: "max 10000 chars"})
		}
	}

	return errs
}

func validateMatcher(prefix string, m MatcherSpec, nested bool) []ValidationError {
	var errs []ValidationError

	if !validMatcherTypes[m.Type] {
		errs = append(errs, ValidationError{Field: prefix + ".type", Message: fmt.Sprintf("must be regex/keyword/compound/entropy/prefix, got %q", m.Type)})
		return errs
	}

	switch m.Type {
	case "regex":
		if len(m.Pattern) > 1024 {
			errs = append(errs, ValidationError{Field: prefix + ".pattern", Message: "max 1024 chars"})
		}
		if m.Pattern != "" {
			p := m.Pattern
			if m.CaseInsensitive {
				p = "(?i)" + p
			}
			if _, err := regexp.Compile(p); err != nil {
				errs = append(errs, ValidationError{Field: prefix + ".pattern", Message: fmt.Sprintf("invalid regex: %v", err)})
			}
		}

	case "keyword":
		if len(m.Keywords) > 100 {
			errs = append(errs, ValidationError{Field: prefix + ".keywords", Message: fmt.Sprintf("max 100 keywords, got %d", len(m.Keywords))})
		}
		for i, kw := range m.Keywords {
			if len(kw) > 256 {
				errs = append(errs, ValidationError{Field: fmt.Sprintf("%s.keywords[%d]", prefix, i), Message: "max 256 chars"})
			}
		}

	case "compound":
		if nested {
			errs = append(errs, ValidationError{Field: prefix + ".type", Message: "compound matchers cannot be nested"})
			return errs
		}
		if m.Operator != "and" && m.Operator != "or" {
			errs = append(errs, ValidationError{Field: prefix + ".operator", Message: fmt.Sprintf("must be and/or, got %q", m.Operator)})
		}
		if len(m.Matchers) > 10 {
			errs = append(errs, ValidationError{Field: prefix + ".matchers", Message: fmt.Sprintf("max 10 children, got %d", len(m.Matchers))})
		}
		for i, child := range m.Matchers {
			errs = append(errs, validateMatcher(fmt.Sprintf("%s.matchers[%d]", prefix, i), child, true)...)
		}

	case "entropy":
		if m.Charset != "base64" && m.Charset != "hex" {
			errs = append(errs, ValidationError{Field: prefix + ".charset", Message: fmt.Sprintf("must be base64/hex, got %q", m.Charset)})
		}
		if m.Threshold < 0 || m.Threshold > 8.0 {
			errs = append(errs, ValidationError{Field: prefix + ".threshold", Message: fmt.Sprintf("must be 0.0-8.0, got %f", m.Threshold)})
		}
		if m.MinLength < 1 {
			errs = append(errs, ValidationError{Field: prefix + ".min_length", Message: fmt.Sprintf("must be >= 1, got %d", m.MinLength)})
		}

	case "prefix":
		if len(m.Prefixes) > 50 {
			errs = append(errs, ValidationError{Field: prefix + ".prefixes", Message: fmt.Sprintf("max 50 prefixes, got %d", len(m.Prefixes))})
		}
		for i, p := range m.Prefixes {
			if len(p) > 256 {
				errs = append(errs, ValidationError{Field: fmt.Sprintf("%s.prefixes[%d]", prefix, i), Message: "max 256 chars"})
			}
		}
	}

	return errs
}

// runTestCase mirrors the engine's dual-view evaluation for a single rule so
// custom-rule authoring (RunTests) matches runtime behavior exactly: it shares
// truncateRuleInput, evaluateRuleRaw, and evaluateRuleShadow. Canonical shadow
// evaluation applies only to rules eligible for config instruction
// canonicalization and only on a changed canonical view.
func runTestCase(
	rule Rule,
	matcher spanMatcher,
	input string,
) bool {
	raw := truncateRuleInput(input)
	cr := compiledRule{rule: rule, matcher: matcher}
	rawMatches := evaluateRuleRaw(cr, raw)
	if len(rawMatches) > 0 {
		return true
	}
	if ruleUsesInstructionCanonicalization(rule) {
		view := canonicalizeInstruction(raw)
		if view.changed {
			return len(evaluateRuleShadow(cr, raw, view)) > 0
		}
	}
	return false
}

type TestFailure struct {
	TestIndex   int
	Description string
	Expected    bool
	Got         bool
	Input       string
}

func RunTests(r Rule) []TestFailure {
	m, err := compileMatcher(r.Matcher)
	if err != nil {
		var failures []TestFailure
		for i, tc := range r.Tests {
			failures = append(failures, TestFailure{
				TestIndex:   i,
				Description: tc.Description,
				Expected:    tc.ShouldMatch,
				Got:         false,
				Input:       tc.Input,
			})
		}
		return failures
	}

	var failures []TestFailure
	for i, tc := range r.Tests {
		got := runTestCase(r, m, tc.Input)
		if got != tc.ShouldMatch {
			failures = append(failures, TestFailure{
				TestIndex:   i,
				Description: tc.Description,
				Expected:    tc.ShouldMatch,
				Got:         got,
				Input:       tc.Input,
			})
		}
	}
	return failures
}
