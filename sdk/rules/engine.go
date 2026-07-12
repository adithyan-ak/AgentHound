package rules

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"time"
)

const (
	evaluateTimeout = 5 * time.Second
	maxInputBytes   = 1 << 20 // 1 MiB
)

type Engine struct {
	rules        []compiledRule
	byScope      map[string][]compiledRule
	disabled     map[string]bool
	loadFailures []string
}

type compiledRule struct {
	rule    Rule
	matcher CompiledMatcher
}

type LoadOptions struct {
	CustomDir  string
	DisableIDs []string
	EnableOnly []string
}

func NewEngine(opts LoadOptions) (*Engine, error) {
	builtins, loadFailures, err := loadBuiltinRulesWithFailures()
	if err != nil {
		return nil, err
	}

	ruleMap := make(map[string]Rule, len(builtins))
	for _, r := range builtins {
		ruleMap[r.ID] = r
	}

	if opts.CustomDir != "" {
		custom, customFailures, err := loadCustomRulesWithFailures(opts.CustomDir)
		if err != nil {
			return nil, err
		}
		loadFailures = append(loadFailures, customFailures...)
		for _, r := range custom {
			ruleMap[r.ID] = r
		}
	}

	disabled := make(map[string]bool)
	for _, id := range opts.DisableIDs {
		disabled[id] = true
	}

	enableOnly := make(map[string]bool)
	for _, id := range opts.EnableOnly {
		enableOnly[id] = true
	}

	var compiled []compiledRule
	byScope := make(map[string][]compiledRule)

	for _, r := range ruleMap {
		if !r.Enabled {
			continue
		}
		if disabled[r.ID] {
			continue
		}
		if len(enableOnly) > 0 && !enableOnly[r.ID] {
			continue
		}

		if errs := ValidateRule(r); len(errs) > 0 {
			slog.Warn("skipping invalid rule", "id", r.ID, "errors", errs)
			loadFailures = append(
				loadFailures,
				fmt.Sprintf("validate text rule %s: %v", r.ID, errs),
			)
			continue
		}

		m, err := compileMatcher(r.Matcher)
		if err != nil {
			slog.Warn("skipping rule with compile error", "id", r.ID, "error", err)
			loadFailures = append(
				loadFailures,
				fmt.Sprintf("compile text rule %s: %v", r.ID, err),
			)
			continue
		}

		cr := compiledRule{rule: r, matcher: m}
		compiled = append(compiled, cr)

		for _, target := range r.Scope.Targets {
			key := r.Scope.Collector + ":" + target
			byScope[key] = append(byScope[key], cr)
		}
	}
	loadFailures = sortedUniqueStrings(loadFailures)
	for _, failure := range loadFailures {
		slog.Warn("rule load failure", "error", failure)
	}

	return &Engine{
		rules:        compiled,
		byScope:      byScope,
		disabled:     disabled,
		loadFailures: loadFailures,
	}, nil
}

func (e *Engine) Rules() []Rule {
	out := make([]Rule, len(e.rules))
	for i, cr := range e.rules {
		out[i] = cr.rule
	}
	return out
}

func (e *Engine) RuleCount() int {
	return len(e.rules)
}

func (e *Engine) LoadFailures() []string {
	if e == nil {
		return nil
	}
	failures := append([]string(nil), e.loadFailures...)
	sort.Strings(failures)
	return failures
}

func (e *Engine) Evaluate(collector, target, text string) []Match {
	if len(text) > maxInputBytes {
		text = text[:maxInputBytes]
	}

	var candidates []compiledRule
	seen := make(map[string]bool)

	for _, key := range []string{collector + ":" + target, "all:" + target} {
		for _, cr := range e.byScope[key] {
			if !seen[cr.rule.ID] {
				candidates = append(candidates, cr)
				seen[cr.rule.ID] = true
			}
		}
	}

	var matches []Match
	for _, cr := range candidates {
		results := cr.matcher.Match(text)
		for _, r := range results {
			if !r.Matched {
				continue
			}
			matchText := r.Text
			if len(matchText) > 100 {
				matchText = matchText[:100]
			}
			matches = append(matches, Match{
				RuleID:   cr.rule.ID,
				RuleName: cr.rule.Name,
				Severity: cr.rule.Severity,
				Labels:   cr.rule.Emit.Labels,
				Offset:   r.Offset,
				Text:     matchText,
				Emit:     cr.rule.Emit,
			})
		}
	}
	return matches
}

func (e *Engine) EvaluateAll(collector string, fields map[string]string) []Match {
	ctx, cancel := context.WithTimeout(context.Background(), evaluateTimeout)
	defer cancel()

	var matches []Match
	for target, text := range fields {
		select {
		case <-ctx.Done():
			slog.Warn("EvaluateAll timed out", "collector", collector)
			return matches
		default:
		}
		matches = append(matches, e.Evaluate(collector, target, text)...)
	}
	return matches
}
