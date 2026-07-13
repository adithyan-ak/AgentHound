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
	matcher spanMatcher
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

// evaluatedMatch is a public Match plus the full (uncapped) raw span identity
// and matcher ordinal used for dedup and deterministic shadow ordering.
type evaluatedMatch struct {
	match    Match
	rawStart int
	rawEnd   int
	ordinal  int
}

// matchIdentity is the full-span identity used to deduplicate shadow matches
// against raw matches. It is computed from the full raw start/end (before the
// evidence cap), so the 100-byte evidence truncation never affects dedup.
type matchIdentity struct {
	ruleID   string
	rawStart int
	rawEnd   int
}

// resolveCandidates returns the scope-resolved candidate rules for a request in
// the exact existing two-key lookup/dedup order (collector then all).
func (e *Engine) resolveCandidates(
	collector string,
	target string,
) []compiledRule {
	var candidates []compiledRule
	seen := make(map[string]bool)
	for _, key := range []string{
		collector + ":" + target,
		"all:" + target,
	} {
		for _, cr := range e.byScope[key] {
			if seen[cr.rule.ID] {
				continue
			}
			seen[cr.rule.ID] = true
			candidates = append(candidates, cr)
		}
	}
	return candidates
}

// evaluatedRuleMatch builds one evaluatedMatch, recording the full raw span for
// dedup and capping only the public evidence text at maxEvidenceBytes.
func evaluatedRuleMatch(
	rule Rule,
	raw string,
	rawStart int,
	rawEnd int,
	ordinal int,
) evaluatedMatch {
	evidenceEnd := rawEnd
	if evidenceEnd-rawStart > maxEvidenceBytes {
		evidenceEnd = rawStart + maxEvidenceBytes
	}
	return evaluatedMatch{
		match: Match{
			RuleID:   rule.ID,
			RuleName: rule.Name,
			Severity: rule.Severity,
			Labels:   rule.Emit.Labels,
			Offset:   rawStart,
			Text:     raw[rawStart:evidenceEnd],
			Emit:     rule.Emit,
		},
		rawStart: rawStart,
		rawEnd:   rawEnd,
		ordinal:  ordinal,
	}
}

// evaluateRuleRaw evaluates one rule against the raw view, preserving the exact
// matcher selection/order and recording full raw spans before the evidence cap.
func evaluateRuleRaw(
	cr compiledRule,
	raw string,
) []evaluatedMatch {
	rawSpans := cr.matcher.matchSpans(raw)
	rawMatches := make([]evaluatedMatch, 0, len(rawSpans))
	for ordinal, span := range rawSpans {
		rawMatches = append(rawMatches, evaluatedRuleMatch(
			cr.rule,
			raw,
			span.start,
			span.end,
			ordinal,
		))
	}
	return rawMatches
}

// evaluateRuleShadow evaluates one eligible rule against the canonical view,
// projecting each full canonical span back to raw and building raw evidence. It
// is called only for a changed view after every candidate's raw pass completed.
func evaluateRuleShadow(
	cr compiledRule,
	raw string,
	view canonicalView,
) []evaluatedMatch {
	if cr.rule.Emit.FindingType != "has_injection_patterns" {
		return nil
	}
	shadowSpans := cr.matcher.matchSpans(view.text)
	shadowMatches := make([]evaluatedMatch, 0, len(shadowSpans))
	for ordinal, span := range shadowSpans {
		rawStart, rawEnd, ok := view.projectRange(
			span.start,
			span.end,
		)
		if !ok {
			continue
		}
		shadowMatches = append(shadowMatches, evaluatedRuleMatch(
			cr.rule,
			raw,
			rawStart,
			rawEnd,
			ordinal,
		))
	}
	return shadowMatches
}

// mergeInstructionMatches returns the raw matches unchanged and in exact order,
// then appends only shadow matches whose full-span identity is not already
// present. Shadow matches are stable-sorted by rule ID, full raw start/end, and
// matcher ordinal before appending; raw always wins a dedup contest.
func mergeInstructionMatches(
	rawMatches []evaluatedMatch,
	shadowMatches []evaluatedMatch,
) []evaluatedMatch {
	merged := append([]evaluatedMatch(nil), rawMatches...)
	seen := make(map[matchIdentity]struct{}, len(rawMatches))
	for _, match := range rawMatches {
		seen[matchIdentity{
			ruleID:   match.match.RuleID,
			rawStart: match.rawStart,
			rawEnd:   match.rawEnd,
		}] = struct{}{}
	}
	sort.SliceStable(shadowMatches, func(i, j int) bool {
		left := shadowMatches[i]
		right := shadowMatches[j]
		if left.match.RuleID != right.match.RuleID {
			return left.match.RuleID < right.match.RuleID
		}
		if left.rawStart != right.rawStart {
			return left.rawStart < right.rawStart
		}
		if left.rawEnd != right.rawEnd {
			return left.rawEnd < right.rawEnd
		}
		return left.ordinal < right.ordinal
	})
	for _, match := range shadowMatches {
		identity := matchIdentity{
			ruleID:   match.match.RuleID,
			rawStart: match.rawStart,
			rawEnd:   match.rawEnd,
		}
		if _, exists := seen[identity]; exists {
			continue
		}
		seen[identity] = struct{}{}
		merged = append(merged, match)
	}
	return merged
}

// publicMatches projects evaluated matches to the public Match slice, preserving
// the nil no-match behavior of the original engine.
func publicMatches(matches []evaluatedMatch) []Match {
	if len(matches) == 0 {
		return nil
	}
	out := make([]Match, len(matches))
	for i := range matches {
		out[i] = matches[i].match
	}
	return out
}

func (e *Engine) Evaluate(collector, target, text string) []Match {
	raw := truncateRuleInput(text)
	candidates := e.resolveCandidates(collector, target)

	var rawMatches []evaluatedMatch
	for _, cr := range candidates {
		rawMatches = append(
			rawMatches,
			evaluateRuleRaw(cr, raw)...,
		)
	}
	if !isInstructionCanonicalRequest(collector, target) ||
		!hasInstructionCanonicalCandidate(candidates) {
		return publicMatches(rawMatches)
	}

	view := canonicalizeInstruction(raw)
	if !view.changed {
		return publicMatches(rawMatches)
	}

	var shadowMatches []evaluatedMatch
	for _, cr := range candidates {
		shadowMatches = append(
			shadowMatches,
			evaluateRuleShadow(cr, raw, view)...,
		)
	}
	return publicMatches(
		mergeInstructionMatches(rawMatches, shadowMatches),
	)
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
