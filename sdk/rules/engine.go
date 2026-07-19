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
	if cr.rule.ShadowExclude {
		return nil
	}
	shadowSpans := cr.matcher.matchSpans(view.text)
	shadowMatches := make([]evaluatedMatch, 0, len(shadowSpans))
	for ordinal, span := range shadowSpans {
		// A zero-length shadow match has no source bytes to ground it. Canonical
		// deletions can move or create boundaries, so projecting such a match can
		// fabricate a raw offset. Keep the authoritative raw-pass matches only.
		if span.start == span.end {
			continue
		}
		// On a shadow truncated at the canonical cap, a match ending exactly at
		// the cut is untrustworthy: an end-anchored ($) or boundary-sensitive
		// pattern may be firing against a boundary that only exists because the
		// projection was cut off. Suppress those; the raw pass still runs.
		if view.truncated && span.end == len(view.text) {
			continue
		}
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
	if len(shadowMatches) == 0 {
		return rawMatches
	}

	// Match cardinality can be very high while rule cardinality stays tiny, so
	// do not size this map from the number of matches.
	shadowRuleIDs := make(map[string]struct{})
	for _, match := range shadowMatches {
		shadowRuleIDs[match.match.RuleID] = struct{}{}
	}

	merged := append([]evaluatedMatch(nil), rawMatches...)
	// A shadow match is dropped when it exactly duplicates or properly overlaps
	// an already-accepted span of the same rule (raw seeds the accepted set, so
	// raw always wins) — this also covers the case where confusable/whitespace
	// collapse projects the shadow match to a wider raw span than the raw match.
	//
	// Dedup is kept near-linear: exact spans use an O(1) map (the high-volume
	// common case and the only way zero-length matches can conflict), and proper
	// overlap uses a forward pointer over each rule's start-sorted raw ranges plus
	// a running max end of accepted shadow spans. A per-match linear scan here was
	// O(matches^2) and a DoS surface for single-token custom rules on 1 MiB input.
	exact := make(map[matchIdentity]struct{}, len(shadowMatches))
	rawByRule := make(map[string][]matcherSpan, len(shadowRuleIDs))
	for _, match := range rawMatches {
		if _, needed := shadowRuleIDs[match.match.RuleID]; !needed {
			continue
		}
		exact[matchIdentity{match.match.RuleID, match.rawStart, match.rawEnd}] = struct{}{}
		rawByRule[match.match.RuleID] = append(
			rawByRule[match.match.RuleID],
			matcherSpan{start: match.rawStart, end: match.rawEnd},
		)
	}
	for id := range rawByRule {
		spans := rawByRule[id]
		sort.Slice(spans, func(i, j int) bool {
			if spans[i].start != spans[j].start {
				return spans[i].start < spans[j].start
			}
			return spans[i].end < spans[j].end
		})
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

	var (
		curRule      string
		rawSpans     []matcherSpan
		ri           int
		maxShadowEnd int
		started      bool
	)
	for _, match := range shadowMatches {
		id := match.match.RuleID
		if !started || id != curRule {
			curRule, rawSpans, ri, maxShadowEnd, started = id, rawByRule[id], 0, 0, true
		}
		s, e := match.rawStart, match.rawEnd
		identity := matchIdentity{id, s, e}
		if _, dup := exact[identity]; dup {
			continue
		}
		// Proper overlap with a raw span: advance to the first raw range ending
		// after s; it overlaps iff it also starts before e.
		for ri < len(rawSpans) && rawSpans[ri].end <= s {
			ri++
		}
		if ri < len(rawSpans) && rawSpans[ri].start < e {
			continue
		}
		// Proper overlap with an already-accepted shadow span (accepted spans are
		// non-overlapping and start at or before s, so the running max suffices).
		if s < maxShadowEnd {
			continue
		}
		exact[identity] = struct{}{}
		if e > maxShadowEnd {
			maxShadowEnd = e
		}
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
	if view.overflow {
		slog.Debug(
			"canonical instruction shadow declined: provenance ceiling exceeded",
			"collector", collector,
			"target", target,
			"bytes", len(raw),
		)
	}
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
