package rules

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

// ManifestForEngine records the exact text-rule semantics used by a collector.
// Fingerprint rules are added by the CLI when they participate in a scan.
func ManifestForEngine(engine *Engine) *ingest.RulesetManifest {
	if engine == nil {
		return ingest.EmptyRulesetManifest()
	}
	manifest := BuildManifest(engine.Rules(), nil, engine.LoadFailures()...)
	return &manifest
}

// BuildManifest records the effective text and fingerprint semantics. Digests
// identify content; authenticity remains unverified unless a separate trusted
// signature workflow attests the artifact.
func BuildManifest(
	textRules []Rule,
	fingerprintRules []FingerprintRule,
	loadFailures ...string,
) ingest.RulesetManifest {
	manifest := ingest.RulesetManifest{
		LoadState:    ingest.OutcomeComplete,
		Authenticity: "unverified",
		Errors:       append([]string(nil), loadFailures...),
	}

	for _, rule := range textRules {
		effectiveMatcher, err := canonicalTextMatcherJSON(rule.Matcher)
		if err != nil {
			manifest.Errors = append(
				manifest.Errors,
				fmt.Sprintf("text rule %s matcher: %v", rule.ID, err),
			)
			continue
		}
		manifest.Entries = append(manifest.Entries, ingest.RuleManifestEntry{
			Type:             "text",
			ID:               rule.ID,
			Version:          rule.Version,
			SemanticSHA256:   semanticDigest(ruleForDigest(rule)),
			Source:           ruleSourceClass(rule.Source),
			EffectiveMatcher: effectiveMatcher,
		})
	}
	for _, rule := range fingerprintRules {
		if errs := ValidateFingerprint(rule); len(errs) > 0 {
			manifest.Errors = append(manifest.Errors,
				fmt.Sprintf("fingerprint rule %s: %v", rule.ID, errs))
			continue
		}
		effectiveMatcher, err := canonicalFingerprintMatcherJSON(rule.Probes)
		if err != nil {
			manifest.Errors = append(
				manifest.Errors,
				fmt.Sprintf("fingerprint rule %s matcher: %v", rule.ID, err),
			)
			continue
		}
		manifest.Entries = append(manifest.Entries, ingest.RuleManifestEntry{
			Type:             "fingerprint",
			ID:               rule.ID,
			Version:          rule.Version,
			SemanticSHA256:   semanticDigest(fingerprintRuleForDigest(rule)),
			Source:           ruleSourceClass(rule.Source),
			EffectiveMatcher: effectiveMatcher,
		})
	}

	sort.Slice(manifest.Entries, func(i, j int) bool {
		if manifest.Entries[i].Type != manifest.Entries[j].Type {
			return manifest.Entries[i].Type < manifest.Entries[j].Type
		}
		if manifest.Entries[i].ID != manifest.Entries[j].ID {
			return manifest.Entries[i].ID < manifest.Entries[j].ID
		}
		return manifest.Entries[i].Version < manifest.Entries[j].Version
	})
	manifest.Errors = sortedUniqueStrings(manifest.Errors)
	if len(manifest.Errors) > 0 {
		if len(manifest.Entries) == 0 {
			manifest.LoadState = ingest.OutcomeFailed
		} else {
			manifest.LoadState = ingest.OutcomePartial
		}
	}
	manifest.Digest = semanticDigest(manifest.Entries)
	return manifest
}

type canonicalTextMatcher struct {
	Type            string                 `json:"type"`
	Pattern         string                 `json:"pattern,omitempty"`
	Keywords        []string               `json:"keywords,omitempty"`
	Prefixes        []string               `json:"prefixes,omitempty"`
	CaseInsensitive bool                   `json:"case_insensitive,omitempty"`
	WordBoundary    bool                   `json:"word_boundary,omitempty"`
	MatchMode       string                 `json:"match_mode,omitempty"`
	Operator        string                 `json:"operator,omitempty"`
	Matchers        []canonicalTextMatcher `json:"matchers,omitempty"`
	Charset         string                 `json:"charset,omitempty"`
	Threshold       float64                `json:"threshold,omitempty"`
	MinLength       int                    `json:"min_length,omitempty"`
}

type canonicalFingerprintMatcher struct {
	Probes []canonicalFingerprintProbe `json:"probes"`
}

type canonicalFingerprintProbe struct {
	Method   string                      `json:"method"`
	Path     string                      `json:"path"`
	Matchers []canonicalFingerprintMatch `json:"matchers"`
}

type canonicalFingerprintMatch struct {
	Type            string `json:"type"`
	StatusCode      int    `json:"status_code,omitempty"`
	StatusRange     string `json:"status_range,omitempty"`
	Name            string `json:"name,omitempty"`
	Value           string `json:"value,omitempty"`
	Pattern         string `json:"pattern,omitempty"`
	Path            string `json:"path,omitempty"`
	Equals          string `json:"equals,omitempty"`
	Regex           string `json:"regex,omitempty"`
	Exists          *bool  `json:"exists,omitempty"`
	CaseInsensitive bool   `json:"case_insensitive,omitempty"`
}

func canonicalTextMatcherJSON(matcher MatcherSpec) (json.RawMessage, error) {
	return json.Marshal(canonicalizeTextMatcher(matcher))
}

func canonicalizeTextMatcher(matcher MatcherSpec) canonicalTextMatcher {
	canonical := canonicalTextMatcher{
		Type:            matcher.Type,
		Pattern:         matcher.Pattern,
		Keywords:        append([]string(nil), matcher.Keywords...),
		Prefixes:        append([]string(nil), matcher.Prefixes...),
		CaseInsensitive: matcher.CaseInsensitive,
		WordBoundary:    matcher.WordBoundary,
		MatchMode:       matcher.MatchMode,
		Operator:        matcher.Operator,
		Charset:         matcher.Charset,
		Threshold:       matcher.Threshold,
		MinLength:       matcher.MinLength,
	}
	for _, child := range matcher.Matchers {
		canonical.Matchers = append(
			canonical.Matchers,
			canonicalizeTextMatcher(child),
		)
	}
	return canonical
}

func canonicalFingerprintMatcherJSON(
	probes []FingerprintProbe,
) (json.RawMessage, error) {
	canonical := canonicalFingerprintMatcher{
		Probes: make([]canonicalFingerprintProbe, 0, len(probes)),
	}
	for _, probe := range probes {
		canonicalProbe := canonicalFingerprintProbe{
			Method:   probe.Method,
			Path:     probe.Path,
			Matchers: make([]canonicalFingerprintMatch, 0, len(probe.Matchers)),
		}
		for _, matcher := range probe.Matchers {
			canonicalProbe.Matchers = append(
				canonicalProbe.Matchers,
				canonicalFingerprintMatch(matcher),
			)
		}
		canonical.Probes = append(canonical.Probes, canonicalProbe)
	}
	return json.Marshal(canonical)
}

func sortedUniqueStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func semanticDigest(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		// All manifest inputs are JSON-compatible SDK structs. Keep this
		// deterministic if a future field violates that contract.
		data = []byte(fmt.Sprintf("unmarshalable:%T", v))
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", sum)
}

// instructionRuleDigest wraps a rule that participates in config instruction
// canonicalization together with the semantic canonicalizer version, so the
// eligible rule's semantic digest changes if and only if the frozen transform
// contract or its Unicode edition changes. It is a digest-payload shape only
// and is never serialized into the manifest JSON.
type instructionRuleDigest struct {
	Rule                 Rule   `json:"rule"`
	CanonicalizerVersion string `json:"canonicalizer_version"`
}

func ruleForDigest(rule Rule) any {
	rule.Source = ""
	rule.Tests = nil
	if !ruleUsesInstructionCanonicalization(rule) {
		return rule
	}
	return instructionRuleDigest{
		Rule:                 rule,
		CanonicalizerVersion: instructionCanonicalizationVersion,
	}
}

func fingerprintRuleForDigest(rule FingerprintRule) FingerprintRule {
	rule.Source = ""
	return rule
}

func ruleSourceClass(source string) string {
	override := getBundleOverridePath()
	switch {
	case source == "", source == BundleSourceBuiltin:
		return BundleSourceBuiltin
	case strings.HasPrefix(source, "bundle:"),
		override != "" && (source == override || strings.HasPrefix(source, strings.TrimRight(override, "/")+"/")):
		return "bundle"
	default:
		return "custom"
	}
}
