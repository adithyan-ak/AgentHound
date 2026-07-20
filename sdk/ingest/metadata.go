package ingest

import (
	"encoding/json"
	"sort"
)

type OutcomeState string

const (
	OutcomeUnknown       OutcomeState = "unknown"
	OutcomeNotApplicable OutcomeState = "not_applicable"
	OutcomeComplete      OutcomeState = "complete"
	OutcomePartial       OutcomeState = "partial"
	OutcomeFailed        OutcomeState = "failed"
	OutcomeTruncated     OutcomeState = "truncated"
)

// CollectionReport distinguishes a successful empty observation from an
// unattempted, failed, partial, or truncated collection.
type CollectionReport struct {
	State              OutcomeState        `json:"state"`
	CoverageKeys       []string            `json:"coverage_keys,omitempty"`
	AuthoritativeRoots []CoverageRoot      `json:"authoritative_roots,omitempty"`
	Outcomes           []CollectionOutcome `json:"outcomes,omitempty"`
}

// CoverageRoot declares the complete active child set observed by one
// exhaustive collector-root run. Targeted and otherwise non-exhaustive runs
// must not emit this declaration.
type CoverageRoot struct {
	CoverageKey       string   `json:"coverage_key"`
	ChildCoverageKeys []string `json:"child_coverage_keys"`
}

type CollectionOutcome struct {
	Collector   string       `json:"collector"`
	CoverageKey string       `json:"coverage_key,omitempty"`
	Target      string       `json:"target,omitempty"`
	Method      string       `json:"method,omitempty"`
	State       OutcomeState `json:"state"`
	Items       int          `json:"items,omitempty"`
	Error       string       `json:"error,omitempty"`
}

func AggregateOutcomeState(outcomes []CollectionOutcome) OutcomeState {
	if len(outcomes) == 0 {
		return OutcomeUnknown
	}
	var complete, failed, partial, truncated, applicable int
	for _, outcome := range outcomes {
		switch outcome.State {
		case OutcomeComplete:
			complete++
			applicable++
		case OutcomeFailed:
			failed++
			applicable++
		case OutcomePartial:
			partial++
			applicable++
		case OutcomeTruncated:
			truncated++
			applicable++
		case OutcomeNotApplicable:
			// An unsupported/unadvertised optional method does not make the
			// enclosing collection incomplete.
		default:
			applicable++
		}
	}
	if applicable == 0 {
		return OutcomeComplete
	}
	if failed == applicable {
		return OutcomeFailed
	}
	if failed > 0 || partial > 0 {
		return OutcomePartial
	}
	if truncated > 0 {
		return OutcomeTruncated
	}
	if complete == applicable {
		return OutcomeComplete
	}
	return OutcomeUnknown
}

func MergeCollectionReports(reports ...*CollectionReport) *CollectionReport {
	merged := &CollectionReport{}
	coverage := make(map[string]bool)
	roots := make(map[string]CoverageRoot)
	var reportStates []CollectionOutcome
	for _, report := range reports {
		if report == nil {
			continue
		}
		state := report.State
		if state == "" {
			state = AggregateOutcomeState(report.Outcomes)
		}
		reportStates = append(reportStates, CollectionOutcome{State: state})
		for _, key := range report.CoverageKeys {
			if key != "" {
				coverage[key] = true
			}
		}
		for _, root := range report.AuthoritativeRoots {
			children := append([]string(nil), root.ChildCoverageKeys...)
			sort.Strings(children)
			roots[root.CoverageKey] = CoverageRoot{
				CoverageKey:       root.CoverageKey,
				ChildCoverageKeys: children,
			}
		}
		merged.Outcomes = append(merged.Outcomes, report.Outcomes...)
	}
	for key := range coverage {
		merged.CoverageKeys = append(merged.CoverageKeys, key)
	}
	sort.Strings(merged.CoverageKeys)
	for _, root := range roots {
		merged.AuthoritativeRoots = append(merged.AuthoritativeRoots, root)
	}
	sort.Slice(merged.AuthoritativeRoots, func(i, j int) bool {
		return merged.AuthoritativeRoots[i].CoverageKey <
			merged.AuthoritativeRoots[j].CoverageKey
	})
	// A report's state is authoritative even when it has no constituent
	// outcomes. This preserves complete-empty coverage instead of turning it
	// back into unknown while still keeping the original outcomes unchanged.
	merged.State = AggregateOutcomeState(reportStates)
	return merged
}

type RuleManifestEntry struct {
	Type             string          `json:"type"`
	ID               string          `json:"id"`
	Version          int             `json:"version"`
	SemanticSHA256   string          `json:"semantic_sha256"`
	Source           string          `json:"source"`
	EffectiveMatcher json.RawMessage `json:"effective_matcher,omitempty"`
}

// RulesetManifest identifies the effective runtime semantics. Authenticity is
// descriptive only; a digest is not a signature.
type RulesetManifest struct {
	Digest       string              `json:"digest,omitempty"`
	Entries      []RuleManifestEntry `json:"entries,omitempty"`
	LoadState    OutcomeState        `json:"load_state"`
	Errors       []string            `json:"errors,omitempty"`
	Authenticity string              `json:"authenticity"`
}

// EmptyRulesetManifest explicitly records that a producer evaluated no
// runtime rules. It is complete metadata, not an omitted/unknown ruleset.
func EmptyRulesetManifest() *RulesetManifest {
	return &RulesetManifest{
		Digest:       "sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e64a8f8bff093b2f5f2cf4e",
		Entries:      []RuleManifestEntry{},
		LoadState:    OutcomeComplete,
		Errors:       []string{},
		Authenticity: "unverified",
	}
}

type IdentityScheme struct {
	EntityKind string `json:"entity_kind"`
	Transport  string `json:"transport,omitempty"`
	Scheme     string `json:"scheme"`
	Version    int    `json:"version"`
}

// CurrentIdentitySchemes returns the identity contract understood by every
// current collector envelope.
func CurrentIdentitySchemes() []IdentityScheme {
	return []IdentityScheme{{
		EntityKind: "MCPServer",
		Transport:  "stdio",
		Scheme:     MCPStdioIdentitySchemeV3,
		Version:    3,
	}}
}
