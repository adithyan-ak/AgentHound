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
	State        OutcomeState        `json:"state"`
	CoverageKeys []string            `json:"coverage_keys,omitempty"`
	Outcomes     []CollectionOutcome `json:"outcomes,omitempty"`
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
		merged.Outcomes = append(merged.Outcomes, report.Outcomes...)
	}
	for key := range coverage {
		merged.CoverageKeys = append(merged.CoverageKeys, key)
	}
	sort.Strings(merged.CoverageKeys)
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

type IdentityScheme struct {
	EntityKind   string `json:"entity_kind"`
	Transport    string `json:"transport,omitempty"`
	Scheme       string `json:"scheme"`
	Version      int    `json:"version"`
	LegacyScheme string `json:"legacy_scheme,omitempty"`
}

type IdentityAliasState string

const (
	IdentityAliasUnresolved IdentityAliasState = "unresolved"
	IdentityAliasOneToOne   IdentityAliasState = "one_to_one"
	IdentityAliasAmbiguous  IdentityAliasState = "ambiguous"
)

// IdentityAlias carries compatibility evidence without mutating legacy IDs.
// An ambiguous legacy ID is a quarantine signal, never an instruction to merge.
type IdentityAlias struct {
	LegacyID   string             `json:"legacy_id"`
	CurrentIDs []string           `json:"current_ids"`
	State      IdentityAliasState `json:"state"`
}

// BuildMCPIdentityAliases summarizes the v2 candidates for each legacy sorted
// stdio ID. Only a complete coverage domain can prove a one-to-one alias;
// multiple candidates are always ambiguous and must be quarantined.
func BuildMCPIdentityAliases(nodes []Node, coverageComplete bool) []IdentityAlias {
	byLegacy := make(map[string]map[string]bool)
	for _, node := range nodes {
		if !nodeHasKind(node, "MCPServer") ||
			node.Properties["id_scheme"] != MCPStdioIdentitySchemeV2 {
			continue
		}
		legacyID, _ := node.Properties["legacy_objectid"].(string)
		if legacyID == "" {
			continue
		}
		if byLegacy[legacyID] == nil {
			byLegacy[legacyID] = make(map[string]bool)
		}
		byLegacy[legacyID][node.ID] = true
	}

	legacyIDs := make([]string, 0, len(byLegacy))
	for legacyID := range byLegacy {
		legacyIDs = append(legacyIDs, legacyID)
	}
	sort.Strings(legacyIDs)

	aliases := make([]IdentityAlias, 0, len(legacyIDs))
	for _, legacyID := range legacyIDs {
		currentIDs := make([]string, 0, len(byLegacy[legacyID]))
		for currentID := range byLegacy[legacyID] {
			currentIDs = append(currentIDs, currentID)
		}
		sort.Strings(currentIDs)
		state := IdentityAliasUnresolved
		switch {
		case len(currentIDs) > 1:
			state = IdentityAliasAmbiguous
		case coverageComplete:
			state = IdentityAliasOneToOne
		}
		aliases = append(aliases, IdentityAlias{
			LegacyID:   legacyID,
			CurrentIDs: currentIDs,
			State:      state,
		})
	}
	return aliases
}

func nodeHasKind(node Node, want string) bool {
	for _, kind := range node.Kinds {
		if kind == want {
			return true
		}
	}
	return false
}
