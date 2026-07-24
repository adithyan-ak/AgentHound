package ingest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
	"github.com/adithyan-ak/agenthound/server/model"
)

func coverageKeys(report *sdkingest.CollectionReport) []string {
	if report == nil {
		return []string{}
	}
	seen := make(map[string]bool, len(report.CoverageKeys))
	keys := make([]string, 0, len(report.CoverageKeys))
	for _, key := range report.CoverageKeys {
		key = strings.TrimSpace(key)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func collectionState(report *sdkingest.CollectionReport) sdkingest.OutcomeState {
	if report == nil {
		return sdkingest.OutcomeUnknown
	}
	return report.State
}

func incompleteCoverageDomains(report *sdkingest.CollectionReport) []string {
	advisory := make(map[string]bool)
	for _, key := range sdkingest.AdvisoryCoverageDomains(report) {
		advisory[key] = true
	}
	states := sdkingest.CoverageStates(report)
	domains := make([]string, 0, len(states))
	for domain, state := range states {
		if state != sdkingest.OutcomeComplete && !advisory[domain] {
			domains = append(domains, domain)
		}
	}
	sort.Strings(domains)
	return domains
}

func mergeCoverage(groups ...[]string) []string {
	seen := make(map[string]bool)
	var merged []string
	for _, group := range groups {
		for _, key := range group {
			key = strings.TrimSpace(key)
			if key == "" || seen[key] {
				continue
			}
			seen[key] = true
			merged = append(merged, key)
		}
	}
	sort.Strings(merged)
	return merged
}

func subtractCoverage(keys []string, replaced ...[]string) []string {
	remove := make(map[string]bool)
	for _, group := range replaced {
		for _, key := range group {
			if key = strings.TrimSpace(key); key != "" {
				remove[key] = true
			}
		}
	}
	var remaining []string
	for _, key := range mergeCoverage(keys) {
		if !remove[key] {
			remaining = append(remaining, key)
		}
	}
	return remaining
}

// prepareObservationDomains verifies the strict-v3 ownership contract after
// validation. It never infers ownership from report-level coverage.
func prepareObservationDomains(data *sdkingest.IngestData) bool {
	keys := coverageKeys(data.Meta.Collection)
	allowed := make(map[string]bool, len(keys))
	for _, key := range keys {
		allowed[key] = true
	}
	for _, node := range data.Graph.Nodes {
		if len(node.ObservationDomains) == 0 {
			return false
		}
		for _, domain := range node.ObservationDomains {
			if !allowed[domain] {
				return false
			}
		}
	}
	for _, edge := range data.Graph.Edges {
		if len(edge.ObservationDomains) == 0 {
			return false
		}
		for _, domain := range edge.ObservationDomains {
			if !allowed[domain] {
				return false
			}
		}
	}
	return len(keys) > 0
}

func parseArtifactObservedAt(value string) (*time.Time, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil, fmt.Errorf("artifact timestamp is not RFC3339: %w", err)
	}
	parsed = parsed.UTC()
	return &parsed, nil
}

func modelGraphSnapshot(stats *graph.GraphStats) *model.GraphSnapshot {
	if stats == nil {
		return nil
	}
	return &model.GraphSnapshot{
		NodeCounts: cloneInt64Map(stats.NodeCounts),
		EdgeCounts: cloneInt64Map(stats.EdgeCounts),
		TotalNodes: stats.TotalNodes,
		TotalEdges: stats.TotalEdges,
	}
}

func modelObservationCompleteness(
	completeness graph.ObservationCompleteness,
) model.PostureObservationCompleteness {
	return model.PostureObservationCompleteness{
		IncompletePropertyNodes:         completeness.IncompletePropertyNodes,
		IncompletePropertyRelationships: completeness.IncompletePropertyRelationships,
		TokenlessNodes:                  completeness.TokenlessNodes,
		TokenlessIncidentRelationships:  completeness.TokenlessIncidentRelationships,
	}
}

func sdkGraphTotals(snapshot *model.GraphSnapshot) *sdkingest.GraphTotals {
	if snapshot == nil {
		return nil
	}
	return &sdkingest.GraphTotals{
		NodeCounts: cloneInt64Map(snapshot.NodeCounts),
		EdgeCounts: cloneInt64Map(snapshot.EdgeCounts),
		TotalNodes: snapshot.TotalNodes,
		TotalEdges: snapshot.TotalEdges,
	}
}

func cloneInt64Map(values map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func comparisonKey(data *sdkingest.IngestData, attributionComplete bool) string {
	if !attributionComplete ||
		!sdkingest.CollectionCoverageComplete(data.Meta.Collection) ||
		data.Meta.Ruleset == nil ||
		data.Meta.Ruleset.LoadState != sdkingest.OutcomeComplete ||
		data.Meta.Ruleset.Digest == "" ||
		len(data.Meta.IdentitySchemes) == 0 {
		return ""
	}
	identity := append([]sdkingest.IdentityScheme(nil), data.Meta.IdentitySchemes...)
	sort.Slice(identity, func(i, j int) bool {
		left := identity[i].EntityKind + "\x00" + identity[i].Transport + "\x00" + identity[i].Scheme
		right := identity[j].EntityKind + "\x00" + identity[j].Transport + "\x00" + identity[j].Scheme
		if left == right {
			return identity[i].Version < identity[j].Version
		}
		return left < right
	})
	payload := struct {
		Coverage []string                   `json:"coverage"`
		Rules    string                     `json:"rules"`
		Identity []sdkingest.IdentityScheme `json:"identity"`
	}{
		Coverage: coverageKeys(data.Meta.Collection),
		Rules:    data.Meta.Ruleset.Digest,
		Identity: identity,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func appendStage(
	result *sdkingest.IngestResult,
	name string,
	state sdkingest.OutcomeState,
	required bool,
	started time.Time,
	err error,
) {
	stage := sdkingest.StageResult{
		Name:     name,
		State:    state,
		Required: required,
		Duration: time.Since(started),
	}
	if err != nil {
		stage.Error = err.Error()
	}
	result.Stages = append(result.Stages, stage)
}

func buildScanMetadata(
	data *sdkingest.IngestData,
	result *sdkingest.IngestResult,
	graphBefore, graphAfter *model.GraphSnapshot,
	reconciliation graph.ReconciliationStats,
	observation graph.ObservationCompleteness,
	completeDomains []string,
) map[string]any {
	graphTotals := sdkingest.FrozenGraphTotals{
		Before: sdkGraphTotals(graphBefore),
		After:  sdkGraphTotals(graphAfter),
	}
	metadata := map[string]any{
		"collection":               data.Meta.Collection,
		"ruleset":                  data.Meta.Ruleset,
		"identity_schemes":         data.Meta.IdentitySchemes,
		"collection_identity":      data.Meta.Identity,
		"stages":                   result.Stages,
		"submitted":                result.Submitted,
		"write_rows":               result.WriteRows,
		"graph_totals":             graphTotals,
		"normalization_status":     result.NormalizationStatus,
		"normalization_warnings":   result.NormalizationWarnings,
		"complete_domains":         completeDomains,
		"reconciliation":           reconciliation,
		"observation_completeness": observation,
		"collector_version":        data.Meta.CollectorVersion,
		"artifact_extra":           data.Meta.Extra,
	}
	return metadata
}

func joinedStageErrors(errs ...error) string {
	var messages []string
	for _, err := range errs {
		if err != nil {
			messages = append(messages, err.Error())
		}
	}
	return strings.Join(messages, "; ")
}
