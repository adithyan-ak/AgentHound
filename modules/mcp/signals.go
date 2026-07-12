package mcp

import (
	"encoding/json"
	"net/url"
	"sort"
	"strings"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/rules"
)

type ToolSignals struct {
	DescriptionHash    string
	CapabilitySurface  []string
	HasInjection       bool
	HasCrossReferences bool
	SourceTrust        string
	Annotations        map[string]any
	// CapabilityEvidence records, per classified capability, the rule that
	// fired, the field it matched, the matched text, and a bounded
	// confidence. Capability classification here is LEXICAL (keyword hints in
	// tool name/description/schema text), so confidence is deliberately capped
	// well below 1.0 — a lexical hint must not become a 100%-confidence host
	// execution claim downstream. Consumers should use this confidence rather
	// than treating capability_surface membership as certainty.
	CapabilityEvidence []CapabilityEvidence
}

// CapabilityEvidence is the provenance + confidence basis for one capability
// classification on a tool.
type CapabilityEvidence struct {
	Capability   string  `json:"capability"`
	RuleID       string  `json:"rule_id"`
	MatchedField string  `json:"matched_field"`
	MatchedText  string  `json:"matched_text,omitempty"`
	Confidence   float64 `json:"confidence"`
	Basis        string  `json:"basis"`
}

type ResourceSignals struct {
	URIScheme string
	// Sensitivity is the highest-severity sensitivity classification a rule
	// assigned to the resource, or "unknown" when no sensitivity rule matched.
	// Absence of a match is NOT evidence the resource is low-sensitivity.
	Sensitivity string
	// SensitivityState records whether sensitivity was assessed (a rule
	// matched) or not_assessed (no sensitivity signal).
	SensitivityState common.AssessmentState
}

func computeToolSignals(tool *mcpsdk.Tool, allToolNames map[string]bool, engine *rules.Engine) ToolSignals {
	schemaMap := inputSchemaAsMap(tool.InputSchema)

	sig := ToolSignals{
		DescriptionHash: common.DescriptionHash(tool.Name, tool.Description, schemaMap),
	}

	combined := tool.Name + " " + tool.Description
	if schemaMap != nil {
		if props, ok := schemaMap["properties"].(map[string]any); ok {
			for key := range props {
				combined += " " + key
			}
		}
	}
	// Evaluate each field independently (rather than EvaluateAll) so a
	// capability match carries the field it matched — the boundary that
	// determines its confidence basis. Ordered so processing is deterministic.
	capFields := []struct{ name, text string }{
		{"tool.description", tool.Description},
		{"tool.name", tool.Name},
		{"tool.combined", combined},
	}

	capSet := make(map[string]bool)
	bestEvidence := make(map[string]CapabilityEvidence)
	for _, f := range capFields {
		if f.text == "" {
			continue
		}
		for _, m := range engine.Evaluate("mcp", f.name, f.text) {
			switch m.Emit.FindingType {
			case "has_injection_patterns":
				sig.HasInjection = true
			case "capability_classification":
				v, ok := m.Emit.PropertyValue.(string)
				if !ok || v == "" {
					continue
				}
				capSet[v] = true
				ev := capabilityEvidenceFor(v, f.name, m)
				if cur, seen := bestEvidence[v]; !seen || ev.Confidence > cur.Confidence {
					bestEvidence[v] = ev
				}
			case "source_trust_classification":
				// First non-empty untrusted-source label wins; any value
				// marks the tool as ingesting untrusted input. Edges are
				// MERGE-keyed so the exact label choice is stable enough.
				if v, ok := m.Emit.PropertyValue.(string); ok && v != "" && sig.SourceTrust == "" {
					sig.SourceTrust = v
				}
			}
		}
	}
	for cap := range capSet {
		sig.CapabilitySurface = append(sig.CapabilitySurface, cap)
	}
	sort.Strings(sig.CapabilitySurface)
	for _, cap := range sig.CapabilitySurface {
		sig.CapabilityEvidence = append(sig.CapabilityEvidence, bestEvidence[cap])
	}

	if tool.Description != "" {
		descLower := strings.ToLower(tool.Description)
		for name := range allToolNames {
			if name != tool.Name && strings.Contains(descLower, strings.ToLower(name)) {
				sig.HasCrossReferences = true
				break
			}
		}
	}

	sig.Annotations = flattenAnnotations(tool.Annotations)

	return sig
}

// capabilityEvidenceFor builds the confidence basis for a lexically-derived
// capability classification. All current capability rules are keyword matchers
// over free text, so the basis is "lexical" and confidence is capped well
// below certainty. A match against the tool's declared name is a marginally
// stronger hint than one buried in free-text description, but it is still a
// hint — never proof of a real capability boundary crossing.
func capabilityEvidenceFor(capability, field string, m rules.Match) CapabilityEvidence {
	confidence := 0.5
	if field == "tool.name" {
		confidence = 0.6
	}
	return CapabilityEvidence{
		Capability:   capability,
		RuleID:       m.RuleID,
		MatchedField: field,
		MatchedText:  m.Text,
		Confidence:   confidence,
		Basis:        "lexical",
	}
}

func flattenAnnotations(ann *mcpsdk.ToolAnnotations) map[string]any {
	if ann == nil {
		return nil
	}
	m := make(map[string]any)
	m["read_only_hint"] = ann.ReadOnlyHint
	m["idempotent_hint"] = ann.IdempotentHint
	if ann.DestructiveHint != nil {
		m["destructive_hint"] = *ann.DestructiveHint
	}
	if ann.OpenWorldHint != nil {
		m["open_world_hint"] = *ann.OpenWorldHint
	}
	if ann.Title != "" {
		m["title"] = ann.Title
	}
	return m
}

func computeResourceSignals(uri string, engine *rules.Engine) ResourceSignals {
	var sig ResourceSignals

	fields := map[string]string{"resource.uri": uri}
	matches := engine.EvaluateAll("mcp", fields)

	bestSeverity := ""
	severityRank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}

	for _, m := range matches {
		if !strings.Contains(m.Emit.FindingType, "sensitivity") {
			continue
		}
		sev := ""
		if v, ok := m.Emit.PropertyValue.(string); ok {
			sev = v
		}
		if bestSeverity == "" {
			bestSeverity = sev
		} else if rank, ok := severityRank[sev]; ok {
			if bestRank, ok2 := severityRank[bestSeverity]; ok2 && rank < bestRank {
				bestSeverity = sev
			}
		}
	}
	if bestSeverity == "" {
		// No sensitivity rule matched. This is an absence of signal, not
		// evidence of low sensitivity — report it as unknown/not_assessed.
		sig.Sensitivity = "unknown"
		sig.SensitivityState = common.AssessmentNotAssessed
	} else {
		sig.Sensitivity = bestSeverity
		sig.SensitivityState = common.AssessmentAssessed
	}

	if u, err := url.Parse(uri); err == nil && u.Scheme != "" {
		sig.URIScheme = u.Scheme
	}

	return sig
}

// inputSchemaKeys extracts the top-level and one-level-nested property
// names from a tool's JSON input schema, returned sorted and de-duplicated.
// Emitted collector-side as the schema_keys node property so the TAINTS
// post-processor can detect schema overlap between tools in pure Cypher
// (no APOC dependency on the server). Returns nil when there are no keys.
func inputSchemaKeys(schema any) []string {
	m := inputSchemaAsMap(schema)
	if m == nil {
		return nil
	}
	keySet := make(map[string]bool)
	collectSchemaKeys(m, keySet, 0)
	if len(keySet) == 0 {
		return nil
	}
	keys := make([]string, 0, len(keySet))
	for k := range keySet {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// collectSchemaKeys walks a JSON-schema "properties" map, recording each
// property name. It descends at most one level into nested object schemas
// (depth 0 -> top level, depth 1 -> one level of nesting) to keep the key
// set bounded and the overlap signal meaningful.
func collectSchemaKeys(m map[string]any, out map[string]bool, depth int) {
	props, ok := m["properties"].(map[string]any)
	if !ok {
		return
	}
	for key, val := range props {
		out[key] = true
		if depth < 1 {
			if sub, ok := val.(map[string]any); ok {
				collectSchemaKeys(sub, out, depth+1)
			}
		}
	}
}

func inputSchemaAsMap(schema any) map[string]any {
	if schema == nil {
		return nil
	}

	if m, ok := schema.(map[string]any); ok {
		return m
	}

	if s, ok := schema.(string); ok {
		var m map[string]any
		if err := json.Unmarshal([]byte(s), &m); err == nil {
			return m
		}
	}

	data, err := json.Marshal(schema)
	if err != nil {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil
	}
	return m
}
