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
}

type ResourceSignals struct {
	URIScheme           string
	Sensitivity         string
	SensitivityRuleID   string
	SensitivityEvidence string
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
	fields := map[string]string{
		"tool.description": tool.Description,
		"tool.name":        tool.Name,
		"tool.combined":    combined,
	}
	matches := engine.EvaluateAll("mcp", fields)

	capSet := make(map[string]bool)
	for _, m := range matches {
		switch m.Emit.FindingType {
		case "has_injection_patterns":
			sig.HasInjection = true
		case "capability_classification":
			if v, ok := m.Emit.PropertyValue.(string); ok {
				capSet[v] = true
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
	for cap := range capSet {
		sig.CapabilitySurface = append(sig.CapabilitySurface, cap)
	}
	sort.Strings(sig.CapabilitySurface)

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
	bestRuleID := ""
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
			bestRuleID = m.RuleID
		} else if rank, ok := severityRank[sev]; ok {
			if bestRank, ok2 := severityRank[bestSeverity]; ok2 && rank < bestRank {
				bestSeverity = sev
				bestRuleID = m.RuleID
			} else if rank == bestRank && (bestRuleID == "" || m.RuleID < bestRuleID) {
				bestRuleID = m.RuleID
			}
		}
	}
	if bestSeverity == "" {
		bestSeverity = string(common.SensitivityUnknown)
		sig.SensitivityEvidence = "no_rule_match"
	} else {
		sig.SensitivityEvidence = "rule_match"
	}
	sig.Sensitivity = bestSeverity
	sig.SensitivityRuleID = bestRuleID

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
